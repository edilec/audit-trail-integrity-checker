/**
 * audit-trail-integrity-checker -- verify a local audit trail's schema, its
 * sequence continuity and its previous-record hash chain, and say exactly how
 * far that verification reaches.
 *
 * The tool reads files and computes SHA-256 digests. It opens no socket, holds
 * no key material, verifies no signature, and writes nothing anywhere: the
 * files it is pointed at are the only evidence there is, and every sentence in
 * the report is a sentence about those files.
 *
 * Three checks, kept separate because each one is blind to what the others see:
 *
 * 1. **Schema** -- every record has the members this build understands, in the
 *    shapes it understands, and no others.
 * 2. **Sequence** -- the numbers run consecutively. A chain that verifies
 *    perfectly can still skip a number, and a skipped number is how a producer
 *    makes deletion and non-issuance indistinguishable.
 * 3. **Chain** -- every record's digest recomputes to the value stored with it,
 *    and every record links to the digest of the record before it. This is what
 *    catches an edited record and a record removed from the middle.
 *
 * And one thing none of them can do, which the report states in its own field
 * rather than leaving to a reader's assumption: **a hash chain cannot detect
 * truncation of its own tail.** Remove the last n records and everything above
 * still verifies. Without a trusted checkpoint that is an unsupported claim,
 * the run is `incomplete`, and it is not a pass. With one, coverage reaches the
 * checkpointed record and stops there.
 */

import { readFile, realpath, stat } from 'node:fs/promises'
import { dirname, isAbsolute, normalize, resolve, sep } from 'node:path'
import { performance } from 'node:perf_hooks'

import { checkSequence, verifyChain } from './chain.mjs'
import { compileCheckpoint, evaluateCoverage } from './coverage.mjs'
import { compileTrail } from './records.mjs'
import { byCodeUnit, decodeUtf8, excerpt, hasForbiddenCharacter, isHash, isPlainObject } from './text.mjs'

export const TOOL_ID = 'audit-trail-integrity-checker'
export const REPORT_SCHEMA_VERSION = '1'

export const DEFAULT_TRAIL_NAME = 'trail.json'

/**
 * Limits, each enforced and each reported by name when it is reached.
 *
 * Exceeding one is never a silent truncation: it produces a finding that names
 * the limit and marks the run `incomplete`, because a partial walk is not
 * evidence about the part nobody walked.
 */
export const DEFAULT_LIMITS = Object.freeze({
  maxDetailDepth: 8,
  maxDetailNodes: 500,
  maxFileBytes: 16777216,
  maxFindings: 1000,
  maxRecords: 50000,
  maxRuntimeMs: 20000,
})

/** A caller may lower a limit, never raise it past these caps. */
export const HARD_LIMITS = Object.freeze({
  maxDetailDepth: 64,
  maxDetailNodes: 20000,
  maxFileBytes: 268435456,
  maxFindings: 20000,
  maxRecords: 2000000,
  maxRuntimeMs: 600000,
})

/**
 * The authoritative rule severity table.
 *
 * Severity is the whole difference between a run that fails and one that
 * passes. Written as a literal at each construction site it drifts silently,
 * and demoting `record-hash-mismatch` to a warning turns "this record is not
 * the record its own digest was written for" into a green build with every
 * test still passing. Every finding takes its severity from here, and an
 * unknown rule id throws.
 *
 * `test/severity-table.test.mjs` asserts this table against the documented
 * catalog in both directions. That is worth having and it is not the test: a
 * table, a catalog and a test's expected map are three declarations, and one
 * edit that changes all three leaves every assertion that compares them
 * satisfied. `test/severity-exit.test.mjs` and `test/severity-word.test.mjs`
 * drive real inputs through the real code and pin the exit code and the
 * severity of each rule with literal values written where they are asserted.
 */
export const RULE_SEVERITY = Object.freeze({
  'anchor-mismatch': 'error',
  'chain-link-broken': 'error',
  'chain-link-missing': 'error',
  'checkpoint-hash-mismatch': 'error',
  'checkpoint-invalid': 'error',
  'checkpoint-outside-segment': 'error',
  'checkpoint-record-mismatch': 'error',
  'checkpoint-record-missing': 'error',
  'checkpoint-record-unverified': 'error',
  'checkpoint-signature-unsupported': 'error',
  'checkpoint-trail-mismatch': 'error',
  'detail-depth-exceeded': 'error',
  'document-invalid': 'error',
  'hash-format-invalid': 'error',
  'identifier-invalid': 'error',
  'input-not-json': 'error',
  'input-not-utf8': 'error',
  'input-too-large': 'error',
  'input-unreadable': 'error',
  'no-records': 'error',
  'path-escapes-root': 'error',
  'record-hash-mismatch': 'error',
  'record-id-duplicate': 'error',
  'record-invalid': 'error',
  'record-not-canonical': 'error',
  'records-not-all-verified': 'error',
  'schema-version-unsupported': 'error',
  'segment-anchor-unverified': 'warning',
  'sequence-duplicate': 'error',
  'sequence-gap': 'error',
  'sequence-out-of-order': 'error',
  'sequence-start-mismatch': 'error',
  'tail-beyond-checkpoint': 'warning',
  'tail-deletion-undetectable': 'warning',
  'tail-truncated-below-checkpoint': 'error',
  'time-budget-exceeded': 'error',
  'timestamp-invalid': 'error',
  'timestamp-regression': 'warning',
  'too-many-detail-nodes': 'error',
  'too-many-findings': 'error',
  'too-many-records': 'error',
})

const MESSAGE_LIMIT = 400
const SUGGESTION_LIMIT = 300
const LOCATION_LIMIT = 200
const MAX_NAME_LENGTH = 200

const ALLOWED_OPTIONS = Object.freeze([
  'anchorHash', 'checkpoint', 'clock', 'firstSequence', 'limits', 'root', 'trail',
])

/**
 * Validate limit overrides.
 *
 * An unknown key throws rather than being ignored. A documented limit that a
 * typo silently disables is a limit that is not enforced, and the CLI turns
 * this throw into a configuration error with an empty stdout.
 */
export function validateLimits(overrides = {}) {
  if (!isPlainObject(overrides)) throw new TypeError('limits must be an object')
  const limits = { ...DEFAULT_LIMITS }
  for (const key of Object.keys(overrides).sort(byCodeUnit)) {
    if (!Object.hasOwn(DEFAULT_LIMITS, key)) {
      throw new TypeError(`Unknown limit "${excerpt(key, 60)}"; known limits are ${Object.keys(DEFAULT_LIMITS).sort(byCodeUnit).join(', ')}`)
    }
    const value = overrides[key]
    const cap = HARD_LIMITS[key]
    if (!Number.isInteger(value) || value < 1 || value > cap) {
      throw new TypeError(`limits.${key} must be an integer between 1 and ${cap}`)
    }
    limits[key] = value
  }
  return Object.freeze(limits)
}

/**
 * True when `candidate` is the real root itself or lies beneath it.
 *
 * Both sides must already be real paths. Comparing a real root against a path
 * that has not been resolved refuses legitimate files whenever the root is
 * reached through a symbolic link -- a `/var` that is really `/private/var` is
 * enough -- and a false refusal is a defect too.
 */
export function isInside(root, candidate) {
  return candidate === root || candidate.startsWith(root.endsWith(sep) ? root : root + sep)
}

/**
 * A file name given on the command line, checked as configuration.
 *
 * Absolute paths and `..` segments are refused here, before any evidence is
 * gathered, because naming a file outside the declared root is a usage error
 * rather than a fact about the subject. This is emphatically *not* the
 * confinement: a symbolic link planted inside the root passes every check in
 * this function, and `resolveInput` is what catches it by resolving the real
 * path of both sides.
 */
function validateName(name, flag) {
  if (typeof name !== 'string' || name.length === 0 || name.length > MAX_NAME_LENGTH) {
    throw new TypeError(`${flag} must be a relative file name of 1-${MAX_NAME_LENGTH} characters`)
  }
  if (hasForbiddenCharacter(name)) {
    throw new TypeError(`${flag} must not contain a control, separator or bidi character`)
  }
  if (isAbsolute(name)) throw new TypeError(`${flag} must be relative to --root, not an absolute path`)
  const parts = normalize(name).split(/[\\/]/)
  if (parts.includes('..')) throw new TypeError(`${flag} must not step outside --root with ".."`)
  return name
}

class FindingSink {
  constructor() {
    this.rows = []
  }

  add(row) {
    this.rows.push({ pointer: '', ...row })
  }
}

/**
 * Build a finding, taking its severity from the one table.
 *
 * Every untrusted string is sanitised here -- file, pointer, message,
 * suggestion and evidence alike, not only the evidence field. A sibling tool
 * sanitised evidence carefully and left identifiers raw, so a record id holding
 * a newline forged an extra line in the human report.
 */
export function createFinding(row) {
  const severity = RULE_SEVERITY[row.ruleId]
  if (severity === undefined) {
    throw new Error(`Rule "${row.ruleId}" is not in RULE_SEVERITY; add it to the table and to docs/integrity-rules.md.`)
  }
  const finding = {
    ruleId: row.ruleId,
    severity,
    message: excerpt(row.message, MESSAGE_LIMIT),
    location: { file: excerpt(row.file, LOCATION_LIMIT), pointer: excerpt(row.pointer, LOCATION_LIMIT) },
  }
  if (row.evidence !== undefined && row.evidence !== '') finding.evidence = excerpt(row.evidence)
  if (row.suggestion !== undefined) finding.suggestion = excerpt(row.suggestion, SUGGESTION_LIMIT)
  return finding
}

/**
 * The documented sort key: `location.file`, `location.pointer`, `ruleId`,
 * `message`.
 *
 * The message is part of the key because a few rules anchor more than one
 * finding at the same pointer on purpose -- a record can be both unknown-keyed
 * and badly timestamped at `/records/3`. No two findings share all four
 * components, and `sort` is stable, so even a tie would preserve emission
 * order, which is itself fixed by the file.
 */
export function compareFindings(a, b) {
  return (
    byCodeUnit(a.location.file, b.location.file) ||
    byCodeUnit(a.location.pointer, b.location.pointer) ||
    byCodeUnit(a.ruleId, b.ruleId) ||
    byCodeUnit(a.message, b.message)
  )
}

function buildReport(sink, state, limits) {
  let findings = sink.rows.map((row) => createFinding(row)).sort(compareFindings)
  let truncated = false

  if (findings.length > limits.maxFindings) {
    const dropped = findings.length - limits.maxFindings + 1
    findings = findings.slice(0, limits.maxFindings - 1)
    findings.push(createFinding({
      file: state.files.trail,
      pointer: '',
      ruleId: 'too-many-findings',
      message: `The run produced more findings than the maxFindings limit of ${limits.maxFindings}; ${dropped} were not reported and this report is partial.`,
      suggestion: 'Raise --max-findings, or verify the trail in segments.',
    }))
    findings.sort(compareFindings)
    truncated = true
  }

  let errors = 0
  let warnings = 0
  for (const finding of findings) {
    if (finding.severity === 'error') errors += 1
    else if (finding.severity === 'warning') warnings += 1
  }

  const status = state.incomplete || truncated ? 'incomplete' : errors > 0 ? 'fail' : 'pass'

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: TOOL_ID,
    status,
    summary: {
      checked: state.checked,
      errors,
      warnings,
      trail: state.trail,
      records: state.records,
      hashesVerified: state.hashesVerified,
      linksVerified: state.linksVerified,
      firstSequence: state.firstSequence,
      lastSequence: state.lastSequence,
      chainVerified: state.chainVerified,
      sequenceContinuous: state.sequenceContinuous,
    },
    coverage: state.coverage,
    findings,
  }
}

/**
 * Resolve one declared input inside the declared root.
 *
 * Both sides are resolved to their real paths before they are compared.
 * Rejecting `..` lexically -- which `validateName` also does -- is not
 * confinement: a symbolic link planted inside the root points anywhere and
 * contains no `..` at all. Equally, comparing a real root against an unresolved
 * target refuses legitimate files, so the root is resolved too.
 */
async function resolveInput(realRoot, name) {
  const target = resolve(realRoot, name)
  try {
    const real = await realpath(target)
    if (!isInside(realRoot, real)) return { ok: false, reason: 'escapes' }
    return { ok: true, real }
  } catch (error) {
    if (error.code !== 'ENOENT' && error.code !== 'ELOOP') return { ok: false, reason: 'unreadable', code: error.code }
    // The entry may still exist as a link that resolves nowhere. Confine the
    // nearest existing ancestor first, so a symlinked parent directory cannot
    // decide where a "missing" file would have been read from.
    try {
      const realParent = await realpath(dirname(target))
      if (!isInside(realRoot, realParent)) return { ok: false, reason: 'escapes' }
    } catch {
      return { ok: false, reason: 'unreadable', code: error.code }
    }
    return { ok: false, reason: 'unreadable', code: error.code }
  }
}

/** Read one confined input and turn it into parsed JSON, or into the finding that says why not. */
async function loadJson(sink, file, real, limits) {
  let info
  try {
    info = await stat(real)
  } catch (error) {
    sink.add({ file, ruleId: 'input-unreadable', message: `${file} could not be inspected: ${error.code ?? 'unknown error'}.` })
    return null
  }
  if (!info.isFile()) {
    sink.add({ file, ruleId: 'input-unreadable', message: `${file} is not a regular file, so nothing was read from it.` })
    return null
  }
  if (info.size > limits.maxFileBytes) {
    sink.add({
      file,
      ruleId: 'input-too-large',
      message: `${file} is ${info.size} bytes, above the maxFileBytes limit of ${limits.maxFileBytes}; it was not read.`,
      suggestion: 'Raise --max-file-bytes, or verify the trail in segments.',
    })
    return null
  }
  let bytes
  try {
    bytes = await readFile(real)
  } catch (error) {
    sink.add({ file, ruleId: 'input-unreadable', message: `${file} could not be read: ${error.code ?? 'unknown error'}.` })
    return null
  }
  const decoded = decodeUtf8(bytes)
  if (!decoded.ok) {
    sink.add({
      file,
      ruleId: 'input-not-utf8',
      message: `${file} is not valid UTF-8, so it was not parsed. Whether a file decodes is the decoder's decision, never an inference drawn from the decoded text.`,
      suggestion: 'Re-encode the file as UTF-8.',
    })
    return null
  }
  try {
    return { value: JSON.parse(decoded.text) }
  } catch (error) {
    sink.add({
      file,
      ruleId: 'input-not-json',
      message: `${file} is not valid JSON: ${error.message}`,
      suggestion: 'Validate the file with a JSON parser before re-running.',
    })
    return null
  }
}

function emptyState(files) {
  return {
    files,
    checked: 0,
    trail: null,
    records: 0,
    hashesVerified: 0,
    linksVerified: 0,
    firstSequence: null,
    lastSequence: null,
    chainVerified: false,
    sequenceContinuous: false,
    coverage: {
      checkpointRequested: false,
      checkpointApplied: false,
      coveredThroughSequence: null,
      uncoveredTailRecords: 0,
      tailDeletionDetectable: false,
    },
    incomplete: false,
  }
}

/**
 * Verify an audit trail.
 *
 * @param {object} options
 * @param {string} options.root Directory holding the trail, and the checkpoint if there is one.
 * @param {string} [options.trail] Trail document, relative to the root.
 * @param {string} [options.checkpoint] Checkpoint document, relative to the root. Without it, tail
 *   deletion is undetectable and the run is `incomplete` by construction.
 * @param {string} [options.anchorHash] Digest of the record immediately before this segment.
 * @param {number} [options.firstSequence] Sequence number this segment is expected to start at.
 * @param {object} [options.limits] Limit overrides; an unknown key throws.
 * @param {Function} [options.clock] Monotonic millisecond source for the time budget. Injected so a
 *   test can drive the budget without waiting, and so nothing here reads a wall clock.
 * @returns {Promise<object>} the report.
 */
export async function checkAuditTrail(options = {}) {
  if (!isPlainObject(options)) throw new TypeError('options must be an object')
  for (const key of Object.keys(options).sort(byCodeUnit)) {
    if (!ALLOWED_OPTIONS.includes(key)) {
      throw new TypeError(`Unknown option "${excerpt(key, 60)}"; known options are ${ALLOWED_OPTIONS.join(', ')}`)
    }
  }
  const limits = validateLimits(options.limits ?? {})
  if (typeof options.root !== 'string' || options.root.length === 0) throw new TypeError('root must be a non-empty string')
  if (options.clock !== undefined && typeof options.clock !== 'function') throw new TypeError('clock must be a function returning milliseconds')
  if (options.anchorHash !== undefined && options.anchorHash !== null && !isHash(options.anchorHash)) {
    throw new TypeError('anchorHash must be 64 lower-case hex digits')
  }
  if (options.firstSequence !== undefined && options.firstSequence !== null
    && (!Number.isSafeInteger(options.firstSequence) || options.firstSequence < 0)) {
    throw new TypeError(`firstSequence must be an integer between 0 and ${Number.MAX_SAFE_INTEGER}`)
  }

  const names = {
    trail: validateName(options.trail ?? DEFAULT_TRAIL_NAME, '--trail'),
    checkpoint: options.checkpoint === undefined || options.checkpoint === null
      ? null
      : validateName(options.checkpoint, '--checkpoint'),
  }
  const anchorHash = options.anchorHash ?? null
  const firstSequence = options.firstSequence ?? null

  let realRoot
  try {
    realRoot = await realpath(options.root)
  } catch (error) {
    throw new Error(`--root could not be resolved: ${error.code ?? 'unknown error'}`)
  }
  let rootInfo
  try {
    rootInfo = await stat(realRoot)
  } catch (error) {
    throw new Error(`--root could not be inspected: ${error.code ?? 'unknown error'}`)
  }
  if (!rootInfo.isDirectory()) throw new Error('--root must be a directory')

  const clock = options.clock ?? (() => performance.now())
  const started = clock()
  const budget = { exceeded: () => clock() - started > limits.maxRuntimeMs }

  const sink = new FindingSink()
  const state = emptyState({ trail: names.trail, checkpoint: names.checkpoint ?? '' })
  state.coverage.checkpointRequested = names.checkpoint !== null

  const parsed = {}
  for (const kind of ['checkpoint', 'trail']) {
    const name = names[kind]
    if (name === null) {
      parsed[kind] = null
      continue
    }
    const located = await resolveInput(realRoot, name)
    if (!located.ok) {
      if (located.reason === 'escapes') {
        sink.add({
          file: name,
          ruleId: 'path-escapes-root',
          message: `${name} resolves outside --root, so it was refused unread.`,
          suggestion: 'Keep the trail and its checkpoint inside the declared root; a symbolic link out of the tree is refused.',
        })
      } else {
        sink.add({
          file: name,
          ruleId: 'input-unreadable',
          message: `${name} could not be resolved inside --root: ${located.code ?? 'unknown error'}.`,
          suggestion: 'Check the file name and its permissions.',
        })
      }
      parsed[kind] = null
      continue
    }
    parsed[kind] = await loadJson(sink, name, located.real, limits)
  }

  const compiled = parsed.trail === null
    ? null
    : compileTrail(sink, names.trail, parsed.trail.value, limits)

  const checkpoint = names.checkpoint === null || parsed.checkpoint === null
    ? null
    : compileCheckpoint(sink, names.checkpoint, parsed.checkpoint.value)

  // (1) No usable trail: unreachable, unreadable, undecodable, unparseable, a
  // shape this build does not implement, or no records at all. Every one of
  // those leaves `compiled` null, so this is the single owner of the flag for
  // that whole axis -- a second place setting it would make the first one
  // unfalsifiable.
  if (compiled === null) {
    state.incomplete = true
    return buildReport(sink, state, limits)
  }

  state.trail = compiled.trail
  state.records = compiled.declared

  const chain = verifyChain(sink, names.trail, compiled, limits, budget, anchorHash)
  const sequence = checkSequence(sink, names.trail, compiled, budget, firstSequence)

  state.hashesVerified = chain.hashesVerified
  state.linksVerified = chain.linksVerified
  state.chainVerified = chain.chainVerified
  state.sequenceContinuous = sequence.continuous
  state.firstSequence = sequence.firstSequence
  state.lastSequence = sequence.lastSequence

  /**
   * The number of records this run actually compared a digest for: verified or
   * verified-as-wrong. Both are evidence. A record whose digest was never
   * computed is neither, and it is what `checked` must not count.
   */
  const examined = chain.hashesVerified + chain.hashMismatches
  state.checked = examined

  // (2) A pass that stopped early is the failure this catalog has already
  // shipped once. Asked after both loops, where a `break` cannot skip it.
  if (chain.stoppedEarly || sequence.stoppedEarly) {
    state.incomplete = true
    sink.add({
      file: names.trail,
      pointer: '/records',
      ruleId: 'time-budget-exceeded',
      message: `The run passed the maxRuntimeMs budget of ${limits.maxRuntimeMs} and stopped after examining ${examined} of ${compiled.declared} record(s); every verdict below is a floor, not an answer.`,
      suggestion: 'Raise --max-runtime-ms, or verify the trail in segments.',
    })
  }

  // (3) Evidence declared but not obtained. Covers every reason a record was
  // never compared -- excluded by the schema check, too deep to canonicalise,
  // or past the point the budget stopped at -- and it is the only place that
  // turns any of them into an incomplete run.
  if (examined !== compiled.declared) {
    state.incomplete = true
    sink.add({
      file: names.trail,
      pointer: '/records',
      ruleId: 'records-not-all-verified',
      message: `${examined} of ${compiled.declared} declared record(s) had a digest recomputed and compared; the rest were not checked at all, so nothing here says whether they were edited.`,
      suggestion: 'Fix what stopped those records from being read, then re-run.',
    })
  }

  // (4) A segment whose first record links to a predecessor nobody named: the
  // records before it are outside this run. The finding is a warning, so this
  // flag is the only thing standing between that input and a green build --
  // which is why test/incomplete.test.mjs pins it directly.
  if (chain.anchorState === 'unverified') state.incomplete = true

  // (5) Tail coverage. Owned entirely by evaluateCoverage, including the case
  // where a checkpoint was asked for and could not be used.
  const evaluated = evaluateCoverage(
    sink,
    { trail: names.trail, checkpoint: names.checkpoint ?? '' },
    compiled,
    checkpoint,
    chain.digestVerified,
    names.checkpoint !== null,
  )
  state.coverage = { checkpointRequested: names.checkpoint !== null, ...evaluated.coverage }
  if (evaluated.incomplete) state.incomplete = true

  return buildReport(sink, state, limits)
}

/** stdout carries this and nothing else, so it can be piped straight into a parser. */
export function serializeReport(report) {
  return JSON.stringify(report, null, 2)
}

/** 0 completed and passed, 1 completed and failed, 2 the run could not be completed. */
export function exitCodeFor(report) {
  if (report.status === 'incomplete') return 2
  return report.status === 'fail' ? 1 : 0
}

const SEVERITY_WIDTH = 7

/**
 * One sentence saying how far this run reached. It is the sentence a reader
 * most often gets wrong on their own, so the tool says it every time rather
 * than leaving it to be inferred from the absence of a finding.
 */
export function describeCoverage(report) {
  const { coverage, summary } = report
  if (!coverage.checkpointRequested) {
    return 'tail coverage: none. No checkpoint was supplied, so records deleted from the end of this trail would leave every digest, link and sequence number in it still verifying.'
  }
  if (!coverage.checkpointApplied) {
    return 'tail coverage: none. A checkpoint was supplied and could not be applied, so the end of this trail is unchecked.'
  }
  if (coverage.uncoveredTailRecords > 0) {
    return `tail coverage: through sequence ${coverage.coveredThroughSequence}. ${coverage.uncoveredTailRecords} record(s) after it are in the same position the whole trail would be in without a checkpoint.`
  }
  return `tail coverage: complete through sequence ${coverage.coveredThroughSequence}, the last of ${summary.records} record(s).`
}

/** The human summary. It goes to stderr; stdout is the JSON report alone. */
export function formatReport(report, extra = {}) {
  const { summary } = report
  const lines = [
    `trail ${excerpt(extra.trail ?? DEFAULT_TRAIL_NAME, 80)}`
    + `${summary.trail === null ? '' : ` (${excerpt(summary.trail, 80)})`}: `
    + `${summary.checked} of ${summary.records} record(s) examined, `
    + `${summary.hashesVerified} digest(s) and ${summary.linksVerified} link(s) verified.`,
    `chain verified: ${summary.chainVerified}. sequence continuous: ${summary.sequenceContinuous}. status ${report.status}.`,
    describeCoverage(report),
  ]
  for (const finding of report.findings) {
    lines.push(
      `${finding.severity.toUpperCase().padEnd(SEVERITY_WIDTH)} `
      + `${finding.location.file}${finding.location.pointer} ${finding.ruleId} ${finding.message}`,
    )
  }
  return `${lines.join('\n')}\n`
}

export { checkSequence, verifyChain } from './chain.mjs'
export { HASH_ALGORITHM, HASH_KEY, canonicalize, hashRecord, sha256Hex } from './canonical.mjs'
export {
  CHECKPOINT_KEYS, CHECKPOINT_SCHEMA_VERSION, compileCheckpoint, evaluateCoverage,
} from './coverage.mjs'
export {
  CHAIN_CRITICAL_KEYS, DOCUMENT_SCHEMA_VERSION, RECORD_KEYS, TRAIL_DOCUMENT_KEYS, compileTrail,
} from './records.mjs'
export {
  EXCERPT_LIMIT, HASH_PATTERN, MAX_IDENTIFIER_LENGTH, byCodeUnit, decodeUtf8, describeValue,
  excerpt, hasForbiddenCharacter, isHash, isIdentifier, isPlainObject, parseTimestamp,
} from './text.mjs'
