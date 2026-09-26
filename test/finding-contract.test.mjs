import assert from 'node:assert/strict'
import test from 'node:test'

import { REPORT_SCHEMA_VERSION, TOOL_ID, compareFindings, createFinding, exitCodeFor, serializeReport } from '../src/index.mjs'
import {
  CHECKPOINT_NAME,
  TRAIL_NAME,
  WITH_CHECKPOINT,
  apiReport,
  chain,
  checkpointAt,
  checkpointAtEnd,
  cleanFiles,
  cleanTrail,
  cliReport,
  event,
} from './support.mjs'

/**
 * The report envelope, and the invariant that matters most: a `pass` is only
 * ever emitted when every verdict the report carries is true.
 *
 * The corpus below is driven through the real entry point and each report is
 * checked against the contract as a whole, rather than each field being checked
 * by the test that happened to produce it.
 */

const cp = (document, overrides) => checkpointAtEnd(document, overrides)
const withCheckpoint = (document, checkpoint = cp(document), options = {}) =>
  apiReport({ [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint }, { checkpoint: CHECKPOINT_NAME, ...options })

const CORPUS = Object.freeze([
  () => apiReport(cleanFiles(), { checkpoint: CHECKPOINT_NAME }),
  () => apiReport({ [TRAIL_NAME]: cleanTrail() }),
  () => apiReport({}),
  () => apiReport({ [TRAIL_NAME]: 'x\n' }),
  () => apiReport({ [TRAIL_NAME]: { schemaVersion: '1', trail: 'a', records: [] } }),
  () => withCheckpoint(cleanTrail(), undefined, { limits: { maxRecords: 1 } }),
  () => withCheckpoint(cleanTrail(), undefined, { anchorHash: 'c'.repeat(64) }),
  () => withCheckpoint(cleanTrail(), undefined, { firstSequence: 9 }),
  () => withCheckpoint(chain('t', [event('a'), event('b', { sequence: 9 })])),
  () => withCheckpoint(chain('t', [event('a'), event('a')])),
  () => withCheckpoint(chain('t', [event('a', { actor: 1, details: 2 })])),
  () => withCheckpoint(chain('t', [event('a', { details: { a: { b: { c: 1 } } } })]), undefined, { limits: { maxDetailDepth: 2 } }),
  () => {
    const document = cleanTrail()
    return withCheckpoint(document, checkpointAt(document, 1))
  },
  () => {
    const document = cleanTrail()
    const checkpoint = cp(document)
    document.records[2].actor = 'rewritten'
    return withCheckpoint(document, checkpoint)
  },
  () => {
    const document = cleanTrail()
    const checkpoint = cp(document)
    document.records.length = 1
    return withCheckpoint(document, checkpoint)
  },
])

const reports = async () => Promise.all(CORPUS.map((build) => build()))

test('every report carries the declared envelope', async () => {
  for (const report of await reports()) {
    assert.equal(report.schemaVersion, REPORT_SCHEMA_VERSION)
    assert.equal(report.tool, TOOL_ID)
    assert.equal(['pass', 'fail', 'incomplete'].includes(report.status), true)
    assert.equal(Number.isInteger(report.summary.checked), true)
    assert.equal(Number.isInteger(report.summary.errors), true)
    assert.equal(Number.isInteger(report.summary.warnings), true)
    assert.equal(Array.isArray(report.findings), true)
    assert.equal(typeof report.coverage.tailDeletionDetectable, 'boolean')
  }
})

test('every finding carries the declared shape and nothing outside it', async () => {
  for (const report of await reports()) {
    for (const finding of report.findings) {
      assert.deepEqual(
        Object.keys(finding).filter((key) => !['ruleId', 'severity', 'message', 'location', 'evidence', 'suggestion'].includes(key)),
        [],
      )
      assert.match(finding.ruleId, /^[a-z][a-z0-9-]*[a-z0-9]$/)
      assert.equal(['error', 'warning', 'info'].includes(finding.severity), true)
      assert.equal(finding.message.length > 0 && finding.message.length <= 403, true)
      assert.deepEqual(Object.keys(finding.location).sort(), ['file', 'pointer'])
      assert.equal(finding.location.file.startsWith('/'), false, 'never an absolute host path')
      assert.equal([TRAIL_NAME, CHECKPOINT_NAME].includes(finding.location.file), true)
      if (finding.evidence !== undefined) assert.equal(finding.evidence.length <= 163, true)
      if (finding.suggestion !== undefined) assert.equal(finding.suggestion.length <= 303, true)
    }
  }
})

test('findings are emitted in the documented order', async () => {
  for (const report of await reports()) {
    const sorted = [...report.findings].sort(compareFindings)
    assert.deepEqual(report.findings, sorted)
  }
})

test('the counts in the summary are the counts in the findings list', async () => {
  for (const report of await reports()) {
    assert.equal(report.summary.errors, report.findings.filter((finding) => finding.severity === 'error').length)
    assert.equal(report.summary.warnings, report.findings.filter((finding) => finding.severity === 'warning').length)
  }
})

/**
 * The invariant that makes every other claim in the report safe to read. A
 * `pass` is not a status the tool may reach while any verdict it carries is
 * false, and it may never be reached with nothing examined.
 */
test('a pass implies every verdict is true and something was examined', async () => {
  let passes = 0
  for (const report of await reports()) {
    if (report.status !== 'pass') continue
    passes += 1
    assert.equal(report.summary.errors, 0)
    assert.equal(report.summary.checked > 0, true, 'a pass on no evidence at all')
    assert.equal(report.summary.checked, report.summary.records)
    assert.equal(report.summary.chainVerified, true)
    assert.equal(report.summary.sequenceContinuous, true)
    assert.equal(report.coverage.checkpointApplied, true)
    assert.equal(report.coverage.tailDeletionDetectable, true)
    assert.equal(report.coverage.uncoveredTailRecords, 0)
    assert.equal(exitCodeFor(report), 0)
  }
  assert.equal(passes, 1, 'the corpus must contain a real pass for this to prove anything')
})

test('an incomplete report never reports a verified chain or covered tail', async () => {
  for (const report of await reports()) {
    if (report.status !== 'incomplete') continue
    assert.equal(exitCodeFor(report), 2)
    const fullyCovered = report.coverage.tailDeletionDetectable && report.coverage.uncoveredTailRecords === 0
    assert.equal(
      report.summary.chainVerified && report.summary.sequenceContinuous && fullyCovered,
      false,
      'an incomplete run claimed everything was verified',
    )
  }
})

test('exit codes follow the status, and nothing else', () => {
  assert.equal(exitCodeFor({ status: 'pass' }), 0)
  assert.equal(exitCodeFor({ status: 'fail' }), 1)
  assert.equal(exitCodeFor({ status: 'incomplete' }), 2)
})

test('a rule with no severity in the table throws rather than defaulting', () => {
  assert.throws(
    () => createFinding({ ruleId: 'invented-rule', file: TRAIL_NAME, pointer: '', message: 'x' }),
    /is not in RULE_SEVERITY/,
  )
})

test('stdout is the serialized report and nothing else', async () => {
  // An input carrying findings of both severities, so a binary that filtered
  // one of them out is caught as well as one that decorated the envelope.
  const document = cleanTrail()
  document.records[1] = { ...document.records[1], actor: 'user:intruder' }
  const files = { [TRAIL_NAME]: document }
  const { stdout, report } = await cliReport(files, [])

  assert.equal(new Set(report.findings.map((finding) => finding.severity)).size, 2)
  assert.equal(stdout, `${serializeReport(report)}\n`)
  // `report` above is `JSON.parse(stdout)`, so comparing the two would compare
  // a value with itself. The report the exported function builds for the same
  // input is an independent value, and comparing against it is what catches a
  // binary that decorates, filters or re-keys the report on its way to stdout.
  assert.deepEqual(JSON.parse(stdout), await apiReport(files))
})

test('the same inputs produce byte-identical stdout on a second run', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1].actor = 'user:intruder'
  const input = { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint }

  const first = await cliReport(input, WITH_CHECKPOINT)
  const second = await cliReport(input, WITH_CHECKPOINT)

  assert.equal(first.stdout, second.stdout)
  assert.equal(first.code, second.code)
})
