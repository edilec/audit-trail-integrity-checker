/**
 * Fixtures and runners shared by the test suite.
 *
 * Two entry points are exercised throughout: `apiReport` calls the exported
 * function, and `cliRun` spawns the real binary and reads the real exit code.
 * Several guarantees in this package can only be pinned by the second -- an
 * exit code cannot be satisfied by editing a table.
 *
 * Everything here builds *inputs*. Nothing here decides what a test expects: no
 * severity, no rule id, no count and no ordering lives in this file, so a test
 * cannot accidentally assert a value against the same declaration that produced
 * it.
 *
 * The one thing this file does borrow from the implementation is the digest
 * itself: a fixture trail has to be chained with the same hash the tool
 * recomputes, or every fixture would be a tamper case. That borrowing is made
 * safe by `test/canonical.test.mjs`, which pins the canonical form and a
 * literal digest written out by hand -- so a change to the hashing shows up
 * there rather than hiding behind fixtures that were regenerated to match.
 */

import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { DEFAULT_LIMITS, checkAuditTrail, hashRecord } from '../src/index.mjs'

const execFileAsync = promisify(execFile)

export const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const CLI = join(projectDirectory, 'bin/audit-trail-integrity-checker.mjs')

export const TRAIL_NAME = 'trail.json'
export const CHECKPOINT_NAME = 'checkpoint.json'

/** One record, before it is chained. Sequence defaults to its position plus one. */
export function event(id, overrides = {}) {
  return {
    id,
    timestamp: '2026-01-02T09:00:00.000Z',
    actor: 'svc-billing',
    action: 'invoice.issued',
    ...overrides,
  }
}

/**
 * Chain a list of events into a trail document.
 *
 * Each record is given the digest of the one before it, then its own digest is
 * computed over everything else it carries. This is the producer side of the
 * format, written here so that a test can then break exactly one thing in the
 * result and know that nothing else is broken.
 */
export function chain(trail, events, { previousHash = null, firstSequence = 1 } = {}) {
  const records = []
  let previous = previousHash
  let sequence = firstSequence

  for (const raw of events) {
    const record = { sequence, ...raw, previousHash: previous }
    const digest = hashRecord(record, DEFAULT_LIMITS)
    if (!digest.ok) throw new Error(`fixture record could not be hashed: ${digest.reason}`)
    record.hash = digest.hash
    records.push(record)
    previous = digest.hash
    sequence = record.sequence + 1
  }

  return { schemaVersion: '1', trail, records }
}

/** Recompute one record's digest after a test has edited it in place. */
export function reseal(document, index) {
  const record = { ...document.records[index] }
  delete record.hash
  const digest = hashRecord(record, DEFAULT_LIMITS)
  if (!digest.ok) throw new Error(`fixture record could not be hashed: ${digest.reason}`)
  document.records[index] = { ...record, hash: digest.hash }
  return document
}

/** A checkpoint over one record of a trail document, by position. */
export function checkpointAt(document, index, overrides = {}) {
  const record = document.records[index]
  return {
    schemaVersion: '1',
    trail: document.trail,
    sequence: record.sequence,
    recordId: record.id,
    recordHash: record.hash,
    ...overrides,
  }
}

/** A checkpoint over the last record of a trail document. */
export const checkpointAtEnd = (document, overrides) =>
  checkpointAt(document, document.records.length - 1, overrides)

/**
 * The four-record trail most tests start from.
 *
 * The details on the third record are not decoration. `X-Request-Id` sorts
 * before `actor_ip` by code unit and after it under English collation, and the
 * canonical form a digest is computed over sorts object keys -- so this record
 * is what makes a collated sort inside the hash observable as a tamper finding
 * rather than as nothing at all.
 */
export const cleanTrail = () => chain('billing.eu-west-1', [
  event('evt-0001', { action: 'trail.opened', actor: 'svc-audit' }),
  event('evt-0002', { timestamp: '2026-01-02T09:00:01.250Z', target: 'invoice:8841' }),
  event('evt-0003', {
    timestamp: '2026-01-02T09:00:02.500Z',
    action: 'invoice.settled',
    target: 'invoice:8841',
    details: { 'X-Request-Id': 'req-7f3c', actor_ip: '198.51.100.24', amountMinor: 4200 },
  }),
  event('evt-0004', { timestamp: '2026-01-02T09:00:03.750Z', action: 'trail.sealed', actor: 'svc-audit' }),
])

/** That trail, with a checkpoint over its last record: the only shape that can pass. */
export function cleanFiles() {
  const document = cleanTrail()
  return { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) }
}

/** The arguments that apply a checkpoint written under the default name. */
export const WITH_CHECKPOINT = Object.freeze(['--checkpoint', CHECKPOINT_NAME])

/**
 * Create a temporary root, write the named files into it, run `body(root)`, and
 * remove the tree afterwards whatever happened.
 *
 * A string is written verbatim and a `Uint8Array` byte for byte, so a test can
 * plant text that is not JSON, or bytes that are not UTF-8 at all.
 */
export async function withRoot(files, body) {
  const root = await mkdtemp(join(tmpdir(), 'audit-trail-integrity-checker-'))
  try {
    for (const [name, content] of Object.entries(files)) {
      const bytes = typeof content === 'string' || content instanceof Uint8Array
        ? content
        : `${JSON.stringify(content, null, 2)}\n`
      await writeFile(join(root, name), bytes)
    }
    return await body(root)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

/** Run the exported API over a temporary root. */
export async function apiReport(files, options = {}) {
  return withRoot(files, (root) => checkAuditTrail({ root, ...options }))
}

/** Spawn the real binary. Returns the exit code and both streams; never throws on a non-zero exit. */
export async function cliRun(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, ...args], { cwd: projectDirectory })
    return { code: 0, stdout, stderr }
  } catch (error) {
    return { code: error.code, stdout: error.stdout ?? '', stderr: error.stderr ?? '' }
  }
}

/** Spawn the real binary over a temporary root, and parse whatever stdout carried. */
export async function cliReport(files, extraArgs = []) {
  return withRoot(files, async (root) => {
    const result = await cliRun(['--root', root, '--json', ...extraArgs])
    return { ...result, report: result.stdout === '' ? null : JSON.parse(result.stdout) }
  })
}

/**
 * Spawn the real binary with the human summary switched on, so a test can
 * assert what a reader sees on stderr as well as what a parser sees on stdout.
 */
export async function cliHuman(files, extraArgs = []) {
  return withRoot(files, async (root) => {
    const result = await cliRun(['--root', root, ...extraArgs])
    return { ...result, report: result.stdout === '' ? null : JSON.parse(result.stdout) }
  })
}

/**
 * A clock that runs a run out of budget after a fixed number of readings.
 *
 * The time budget is the one limit that cannot be driven by the size of an
 * input, and waiting for a real timeout would make the suite slow and flaky.
 * The first reading is the run's start; `allowed` readings after that are
 * inside the budget and everything later is far outside it.
 */
export function budgetClock(allowed) {
  let calls = 0
  return () => {
    calls += 1
    return calls <= allowed + 1 ? 0 : 1e9
  }
}

/** Every rule id a report raised, deduplicated, in the order the report emitted them. */
export const raisedRules = (report) => [...new Set(report.findings.map((finding) => finding.ruleId))]

/** The findings for one rule id, in emitted order. */
export const findingsFor = (report, ruleId) => report.findings.filter((finding) => finding.ruleId === ruleId)

/** True when the report raised that rule at all. */
export const raised = (report, ruleId) => report.findings.some((finding) => finding.ruleId === ruleId)

/**
 * One character from each class the report contract names, built from code
 * points so every test file that uses them stays plain ASCII and readable.
 */
export const FORBIDDEN = Object.freeze({
  'C0 NUL': String.fromCharCode(0x00),
  'C0 LF': String.fromCharCode(0x0a),
  'C0 ESC': String.fromCharCode(0x1b),
  DEL: String.fromCharCode(0x7f),
  'C1 NEL': String.fromCharCode(0x85),
  'C1 CSI': String.fromCharCode(0x9b),
  'line separator': String.fromCharCode(0x2028),
  'paragraph separator': String.fromCharCode(0x2029),
  'bidi LRM': String.fromCharCode(0x200e),
  'bidi RLM': String.fromCharCode(0x200f),
  'bidi RLO': String.fromCharCode(0x202e),
  'bidi isolate': String.fromCharCode(0x2066),
})

/** A sink shaped exactly like the one the implementation uses, for unit tests of a single pass. */
export function sink() {
  return { rows: [], add(row) { this.rows.push({ pointer: '', ...row }) } }
}
