import assert from 'node:assert/strict'
import test from 'node:test'

import { DEFAULT_LIMITS, HARD_LIMITS, checkAuditTrail, validateLimits } from '../src/index.mjs'
import {
  CHECKPOINT_NAME,
  TRAIL_NAME,
  WITH_CHECKPOINT,
  chain,
  checkpointAtEnd,
  cleanFiles,
  cleanTrail,
  cliReport,
  cliRun,
  event,
  findingsFor,
  raised,
  withRoot,
} from './support.mjs'

/**
 * Limits: declared, enforced, and rejected when misspelled.
 *
 * A limit that is accepted and ignored is worse than no limit, because it reads
 * as protection. A one-character typo in a limit name must not turn a real
 * failure into a green run, so an unknown key throws and the CLI turns that
 * into a configuration error with an empty stdout.
 */

test('every documented limit has a cap, and the defaults are inside it', () => {
  assert.deepEqual(Object.keys(DEFAULT_LIMITS).sort(), Object.keys(HARD_LIMITS).sort())
  for (const [key, value] of Object.entries(DEFAULT_LIMITS)) {
    assert.equal(Number.isInteger(value), true, key)
    assert.equal(value >= 1 && value <= HARD_LIMITS[key], true, key)
  }
})

test('an unknown limit name is refused rather than ignored', () => {
  assert.throws(() => validateLimits({ maxRecord: 5 }), /Unknown limit "maxRecord"/)
  assert.throws(() => validateLimits({ maxrecords: 5 }), /Unknown limit/)
})

test('a limit outside its range is refused', () => {
  assert.throws(() => validateLimits({ maxRecords: 0 }), /between 1 and/)
  assert.throws(() => validateLimits({ maxRecords: HARD_LIMITS.maxRecords + 1 }), /between 1 and/)
  assert.throws(() => validateLimits({ maxRecords: 1.5 }), /between 1 and/)
  assert.throws(() => validateLimits({ maxRecords: '10' }), /between 1 and/)
  assert.throws(() => validateLimits([]), /limits must be an object/)
})

test('a lowered limit is the one enforced', () => {
  assert.equal(validateLimits({ maxRecords: 3 }).maxRecords, 3)
  assert.equal(validateLimits({}).maxRecords, DEFAULT_LIMITS.maxRecords)
})

test('a misspelled limit on the command line is a configuration error with an empty stdout', async () => {
  const { code, stdout, stderr } = await cliRun(['--root', '.', '--max-record', '5'])

  assert.equal(code, 2)
  assert.equal(stdout, '')
  assert.match(stderr, /Unknown option "--max-record"/)
})

test('an unknown option to the exported function is refused', async () => {
  await assert.rejects(
    () => checkAuditTrail({ root: '.', checkpoints: 'x.json' }),
    /Unknown option "checkpoints"/,
  )
})

test('each record limit is enforced and named in the finding that fires', async () => {
  const deep = chain('billing.eu-west-1', [event('a', { details: { a: { b: { c: 1 } } } })])
  const wide = chain('billing.eu-west-1', [event('a', { details: { a: 1, b: 2, c: 3, d: 4 } })])

  const depth = await cliReport(
    { [TRAIL_NAME]: deep, [CHECKPOINT_NAME]: checkpointAtEnd(deep) },
    [...WITH_CHECKPOINT, '--max-detail-depth', '2'],
  )
  assert.equal(depth.code, 2)
  assert.equal(raised(depth.report, 'detail-depth-exceeded'), true)
  assert.match(findingsFor(depth.report, 'detail-depth-exceeded')[0].message, /maxDetailDepth limit of 2/)
  // The route into `details` is key positions, never key names: see
  // refusalPointer, and test/redaction.test.mjs for why.
  assert.equal(findingsFor(depth.report, 'detail-depth-exceeded')[0].location.pointer, '/records/0/details/#0/#0')

  const nodes = await cliReport(
    { [TRAIL_NAME]: wide, [CHECKPOINT_NAME]: checkpointAtEnd(wide) },
    [...WITH_CHECKPOINT, '--max-detail-nodes', '4'],
  )
  assert.equal(nodes.code, 2)
  assert.equal(raised(nodes.report, 'too-many-detail-nodes'), true)
  assert.match(findingsFor(nodes.report, 'too-many-detail-nodes')[0].message, /maxDetailNodes limit of 4/)
})

test('a record refused by a limit is never counted as examined', async () => {
  const deep = chain('billing.eu-west-1', [event('a'), event('b', { details: { a: { b: { c: 1 } } } })])

  const { report } = await cliReport(
    { [TRAIL_NAME]: deep, [CHECKPOINT_NAME]: checkpointAtEnd(deep) },
    [...WITH_CHECKPOINT, '--max-detail-depth', '2'],
  )

  assert.equal(report.summary.records, 2)
  assert.equal(report.summary.checked, 1)
  assert.equal(report.summary.chainVerified, false)
})

test('the time budget is injected, never read from a wall clock', async () => {
  await withRoot(cleanFiles(), async (root) => {
    let readings = 0
    const report = await checkAuditTrail({
      root,
      checkpoint: CHECKPOINT_NAME,
      clock: () => { readings += 1; return 0 },
    })

    assert.equal(report.status, 'pass')
    assert.equal(readings > 1, true, 'the injected clock is the one the budget reads')
  })
})

test('a clock that is not a function is a configuration error', async () => {
  await assert.rejects(() => checkAuditTrail({ root: '.', clock: 5 }), /clock must be a function/)
})

test('an anchor that is not a digest, and a first sequence that is not an index, are refused', async () => {
  await assert.rejects(() => checkAuditTrail({ root: '.', anchorHash: 'AB' }), /64 lower-case hex/)
  await assert.rejects(() => checkAuditTrail({ root: '.', firstSequence: -1 }), /firstSequence must be an integer/)

  const anchor = await cliRun(['--root', '.', '--anchor-hash', 'AB'])
  assert.equal(anchor.code, 2)
  assert.equal(anchor.stdout, '')

  const sequence = await cliRun(['--root', '.', '--first-sequence', 'x'])
  assert.equal(sequence.code, 2)
  assert.equal(sequence.stdout, '')
  assert.match(sequence.stderr, /--first-sequence requires a non-negative integer/)
})

test('the maximum record count is enforced before any record is read', async () => {
  const document = cleanTrail()

  const { report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    [...WITH_CHECKPOINT, '--max-records', '3'],
  )

  assert.equal(report.summary.checked, 0)
  assert.equal(report.summary.records, 0)
  assert.match(findingsFor(report, 'too-many-records')[0].message, /maxRecords limit of 3/)
})
