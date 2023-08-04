import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CHECKPOINT_NAME,
  TRAIL_NAME,
  WITH_CHECKPOINT,
  budgetClock,
  chain,
  checkpointAt,
  checkpointAtEnd,
  cleanFiles,
  cleanTrail,
  cliReport,
  event,
  raised,
} from './support.mjs'

/**
 * Every way this tool can fail to obtain the evidence it declared, and the
 * proof that none of them can end in a pass.
 *
 * Three of the cases below raise no error-severity finding at all. For those,
 * the `incomplete` flag is the only thing standing between the input and exit
 * 0 -- the defect class the report contract names explicitly -- so each one
 * asserts the exit code and the error count together. Delete the flag and the
 * count stays 0 while the exit code moves to 0, which is exactly what these
 * assertions catch.
 */

test('an input that is not valid UTF-8 is not parsed and not passed', async () => {
  const bytes = new Uint8Array([0x7b, 0x22, 0xff, 0xfe, 0x22, 0x7d])

  const { code, report } = await cliReport({ [TRAIL_NAME]: bytes })

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(raised(report, 'input-not-utf8'), true)
  assert.equal(report.summary.checked, 0)
})

test('an input that is not JSON is reported rather than guessed at', async () => {
  const { code, report } = await cliReport({ [TRAIL_NAME]: 'records: []\n' })

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(raised(report, 'input-not-json'), true)
})

test('a missing input produces a report saying which input was not read', async () => {
  const { code, report } = await cliReport({})

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(raised(report, 'input-unreadable'), true)
  assert.equal(report.findings[0].location.file, TRAIL_NAME)
})

test('a file above the byte limit is not read', async () => {
  const { code, report } = await cliReport(cleanFiles(), ['--max-file-bytes', '32'])

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(raised(report, 'input-too-large'), true)
})

test('a trail above the record limit is refused whole, never read in part', async () => {
  const { code, report } = await cliReport(cleanFiles(), [...WITH_CHECKPOINT, '--max-records', '2'])

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(raised(report, 'too-many-records'), true)
  assert.equal(report.summary.checked, 0)
})

test('a record that could not be examined makes the run incomplete', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1] = { ...document.records[1], hash: 'not-a-digest' }

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint },
    WITH_CHECKPOINT,
  )

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(raised(report, 'records-not-all-verified'), true)
  assert.equal(report.summary.checked, 3)
  assert.equal(report.summary.records, 4)
})

test('the run is incomplete when the budget stopped it, even with every record examined', async () => {
  const files = cleanFiles()
  // Four readings inside the budget: one per record in the chain pass. The
  // sequence pass then reads a fifth and stops. Every digest was compared, so
  // this is the case where only the budget flag can withhold the verdict.
  const { report } = await cliReport(files, WITH_CHECKPOINT)
  assert.equal(report.status, 'pass')

  const stopped = await (await import('./support.mjs')).apiReport(files, {
    checkpoint: CHECKPOINT_NAME,
    clock: budgetClock(4),
  })

  assert.equal(stopped.status, 'incomplete')
  assert.equal(stopped.summary.checked, 4)
  assert.equal(raised(stopped, 'time-budget-exceeded'), true)
  assert.equal(raised(stopped, 'records-not-all-verified'), false)
  assert.equal(stopped.summary.sequenceContinuous, false)
})

test('more findings than the limit is a partial report, not a shorter clean one', async () => {
  const document = chain('billing.eu-west-1', [
    event('a', { actor: 4 }),
    event('b', { actor: 4 }),
    event('c', { actor: 4 }),
  ])

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    [...WITH_CHECKPOINT, '--max-findings', '2'],
  )

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.findings.length, 2)
  assert.equal(raised(report, 'too-many-findings'), true)
})

/**
 * The three cases whose only findings are warnings. If `incomplete` stopped
 * being set for any of them, `summary.errors` would still be 0 and the exit
 * code would become 0 -- a green run on evidence nobody obtained.
 */
test('no checkpoint: warnings only, and still not a pass', async () => {
  const { code, report } = await cliReport({ [TRAIL_NAME]: cleanTrail() })

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
})

test('a checkpoint short of the end: warnings only, and still not a pass', async () => {
  const document = cleanTrail()

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAt(document, 1) },
    WITH_CHECKPOINT,
  )

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
})

test('a segment with no anchor: warnings only, and still not a pass', async () => {
  const document = chain('billing.eu-west-1', [event('evt-0101'), event('evt-0102')], {
    previousHash: 'b'.repeat(64),
    firstSequence: 101,
  })

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    WITH_CHECKPOINT,
  )

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
})

test('a pass is reachable only when every verdict the report carries is true', async () => {
  const { code, report } = await cliReport(cleanFiles(), WITH_CHECKPOINT)

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.equal(report.summary.chainVerified, true)
  assert.equal(report.summary.sequenceContinuous, true)
  assert.equal(report.coverage.tailDeletionDetectable, true)
  assert.equal(report.coverage.uncoveredTailRecords, 0)
  assert.equal(report.summary.checked > 0, true)
})

/**
 * The one `incomplete` flag in this package that no test reached.
 *
 * `checkpoint-record-unverified` is raised whenever the checkpoint agrees with
 * a digest this run never recomputed, and it was pinned only through inputs
 * that were already incomplete for a second reason -- a record too deep to
 * canonicalise is also a record that was never examined, and case (3) in
 * index.mjs marks the run incomplete for that. So flipping coverage.mjs's flag
 * to `false` left the whole suite green.
 *
 * This input has no second reason. Record 2 is edited in place and keeps the
 * digest it was written with, so the run *does* examine it -- a recomputed
 * digest that disagrees is evidence, and `checked` reaches the declared count.
 * The checkpoint carries that same stored digest, so the checkpoint and the
 * file agree with each other while the record itself is known to have been
 * rewritten. The only thing left holding exit 2 is the flag: with it the run
 * is incomplete, without it the same input is an ordinary `fail` at exit 1,
 * and a reader is told the trail was checked and found wrong rather than that
 * the checkpoint established nothing.
 */
test('a checkpoint agreeing with a stored digest that did not recompute is incomplete, not merely failed', async () => {
  const document = cleanTrail()
  document.records[1] = { ...document.records[1], actor: 'user:intruder' }
  const checkpoint = checkpointAt(document, 1)

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint },
    WITH_CHECKPOINT,
  )

  // The second reason is really absent: every declared record was examined.
  assert.equal(report.summary.checked, report.summary.records)
  assert.equal(raised(report, 'records-not-all-verified'), false)
  assert.equal(raised(report, 'record-hash-mismatch'), true)

  assert.equal(raised(report, 'checkpoint-record-unverified'), true)
  assert.equal(report.coverage.checkpointApplied, true)
  assert.equal(report.coverage.coveredThroughSequence, null)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
})
