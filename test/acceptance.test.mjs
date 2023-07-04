import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CHECKPOINT_NAME,
  TRAIL_NAME,
  WITH_CHECKPOINT,
  chain,
  checkpointAt,
  checkpointAtEnd,
  cleanFiles,
  cleanTrail,
  cliReport,
  event,
  raised,
  reseal,
} from './support.mjs'

/**
 * What this tool is for, and the one thing it cannot do.
 *
 * Every case here runs through the real binary and asserts the real exit code.
 * The last three are the ones that matter most: they establish that the tool
 * does **not** claim to detect a deletion from the end of a trail, by showing
 * that a truncated trail and a whole one produce the same verdict, and that the
 * report says so in its own field instead of leaving a reader to assume
 * otherwise.
 */

test('a trail that verifies, checkpointed at its last record, passes', async () => {
  const { code, report, stdout } = await cliReport(cleanFiles(), WITH_CHECKPOINT)

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.deepEqual(report.findings, [])
  assert.equal(report.summary.checked, 4)
  assert.equal(report.summary.hashesVerified, 4)
  assert.equal(report.summary.linksVerified, 3)
  assert.equal(report.summary.chainVerified, true)
  assert.equal(report.summary.sequenceContinuous, true)
  assert.equal(report.coverage.tailDeletionDetectable, true)
  assert.equal(report.coverage.uncoveredTailRecords, 0)
  assert.equal(stdout.endsWith('}\n'), true)
})

test('a middle record edited in place is detected by its own digest', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1].actor = 'user:intruder'

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint },
    WITH_CHECKPOINT,
  )

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(raised(report, 'record-hash-mismatch'), true)
  assert.equal(report.summary.chainVerified, false)
  // The edit was seen. Every record was still examined: this is a verdict, not
  // a run that gave up.
  assert.equal(report.summary.checked, 4)
  assert.equal(report.summary.hashesVerified, 3)
})

test('a middle record edited and resealed is detected by the next record link', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1].actor = 'user:intruder'
  reseal(document, 1)

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint },
    WITH_CHECKPOINT,
  )

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  // Recomputing the digest of the edited record is not enough for the attacker:
  // the record after it still names the digest the record used to have.
  assert.equal(raised(report, 'record-hash-mismatch'), false)
  assert.equal(raised(report, 'chain-link-broken'), true)
  assert.equal(report.findings[0].location.pointer, '/records/2/previousHash')
})

test('a middle record removed is detected by the link and by the sequence', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records.splice(1, 1)

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint },
    WITH_CHECKPOINT,
  )

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(raised(report, 'chain-link-broken'), true)
  assert.equal(raised(report, 'sequence-gap'), true)
  assert.equal(report.summary.chainVerified, false)
  assert.equal(report.summary.sequenceContinuous, false)
})

/**
 * The acceptance case this tool exists to state honestly.
 *
 * The truncated trail is not a broken trail. Every digest in it matches, every
 * link matches, the sequence is consecutive, and there is nothing inside the
 * file to compare its end against. A tool that reported that as a pass would be
 * telling its reader the trail is complete, which it has no evidence for.
 */
test('without a checkpoint, a truncated trail verifies exactly as the whole one does', async () => {
  const whole = cleanTrail()
  const truncated = cleanTrail()
  truncated.records.length = 2

  const full = await cliReport({ [TRAIL_NAME]: whole })
  const cut = await cliReport({ [TRAIL_NAME]: truncated })

  // Same verdict on both: the chain is intact in both files, which is precisely
  // why the chain cannot be what tells them apart.
  assert.equal(full.report.summary.chainVerified, true)
  assert.equal(cut.report.summary.chainVerified, true)
  assert.equal(full.report.summary.sequenceContinuous, true)
  assert.equal(cut.report.summary.sequenceContinuous, true)
  assert.equal(cut.report.summary.errors, 0)

  // And neither one is a pass, because "no records were removed from the end"
  // is a claim this run has no evidence for.
  assert.equal(full.code, 2)
  assert.equal(cut.code, 2)
  assert.equal(full.report.status, 'incomplete')
  assert.equal(cut.report.status, 'incomplete')
  assert.equal(raised(cut.report, 'tail-deletion-undetectable'), true)
  assert.equal(cut.report.coverage.tailDeletionDetectable, false)
  assert.equal(cut.report.coverage.checkpointRequested, false)
})

test('the report says in its own field that tail deletion was undetectable', async () => {
  const { report, stderr } = await cliReport({ [TRAIL_NAME]: cleanTrail() })

  assert.equal(report.coverage.tailDeletionDetectable, false)
  assert.equal(report.coverage.coveredThroughSequence, null)
  assert.equal(report.coverage.checkpointApplied, false)
  assert.equal(report.status, 'incomplete')
  // --json silences the human summary; the one line that is never silenced is
  // the one that says this run is not a pass.
  assert.match(stderr, /incomplete: this run is not a pass\./)
})

test('with a checkpoint, a truncated tail is detected', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records.length = 2

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint },
    WITH_CHECKPOINT,
  )

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(raised(report, 'tail-truncated-below-checkpoint'), true)
  assert.equal(report.coverage.tailDeletionDetectable, true)
})

test('a checkpoint covers up to its own record and no further', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAt(document, 1)

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint },
    WITH_CHECKPOINT,
  )

  // Everything in the file verifies and the checkpoint matched. The run is
  // still incomplete, because the two records after the checkpoint are in
  // exactly the position the whole trail was in without one.
  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.chainVerified, true)
  assert.equal(report.coverage.coveredThroughSequence, 2)
  assert.equal(report.coverage.uncoveredTailRecords, 2)
  assert.equal(raised(report, 'tail-beyond-checkpoint'), true)
})

test('a sequence number skipped by the producer is invisible to the chain', async () => {
  const document = chain('billing.eu-west-1', [
    event('evt-0001'),
    event('evt-0002', { sequence: 5 }),
    event('evt-0003'),
  ])

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    WITH_CHECKPOINT,
  )

  assert.equal(code, 1)
  // This is the case that makes the sequence check worth having separately: the
  // chain is perfect and four numbers are unaccounted for.
  assert.equal(report.summary.chainVerified, true)
  assert.equal(report.summary.sequenceContinuous, false)
  assert.equal(raised(report, 'sequence-gap'), true)
  assert.equal(raised(report, 'chain-link-broken'), false)
})
