import assert from 'node:assert/strict'
import test from 'node:test'

import { CHECKPOINT_KEYS } from '../src/index.mjs'
import {
  CHECKPOINT_NAME,
  TRAIL_NAME,
  WITH_CHECKPOINT,
  chain,
  checkpointAt,
  checkpointAtEnd,
  cleanTrail,
  cliReport,
  event,
  findingsFor,
  raised,
} from './support.mjs'

/**
 * The checkpoint: what it establishes, and everything it does not.
 *
 * A checkpoint is the only evidence this tool can have about the end of a
 * trail, so every way one can fail to apply has to end somewhere other than
 * "covered". None of these cases may produce a pass.
 */

const trailFiles = (document, checkpoint) => ({
  [TRAIL_NAME]: document,
  [CHECKPOINT_NAME]: checkpoint,
})

test('a checkpoint for another trail is not applied to this one', async () => {
  const document = cleanTrail()
  const checkpoint = { ...checkpointAtEnd(document), trail: 'billing.us-east-1' }

  const { code, report } = await cliReport(trailFiles(document, checkpoint), WITH_CHECKPOINT)

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(raised(report, 'checkpoint-trail-mismatch'), true)
  assert.equal(report.coverage.checkpointApplied, false)
  assert.equal(report.coverage.tailDeletionDetectable, false)
})

test('a checkpoint naming a different record at that sequence is an error', async () => {
  const document = cleanTrail()
  const checkpoint = { ...checkpointAtEnd(document), recordId: 'evt-9999' }

  const { code, report } = await cliReport(trailFiles(document, checkpoint), WITH_CHECKPOINT)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(raised(report, 'checkpoint-record-mismatch'), true)
})

test('a checkpoint disagreeing with the digest at that sequence is an error', async () => {
  const document = cleanTrail()
  const checkpoint = { ...checkpointAtEnd(document), recordHash: 'd'.repeat(64) }

  const { code, report } = await cliReport(trailFiles(document, checkpoint), WITH_CHECKPOINT)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(raised(report, 'checkpoint-hash-mismatch'), true)
  assert.equal(findingsFor(report, 'checkpoint-hash-mismatch')[0].evidence.startsWith('checkpoint dddddddddddddddd...'), true)
})

test('a checkpoint whose sequence is missing from a range the file covers is an error', async () => {
  const document = chain('billing.eu-west-1', [event('a'), event('b', { sequence: 5 })])
  const checkpoint = { ...checkpointAtEnd(document), sequence: 3, recordId: 'c' }

  const { code, report } = await cliReport(trailFiles(document, checkpoint), WITH_CHECKPOINT)

  assert.equal(code, 2)
  assert.equal(raised(report, 'checkpoint-record-missing'), true)
  assert.equal(report.coverage.tailDeletionDetectable, false)
})

test('a checkpoint taken before this segment says nothing about its tail', async () => {
  const document = chain('billing.eu-west-1', [event('a'), event('b')], {
    previousHash: 'b'.repeat(64),
    firstSequence: 40,
  })
  const checkpoint = { ...checkpointAtEnd(document), sequence: 12, recordId: 'evt-0012' }

  const { code, report } = await cliReport(trailFiles(document, checkpoint), [
    ...WITH_CHECKPOINT, '--anchor-hash', 'b'.repeat(64),
  ])

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(raised(report, 'checkpoint-outside-segment'), true)
  assert.equal(report.coverage.tailDeletionDetectable, false)
})

test('a checkpoint agreeing with a digest this run never recomputed is not coverage', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  // The record the checkpoint covers is too deep to canonicalise, so its digest
  // was never recomputed. The checkpoint and the file agree with each other and
  // that is all: nothing here says the record is intact.
  document.records[3] = { ...document.records[3], details: { a: { b: { c: { d: 1 } } } } }

  const { code, report } = await cliReport(trailFiles(document, checkpoint), [
    ...WITH_CHECKPOINT, '--max-detail-depth', '2',
  ])

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(raised(report, 'detail-depth-exceeded'), true)
  assert.equal(raised(report, 'checkpoint-record-unverified'), true)
  assert.equal(report.coverage.coveredThroughSequence, null)
  assert.equal(report.coverage.tailDeletionDetectable, false)
})

test('a signature on a checkpoint is reported as unchecked, never as verified', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document, { signature: 'MEUCIQD-not-verified-by-this-build' })

  const { code, report } = await cliReport(trailFiles(document, checkpoint), WITH_CHECKPOINT)

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(raised(report, 'checkpoint-signature-unsupported'), true)
  // The comparison still happened; what did not happen is any verification of
  // where the checkpoint came from.
  assert.equal(report.coverage.checkpointApplied, true)
  assert.equal(report.coverage.coveredThroughSequence, 4)
})

test('a malformed checkpoint is refused, and its trail is not silently uncovered', async () => {
  const cases = [
    { pointer: '', value: [] },
    { pointer: '', value: { ...checkpointAtEnd(cleanTrail()), extra: 1 } },
    { pointer: '/schemaVersion', value: { ...checkpointAtEnd(cleanTrail()), schemaVersion: '2' } },
    { pointer: '/trail', value: { ...checkpointAtEnd(cleanTrail()), trail: 42 } },
    { pointer: '/sequence', value: { ...checkpointAtEnd(cleanTrail()), sequence: -1 } },
    { pointer: '/recordId', value: { ...checkpointAtEnd(cleanTrail()), recordId: '' } },
    { pointer: '/recordHash', value: { ...checkpointAtEnd(cleanTrail()), recordHash: 'AB' } },
    { pointer: '/issuedAt', value: { ...checkpointAtEnd(cleanTrail()), issuedAt: 'yesterday' } },
  ]

  for (const { pointer, value } of cases) {
    const { code, report } = await cliReport(trailFiles(cleanTrail(), value), WITH_CHECKPOINT)

    assert.equal(code, 2, pointer)
    assert.equal(report.status, 'incomplete')
    assert.equal(report.coverage.checkpointRequested, true)
    assert.equal(report.coverage.tailDeletionDetectable, false)
    const finding = report.findings.find((row) => row.location.file === CHECKPOINT_NAME)
    assert.equal(finding.location.pointer, pointer)
  }
})

test('a checkpoint that could not be read leaves the tail unchecked', async () => {
  const { code, report } = await cliReport({ [TRAIL_NAME]: cleanTrail() }, WITH_CHECKPOINT)

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(raised(report, 'input-unreadable'), true)
  assert.equal(report.coverage.checkpointRequested, true)
  assert.equal(report.coverage.tailDeletionDetectable, false)
  // The reason is already on the report; the tool does not also claim a
  // checkpoint was never asked for.
  assert.equal(raised(report, 'tail-deletion-undetectable'), false)
})

test('a checkpoint in the middle of the file covers only up to itself', async () => {
  const document = cleanTrail()

  const { report } = await cliReport(trailFiles(document, checkpointAt(document, 2)), WITH_CHECKPOINT)

  assert.equal(report.coverage.coveredThroughSequence, 3)
  assert.equal(report.coverage.uncoveredTailRecords, 1)
  assert.equal(findingsFor(report, 'tail-beyond-checkpoint')[0].location.pointer, '/records/3')
})

test('the checkpoint key set is the one the tool actually reads', () => {
  assert.deepEqual(
    [...CHECKPOINT_KEYS],
    ['issuedAt', 'recordHash', 'recordId', 'schemaVersion', 'sequence', 'signature', 'trail'],
  )
})
