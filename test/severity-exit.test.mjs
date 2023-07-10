import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CHECKPOINT_NAME,
  TRAIL_NAME,
  WITH_CHECKPOINT,
  chain,
  checkpointAtEnd,
  cleanFiles,
  cleanTrail,
  cliReport,
  event,
  reseal,
} from './support.mjs'

/**
 * Severity, pinned by the process exit code.
 *
 * Every case below completes: nothing about its input is unknown, unsupported
 * or truncated, so the report is a verdict and the binary exits 1. Demote the
 * rule it turns on to a warning and the same input exits 0 -- a refusal turned
 * into a green build, which is exactly the drift a table cannot defend against.
 * Three declarations can be edited together; an exit code cannot be edited at
 * all.
 *
 * The other direction is pinned too: a run whose only finding is the one
 * warning that does not withhold the pass must exit 0, so promoting it is
 * caught here as well.
 *
 * Every expectation is a literal written at the place it is asserted.
 */

const files = (document, checkpoint = checkpointAtEnd(document)) => ({
  [TRAIL_NAME]: document,
  [CHECKPOINT_NAME]: checkpoint,
})

test('a trail with nothing wrong exits 0 with an empty findings list', async () => {
  const { code, report } = await cliReport(cleanFiles(), WITH_CHECKPOINT)

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.deepEqual(report.findings, [])
})

test('a record edited in place exits 1', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1].actor = 'user:intruder'

  const { code, report } = await cliReport(files(document, checkpoint), WITH_CHECKPOINT)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('a record edited and resealed exits 1', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1].actor = 'user:intruder'
  reseal(document, 1)

  const { code, report } = await cliReport(files(document, checkpoint), WITH_CHECKPOINT)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('a null link in the middle exits 1', async () => {
  const document = cleanTrail()
  document.records[2] = { ...document.records[2], previousHash: null }
  reseal(document, 2)

  const { code, report } = await cliReport(files(document), WITH_CHECKPOINT)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 2)
})

test('a skipped sequence number exits 1', async () => {
  const document = chain('billing.eu-west-1', [event('a'), event('b', { sequence: 9 })])

  const { code, report } = await cliReport(files(document), WITH_CHECKPOINT)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('a repeated sequence number exits 1', async () => {
  // The checkpointed record keeps a sequence of its own: a checkpoint over a
  // number two records share would be ambiguous, which is a different case.
  const document = chain('billing.eu-west-1', [
    event('a'),
    event('b', { sequence: 1 }),
    event('c', { sequence: 2 }),
  ])

  const { code, report } = await cliReport(files(document), WITH_CHECKPOINT)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('a sequence number that goes backwards exits 1', async () => {
  const document = chain('billing.eu-west-1', [event('a', { sequence: 9 }), event('b', { sequence: 2 })])

  const { code, report } = await cliReport(files(document), WITH_CHECKPOINT)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('a segment that does not start where --first-sequence says exits 1', async () => {
  const { code, report } = await cliReport(cleanFiles(), [...WITH_CHECKPOINT, '--first-sequence', '7'])

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('a repeated record id exits 1', async () => {
  const document = chain('billing.eu-west-1', [event('a'), event('a')])

  const { code, report } = await cliReport(files(document), WITH_CHECKPOINT)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('an unknown key on a record exits 1', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1] = { ...document.records[1], note: 'added later' }

  const { code, report } = await cliReport(files(document, checkpoint), WITH_CHECKPOINT)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 2)
})

test('a malformed timestamp exits 1', async () => {
  const document = chain('billing.eu-west-1', [event('a', { timestamp: '02/01/2026' })])

  const { code, report } = await cliReport(files(document), WITH_CHECKPOINT)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('an anchor that names another predecessor exits 1', async () => {
  const { code, report } = await cliReport(cleanFiles(), [...WITH_CHECKPOINT, '--anchor-hash', 'c'.repeat(64)])

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('a checkpoint disagreeing about the record at its sequence exits 1', async () => {
  const document = cleanTrail()

  const byId = await cliReport(
    files(document, { ...checkpointAtEnd(document), recordId: 'evt-9999' }),
    WITH_CHECKPOINT,
  )
  assert.equal(byId.code, 1)
  assert.equal(byId.report.summary.errors, 1)

  const byHash = await cliReport(
    files(document, { ...checkpointAtEnd(document), recordHash: 'd'.repeat(64) }),
    WITH_CHECKPOINT,
  )
  assert.equal(byHash.code, 1)
  assert.equal(byHash.report.summary.errors, 1)
})

test('a trail that stops short of its checkpoint exits 1', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records.length = 2

  const { code, report } = await cliReport(files(document, checkpoint), WITH_CHECKPOINT)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
})

test('a run whose only finding is a timestamp regression exits 0', async () => {
  const document = chain('billing.eu-west-1', [
    event('a', { timestamp: '2026-01-02T09:00:05.000Z' }),
    event('b', { timestamp: '2026-01-02T09:00:04.999Z' }),
  ])

  const { code, report } = await cliReport(files(document), WITH_CHECKPOINT)

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
})
