import assert from 'node:assert/strict'
import test from 'node:test'

import { RECORD_KEYS, TRAIL_DOCUMENT_KEYS, compileTrail } from '../src/index.mjs'
import {
  CHECKPOINT_NAME,
  TRAIL_NAME,
  WITH_CHECKPOINT,
  apiReport,
  chain,
  checkpointAtEnd,
  cleanTrail,
  cliReport,
  event,
  findingsFor,
  raised,
  sink,
} from './support.mjs'

/**
 * The schema check, exercised through the real entry point.
 *
 * The distinction this file is really about is which defects leave the run able
 * to say anything at all. A record missing its `hash` cannot take part in the
 * chain, so the run examined fewer records than the file declares and is
 * incomplete. A record with an unknown key can still be hashed, so the chain
 * verdict stands and the run is a completed failure.
 */

const limits = { maxDetailDepth: 8, maxDetailNodes: 500, maxFileBytes: 1000, maxFindings: 10, maxRecords: 10, maxRuntimeMs: 1000 }

function trailWith(records) {
  return { schemaVersion: '1', trail: 'billing.eu-west-1', records }
}

test('the document must be an object with the declared keys', async () => {
  // A string would be written to the file verbatim rather than as JSON; that
  // path is covered by test/incomplete.test.mjs instead.
  for (const value of [[], 42, null, true]) {
    const report = await apiReport({ [TRAIL_NAME]: value })
    assert.equal(raised(report, 'document-invalid'), true)
    assert.equal(report.status, 'incomplete')
  }
})

test('an unknown document key is refused, so a typo cannot disable a check', async () => {
  const document = { ...cleanTrail(), recrods: [] }

  const report = await apiReport({ [TRAIL_NAME]: document })

  assert.equal(raised(report, 'document-invalid'), true)
  assert.equal(report.status, 'incomplete')
  assert.match(findingsFor(report, 'document-invalid')[0].message, /"recrods"/)
})

test('a schemaVersion this build does not implement is refused, not guessed at', async () => {
  const report = await apiReport({ [TRAIL_NAME]: { ...cleanTrail(), schemaVersion: '2' } })

  assert.equal(raised(report, 'schema-version-unsupported'), true)
  assert.equal(report.status, 'incomplete')
})

test('a document with no records at all is incomplete, never a green run on no evidence', async () => {
  const { code, report } = await cliReport({ [TRAIL_NAME]: trailWith([]) })

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.checked, 0)
  assert.equal(raised(report, 'no-records'), true)
})

test('a record missing a chain-critical member is excluded, and the run says so', async () => {
  const cases = [
    { pointer: '/records/1/id', rule: 'identifier-invalid', mutate: (record) => { delete record.id } },
    { pointer: '/records/1/sequence', rule: 'record-invalid', mutate: (record) => { record.sequence = '2' } },
    { pointer: '/records/1/hash', rule: 'hash-format-invalid', mutate: (record) => { record.hash = 'nope' } },
    { pointer: '/records/1/previousHash', rule: 'hash-format-invalid', mutate: (record) => { record.previousHash = 7 } },
  ]

  for (const { pointer, rule, mutate } of cases) {
    const document = cleanTrail()
    mutate(document.records[1])
    const report = await apiReport(
      { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
      { checkpoint: CHECKPOINT_NAME },
    )

    assert.equal(raised(report, rule), true, rule)
    assert.equal(findingsFor(report, rule)[0].location.pointer, pointer)
    // Excluded, so fewer records were examined than the file declares.
    assert.equal(report.summary.checked, 3)
    assert.equal(raised(report, 'records-not-all-verified'), true)
    assert.equal(report.status, 'incomplete')
    assert.equal(report.summary.chainVerified, false)
  }
})

test('an unknown record key is an error, and the chain verdict still stands', async () => {
  const document = cleanTrail()
  document.records[2] = { ...document.records[2], signature: 'x' }
  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    WITH_CHECKPOINT,
  )

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(raised(report, 'record-invalid'), true)
  // The digest covers the unknown key, so adding one breaks the record's own
  // hash. The point of this case is the other half: every record was examined.
  assert.equal(report.summary.checked, 4)
  assert.equal(raised(report, 'records-not-all-verified'), false)
})

test('a bad timestamp is a completed failure, not missing evidence', async () => {
  const document = chain('billing.eu-west-1', [
    event('evt-0001'),
    event('evt-0002', { timestamp: '02/01/2026 09:00' }),
  ])

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    WITH_CHECKPOINT,
  )

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(raised(report, 'timestamp-invalid'), true)
  assert.equal(report.summary.checked, 2)
  assert.equal(report.summary.chainVerified, true)
})

test('timestamps are accepted with or without a fractional part and compared correctly', async () => {
  const document = chain('billing.eu-west-1', [
    event('evt-0001', { timestamp: '2026-01-02T09:00:00Z' }),
    event('evt-0002', { timestamp: '2026-01-02T09:00:00.500Z' }),
  ])

  const report = await apiReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    { checkpoint: CHECKPOINT_NAME },
  )

  // Compared as text, a missing fraction would sort after ".500" and look like
  // a regression. It is normalised to ".000" for the comparison only.
  assert.equal(raised(report, 'timestamp-regression'), false)
  assert.equal(raised(report, 'timestamp-invalid'), false)
  assert.equal(report.status, 'pass')
})

test('a timestamp that goes backwards is a warning, not a chain defect', async () => {
  const document = chain('billing.eu-west-1', [
    event('evt-0001', { timestamp: '2026-01-02T09:00:05.000Z' }),
    event('evt-0002', { timestamp: '2026-01-02T09:00:04.999Z' }),
  ])

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    WITH_CHECKPOINT,
  )

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.equal(report.summary.warnings, 1)
  assert.equal(raised(report, 'timestamp-regression'), true)
})

test('a repeated record id is reported at the second occurrence', async () => {
  const document = chain('billing.eu-west-1', [event('evt-0001'), event('evt-0001')])

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    WITH_CHECKPOINT,
  )

  assert.equal(code, 1)
  assert.equal(raised(report, 'record-id-duplicate'), true)
  assert.equal(findingsFor(report, 'record-id-duplicate')[0].location.pointer, '/records/1/id')
  assert.equal(report.summary.checked, 2)
})

test('optional members are optional, and checked when present', async () => {
  const rows = sink()
  const document = trailWith([
    { id: 'a', sequence: 1, previousHash: null, hash: '0'.repeat(64), timestamp: '2026-01-02T09:00:00.000Z', actor: 'svc', action: 'x', target: 'y', details: { a: 1 } },
    { id: 'b', sequence: 2, previousHash: '0'.repeat(64), hash: '1'.repeat(64), timestamp: '2026-01-02T09:00:01.000Z', actor: 'svc', action: 'x', target: 4, details: [] },
  ])

  const compiled = compileTrail(rows, TRAIL_NAME, document, limits)

  assert.equal(compiled.records.length, 2)
  assert.deepEqual(
    rows.rows.map((row) => `${row.pointer} ${row.ruleId}`),
    ['/records/1/target record-invalid', '/records/1/details record-invalid'],
  )
})

test('the declared key sets are the ones the tool actually reads', () => {
  assert.deepEqual([...TRAIL_DOCUMENT_KEYS], ['records', 'schemaVersion', 'trail'])
  assert.deepEqual(
    [...RECORD_KEYS],
    ['action', 'actor', 'details', 'hash', 'id', 'previousHash', 'sequence', 'target', 'timestamp'],
  )
})
