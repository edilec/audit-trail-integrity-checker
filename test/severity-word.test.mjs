import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { DEFAULT_LIMITS, RULE_SEVERITY, checkAuditTrail, createFinding, verifyChain } from '../src/index.mjs'
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
  cliHuman,
  cliReport,
  event,
  findingsFor,
  projectDirectory,
  reseal,
  sink,
} from './support.mjs'

/**
 * The severity of every rule in the catalog, pinned one rule at a time.
 *
 * Most of this package's error rules fire on inputs that are also incomplete,
 * so their exit code is 2 either way and `test/severity-exit.test.mjs` cannot
 * reach them. They are pinned here instead: each test drives a real input
 * through the real entry point, finds the finding the rule produced, and
 * asserts its severity as a **literal written at the assertion**. There is no
 * expected-value map in this file and no import of the table, so a coordinated
 * edit of the table and the documented catalog leaves every assertion below
 * asserting the old value -- which is the point.
 */

const files = (document, checkpoint = checkpointAtEnd(document)) => ({
  [TRAIL_NAME]: document,
  [CHECKPOINT_NAME]: checkpoint,
})

/** The severity the tool actually put on the first finding for that rule. */
async function severityOf(report, ruleId) {
  const found = findingsFor(report, ruleId)
  assert.equal(found.length > 0, true, `${ruleId} was not raised by this input`)
  return found[0].severity
}

const report = async (input, args = WITH_CHECKPOINT) => (await cliReport(input, args)).report

test('anchor-mismatch is an error', async () => {
  const result = await report(cleanFiles(), [...WITH_CHECKPOINT, '--anchor-hash', 'c'.repeat(64)])
  assert.equal(await severityOf(result, 'anchor-mismatch'), 'error')
})

test('chain-link-broken is an error', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1].actor = 'user:intruder'
  reseal(document, 1)
  assert.equal(await severityOf(await report(files(document, checkpoint)), 'chain-link-broken'), 'error')
})

test('chain-link-missing is an error', async () => {
  const document = cleanTrail()
  document.records[2] = { ...document.records[2], previousHash: null }
  reseal(document, 2)
  assert.equal(await severityOf(await report(files(document)), 'chain-link-missing'), 'error')
})

test('checkpoint-hash-mismatch is an error', async () => {
  const document = cleanTrail()
  const result = await report(files(document, { ...checkpointAtEnd(document), recordHash: 'd'.repeat(64) }))
  assert.equal(await severityOf(result, 'checkpoint-hash-mismatch'), 'error')
})

test('checkpoint-invalid is an error', async () => {
  const document = cleanTrail()
  const result = await report(files(document, { ...checkpointAtEnd(document), extra: 1 }))
  assert.equal(await severityOf(result, 'checkpoint-invalid'), 'error')
})

test('checkpoint-outside-segment is an error', async () => {
  const document = chain('billing.eu-west-1', [event('a', { sequence: 40 }), event('b')])
  const checkpoint = { schemaVersion: '1', trail: 'billing.eu-west-1', sequence: 12, recordId: 'q', recordHash: 'e'.repeat(64) }
  assert.equal(await severityOf(await report(files(document, checkpoint)), 'checkpoint-outside-segment'), 'error')
})

test('checkpoint-record-mismatch is an error', async () => {
  const document = cleanTrail()
  const result = await report(files(document, { ...checkpointAtEnd(document), recordId: 'evt-9999' }))
  assert.equal(await severityOf(result, 'checkpoint-record-mismatch'), 'error')
})

test('checkpoint-record-missing is an error', async () => {
  const document = chain('billing.eu-west-1', [event('a', { sequence: 5 }), event('b', { sequence: 9 })])
  const checkpoint = { schemaVersion: '1', trail: 'billing.eu-west-1', sequence: 7, recordId: 'q', recordHash: 'e'.repeat(64) }
  assert.equal(await severityOf(await report(files(document, checkpoint)), 'checkpoint-record-missing'), 'error')
})

test('checkpoint-record-unverified is an error', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[3] = { ...document.records[3], details: { a: { b: { c: { d: 1 } } } } }
  const result = await report(files(document, checkpoint), [...WITH_CHECKPOINT, '--max-detail-depth', '2'])
  assert.equal(await severityOf(result, 'checkpoint-record-unverified'), 'error')
})

test('checkpoint-signature-unsupported is an error', async () => {
  const document = cleanTrail()
  const result = await report(files(document, checkpointAtEnd(document, { signature: 'unchecked' })))
  assert.equal(await severityOf(result, 'checkpoint-signature-unsupported'), 'error')
})

test('checkpoint-trail-mismatch is an error', async () => {
  const document = cleanTrail()
  const result = await report(files(document, { ...checkpointAtEnd(document), trail: 'billing.us-east-1' }))
  assert.equal(await severityOf(result, 'checkpoint-trail-mismatch'), 'error')
})

test('detail-depth-exceeded is an error', async () => {
  const document = chain('billing.eu-west-1', [event('a', { details: { a: { b: { c: 1 } } } })])
  const result = await report(files(document), [...WITH_CHECKPOINT, '--max-detail-depth', '2'])
  assert.equal(await severityOf(result, 'detail-depth-exceeded'), 'error')
})

test('document-invalid is an error', async () => {
  assert.equal(await severityOf(await report({ [TRAIL_NAME]: { ...cleanTrail(), records: 5 } }, []), 'document-invalid'), 'error')
})

test('hash-format-invalid is an error', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1] = { ...document.records[1], hash: 'not-a-digest' }
  assert.equal(await severityOf(await report(files(document, checkpoint)), 'hash-format-invalid'), 'error')
})

test('identifier-invalid is an error', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  delete document.records[1].id
  assert.equal(await severityOf(await report(files(document, checkpoint)), 'identifier-invalid'), 'error')
})

test('input-not-json is an error', async () => {
  assert.equal(await severityOf(await report({ [TRAIL_NAME]: 'records: []\n' }, []), 'input-not-json'), 'error')
})

test('input-not-utf8 is an error', async () => {
  const bytes = new Uint8Array([0x7b, 0x22, 0xff, 0xfe, 0x22, 0x7d])
  assert.equal(await severityOf(await report({ [TRAIL_NAME]: bytes }, []), 'input-not-utf8'), 'error')
})

test('input-too-large is an error', async () => {
  assert.equal(await severityOf(await report(cleanFiles(), ['--max-file-bytes', '32']), 'input-too-large'), 'error')
})

test('input-unreadable is an error', async () => {
  assert.equal(await severityOf(await report({}, []), 'input-unreadable'), 'error')
})

test('no-records is an error', async () => {
  const empty = { schemaVersion: '1', trail: 'billing.eu-west-1', records: [] }
  assert.equal(await severityOf(await report({ [TRAIL_NAME]: empty }, []), 'no-records'), 'error')
})

test('path-escapes-root is an error', async () => {
  const base = await mkdtemp(join(tmpdir(), 'audit-trail-severity-'))
  try {
    await writeFile(join(base, 'outside.json'), '{}')
    const root = join(base, 'root')
    await mkdir(root)
    await symlink(join(base, 'outside.json'), join(root, TRAIL_NAME))

    const result = await checkAuditTrail({ root })

    assert.equal(await severityOf(result, 'path-escapes-root'), 'error')
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})

test('record-hash-mismatch is an error', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1].actor = 'user:intruder'
  assert.equal(await severityOf(await report(files(document, checkpoint)), 'record-hash-mismatch'), 'error')
})

test('record-id-duplicate is an error', async () => {
  const document = chain('billing.eu-west-1', [event('a'), event('a')])
  assert.equal(await severityOf(await report(files(document)), 'record-id-duplicate'), 'error')
})

test('record-invalid is an error', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1] = { ...document.records[1], note: 'added later' }
  assert.equal(await severityOf(await report(files(document, checkpoint)), 'record-invalid'), 'error')
})

test('record-not-canonical is an error', () => {
  // No JSON file can hold a value the canonical form refuses, so this rule is
  // driven through the real pass with a synthesised record instead.
  const rows = sink()
  const compiled = {
    declared: 1,
    trail: 'billing.eu-west-1',
    records: [{
      index: 0,
      pointer: '/records/0',
      id: 'evt-0001',
      sequence: 1,
      timestampSortKey: null,
      previousHash: null,
      hash: '0'.repeat(64),
      raw: { id: 'evt-0001', sequence: 1, previousHash: null, hash: '0'.repeat(64), details: new Map() },
    }],
  }
  verifyChain(rows, TRAIL_NAME, compiled, DEFAULT_LIMITS, { exceeded: () => false }, null)

  assert.equal(rows.rows[0].ruleId, 'record-not-canonical')
  assert.equal(createFinding(rows.rows[0]).severity, 'error')
})

test('records-not-all-verified is an error', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1] = { ...document.records[1], hash: 'not-a-digest' }
  assert.equal(await severityOf(await report(files(document, checkpoint)), 'records-not-all-verified'), 'error')
})

test('schema-version-unsupported is an error', async () => {
  assert.equal(
    await severityOf(await report({ [TRAIL_NAME]: { ...cleanTrail(), schemaVersion: '2' } }, []), 'schema-version-unsupported'),
    'error',
  )
})

test('segment-anchor-unverified is a warning', async () => {
  const document = chain('billing.eu-west-1', [event('a'), event('b')], {
    previousHash: 'b'.repeat(64),
    firstSequence: 101,
  })
  assert.equal(await severityOf(await report(files(document)), 'segment-anchor-unverified'), 'warning')
})

test('sequence-duplicate is an error', async () => {
  const document = chain('billing.eu-west-1', [event('a'), event('b', { sequence: 1 }), event('c', { sequence: 2 })])
  assert.equal(await severityOf(await report(files(document)), 'sequence-duplicate'), 'error')
})

test('sequence-gap is an error', async () => {
  const document = chain('billing.eu-west-1', [event('a'), event('b', { sequence: 9 })])
  assert.equal(await severityOf(await report(files(document)), 'sequence-gap'), 'error')
})

test('sequence-out-of-order is an error', async () => {
  const document = chain('billing.eu-west-1', [event('a', { sequence: 9 }), event('b', { sequence: 2 })])
  assert.equal(await severityOf(await report(files(document)), 'sequence-out-of-order'), 'error')
})

test('sequence-start-mismatch is an error', async () => {
  const result = await report(cleanFiles(), [...WITH_CHECKPOINT, '--first-sequence', '7'])
  assert.equal(await severityOf(result, 'sequence-start-mismatch'), 'error')
})

test('tail-beyond-checkpoint is a warning', async () => {
  const document = cleanTrail()
  assert.equal(await severityOf(await report(files(document, checkpointAt(document, 1))), 'tail-beyond-checkpoint'), 'warning')
})

test('tail-deletion-undetectable is a warning', async () => {
  assert.equal(await severityOf(await report({ [TRAIL_NAME]: cleanTrail() }, []), 'tail-deletion-undetectable'), 'warning')
})

test('tail-truncated-below-checkpoint is an error', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records.length = 2
  assert.equal(await severityOf(await report(files(document, checkpoint)), 'tail-truncated-below-checkpoint'), 'error')
})

test('time-budget-exceeded is an error', async () => {
  const result = await (await import('./support.mjs')).apiReport(cleanFiles(), {
    checkpoint: CHECKPOINT_NAME,
    clock: budgetClock(2),
  })
  assert.equal(await severityOf(result, 'time-budget-exceeded'), 'error')
})

test('timestamp-invalid is an error', async () => {
  const document = chain('billing.eu-west-1', [event('a', { timestamp: '02/01/2026' })])
  assert.equal(await severityOf(await report(files(document)), 'timestamp-invalid'), 'error')
})

test('timestamp-regression is a warning', async () => {
  const document = chain('billing.eu-west-1', [
    event('a', { timestamp: '2026-01-02T09:00:05.000Z' }),
    event('b', { timestamp: '2026-01-02T09:00:04.999Z' }),
  ])
  assert.equal(await severityOf(await report(files(document)), 'timestamp-regression'), 'warning')
})

test('too-many-detail-nodes is an error', async () => {
  const document = chain('billing.eu-west-1', [event('a', { details: { a: 1, b: 2, c: 3 } })])
  const result = await report(files(document), [...WITH_CHECKPOINT, '--max-detail-nodes', '3'])
  assert.equal(await severityOf(result, 'too-many-detail-nodes'), 'error')
})

test('too-many-findings is an error', async () => {
  const document = chain('billing.eu-west-1', [
    event('a', { actor: 4 }),
    event('b', { actor: 4 }),
    event('c', { actor: 4 }),
  ])
  const result = await report(files(document), [...WITH_CHECKPOINT, '--max-findings', '2'])
  assert.equal(await severityOf(result, 'too-many-findings'), 'error')
})

test('too-many-records is an error', async () => {
  assert.equal(await severityOf(await report(cleanFiles(), [...WITH_CHECKPOINT, '--max-records', '2']), 'too-many-records'), 'error')
})

/**
 * The severity word a reader sees. `formatReport` prints it in upper case, and
 * a demotion changes the printed line as well as the exit code.
 */
test('the human report prints the severity word of every finding it lists', async () => {
  const document = cleanTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[1].actor = 'user:intruder'

  const { stderr, report: parsed } = await cliHuman(files(document, checkpoint), WITH_CHECKPOINT)

  assert.match(stderr, /^ERROR {3}trail\.json\/records\/1\/hash record-hash-mismatch /m)
  assert.equal(parsed.findings.length, 1)

  const uncovered = await cliHuman({ [TRAIL_NAME]: cleanTrail() }, [])
  assert.match(uncovered.stderr, /^WARNING trail\.json\/records tail-deletion-undetectable /m)
})

/**
 * Completeness: every rule in the catalog has a case above. A rule with no case
 * has no pinned severity, so this file must fail when one is added without one.
 */
test('every rule in the catalog is pinned by a case in this file', async () => {
  const source = await (await import('node:fs/promises')).readFile(
    join(projectDirectory, 'test/severity-word.test.mjs'),
    'utf8',
  )

  for (const ruleId of Object.keys(RULE_SEVERITY)) {
    assert.equal(source.includes(`'${ruleId}'`), true, `${ruleId} has no severity case in this file`)
  }
})
