import assert from 'node:assert/strict'
import test from 'node:test'

import { DEFAULT_LIMITS, checkSequence, compileTrail, createFinding, verifyChain } from '../src/index.mjs'
import {
  CHECKPOINT_NAME,
  TRAIL_NAME,
  WITH_CHECKPOINT,
  budgetClock,
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
 * The chain and the sequence, including the cases only reachable by driving the
 * two passes directly.
 */

const NEVER = { exceeded: () => false }

function compile(document, rows = sink()) {
  return { rows, compiled: compileTrail(rows, TRAIL_NAME, document, DEFAULT_LIMITS) }
}

test('a link is verified only when both ends were verified', async () => {
  const document = cleanTrail()
  // Break the digest of record 0 without touching the link record 1 carries.
  document.records[0] = { ...document.records[0], hash: 'a'.repeat(64) }
  document.records[1] = { ...document.records[1], previousHash: 'a'.repeat(64) }

  const { rows, compiled } = compile(document)
  const result = verifyChain(rows, TRAIL_NAME, compiled, DEFAULT_LIMITS, NEVER, null)

  // The link between 0 and 1 matches what the file says, and neither end of it
  // is the record its digest was written for -- so that link proves nothing and
  // is not counted. Rewriting the link also rewrote record 1's own digest,
  // because `previousHash` is covered by it: the two are entangled on purpose.
  assert.equal(result.hashMismatches, 2)
  assert.equal(result.linkFailures, 0)
  assert.equal(result.linksVerified, 1)
  assert.deepEqual(result.digestVerified, [false, false, true, true])
  assert.equal(result.chainVerified, false)
})

test('a null link in the middle of a file is reported as its own break', async () => {
  const document = cleanTrail()
  document.records[2] = { ...document.records[2], previousHash: null }

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    WITH_CHECKPOINT,
  )

  assert.equal(code, 1)
  assert.equal(raised(report, 'chain-link-missing'), true)
})

test('a segment whose first record links elsewhere is unverified without an anchor', async () => {
  const document = chain('billing.eu-west-1', [event('evt-0101'), event('evt-0102')], {
    previousHash: 'b'.repeat(64),
    firstSequence: 101,
  })

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    WITH_CHECKPOINT,
  )

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.errors, 0)
  assert.equal(raised(report, 'segment-anchor-unverified'), true)
  assert.equal(report.summary.chainVerified, false)
})

test('an anchor that matches completes the segment, and one that does not is an error', async () => {
  const document = chain('billing.eu-west-1', [event('evt-0101'), event('evt-0102')], {
    previousHash: 'b'.repeat(64),
    firstSequence: 101,
  })
  const files = { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) }

  const matched = await cliReport(files, [...WITH_CHECKPOINT, '--anchor-hash', 'b'.repeat(64)])
  assert.equal(matched.code, 0)
  assert.equal(matched.report.status, 'pass')
  assert.equal(matched.report.summary.chainVerified, true)

  const mismatched = await cliReport(files, [...WITH_CHECKPOINT, '--anchor-hash', 'c'.repeat(64)])
  assert.equal(mismatched.code, 1)
  assert.equal(raised(mismatched.report, 'anchor-mismatch'), true)
})

test('an anchor given for a trail that starts at its own genesis is a mismatch', async () => {
  const document = cleanTrail()

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    [...WITH_CHECKPOINT, '--anchor-hash', 'c'.repeat(64)],
  )

  assert.equal(code, 1)
  assert.equal(raised(report, 'anchor-mismatch'), true)
})

test('--first-sequence catches a segment that does not start where it should', async () => {
  const document = cleanTrail()

  const { code, report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    [...WITH_CHECKPOINT, '--first-sequence', '7'],
  )

  assert.equal(code, 1)
  assert.equal(raised(report, 'sequence-start-mismatch'), true)
  assert.equal(findingsFor(report, 'sequence-start-mismatch')[0].location.pointer, '/records/0/sequence')
})

test('sequence numbers that repeat or go backwards are reported apart from a gap', async () => {
  const repeated = chain('billing.eu-west-1', [event('a'), event('b', { sequence: 1 })])
  const backwards = chain('billing.eu-west-1', [event('a', { sequence: 9 }), event('b', { sequence: 3 })])

  const first = await cliReport(
    { [TRAIL_NAME]: repeated, [CHECKPOINT_NAME]: checkpointAtEnd(repeated) },
    WITH_CHECKPOINT,
  )
  assert.equal(first.code, 1)
  assert.equal(raised(first.report, 'sequence-duplicate'), true)

  const second = await cliReport(
    { [TRAIL_NAME]: backwards, [CHECKPOINT_NAME]: checkpointAtEnd(backwards) },
    WITH_CHECKPOINT,
  )
  assert.equal(second.code, 1)
  assert.equal(raised(second.report, 'sequence-out-of-order'), true)
})

test('a record the canonical form cannot serialise is unknown, never a match', () => {
  // No JSON file can hold one of these, which is exactly why this case is
  // driven through the real pass directly rather than through a fixture: the
  // branch that refuses to hash an undefined value has to be shown to refuse.
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

  const result = verifyChain(rows, TRAIL_NAME, compiled, DEFAULT_LIMITS, NEVER, null)

  assert.equal(rows.rows.length, 1)
  assert.equal(rows.rows[0].ruleId, 'record-not-canonical')
  assert.equal(createFinding(rows.rows[0]).severity, 'error')
  assert.equal(result.hashesVerified, 0)
  assert.equal(result.unhashable, 1)
  assert.equal(result.chainVerified, false)
})

test('a pass that stopped early is never reported as verified', () => {
  const document = cleanTrail()
  const { rows, compiled } = compile(document)
  // Out of budget from the second reading: the loop breaks on the first record.
  const result = verifyChain(rows, TRAIL_NAME, compiled, DEFAULT_LIMITS, { exceeded: () => true }, null)

  assert.equal(result.processed, 0)
  assert.equal(result.completed, false)
  assert.equal(result.stoppedEarly, true)
  assert.equal(result.chainVerified, false)
})

/**
 * The failure this catalog has already shipped once: a budget exhausted inside
 * a loop, a `break`, and a success branch below it that nobody re-checked.
 *
 * Here the budget is exhausted on the *last* iteration, so the loop ends on its
 * own condition and the break never runs. The verdict must still be withheld,
 * which only the re-check after the loop can do.
 */
test('a budget exhausted on the final iteration still withholds the verdict', () => {
  const document = cleanTrail()
  const { rows, compiled } = compile(document)
  let readings = 0
  const budget = { exceeded: () => { readings += 1; return readings > document.records.length } }

  const result = verifyChain(rows, TRAIL_NAME, compiled, DEFAULT_LIMITS, budget, null)

  assert.equal(result.processed, document.records.length)
  assert.equal(result.hashesVerified, document.records.length)
  assert.equal(result.stoppedEarly, true)
  assert.equal(result.chainVerified, false)
})

test('the sequence pass is bounded by the same budget and says when it stopped', () => {
  const document = cleanTrail()
  const { rows, compiled } = compile(document)

  const result = checkSequence(rows, TRAIL_NAME, compiled, { exceeded: () => true }, null)

  assert.equal(result.processed, 0)
  assert.equal(result.continuous, false)
  assert.equal(result.stoppedEarly, true)
})

test('a time budget that runs out mid-run is an incomplete report, never a pass', async () => {
  const report = await (await import('./support.mjs')).apiReport(
    { [TRAIL_NAME]: cleanTrail(), [CHECKPOINT_NAME]: checkpointAtEnd(cleanTrail()) },
    { checkpoint: CHECKPOINT_NAME, clock: budgetClock(2) },
  )

  assert.equal(report.status, 'incomplete')
  assert.equal(raised(report, 'time-budget-exceeded'), true)
  assert.equal(report.summary.chainVerified, false)
})
