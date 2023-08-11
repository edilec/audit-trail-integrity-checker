import assert from 'node:assert/strict'
import test from 'node:test'

import { DEFAULT_LIMITS, RULE_SEVERITY, byCodeUnit } from '../src/index.mjs'
import { CHECKPOINT_NAME, TRAIL_NAME, apiReport, chain, checkpointAt, checkpointAtEnd, cleanTrail, event } from './support.mjs'

/**
 * The ordering call sites that cannot be pinned, proved equivalent instead of
 * left as gaps.
 *
 * `test/ordering.test.mjs` pins the sites whose values come from a file or a
 * caller, by emitting a sequence a collator would emit differently. The rest
 * order values drawn from alphabets on which code-unit order and English
 * collation agree on every pair: rule ids over `[a-z-]`, JSON Pointers over
 * `[A-Za-z0-9/]`, and this package's own limit names. Substituting a collator
 * at those sites is an *equivalent* mutation -- the output cannot change, so no
 * test can catch it -- and saying so with an enumeration is more honest than
 * either claiming coverage or leaving a gap.
 *
 * Two of the proofs below are conditional, so each one also checks the
 * condition it rests on against what the tool really emits: a new pointer shape
 * or a second finding under one record's `details` would fail this file rather
 * than quietly widening the alphabet the proof stands on.
 */

const collator = new Intl.Collator('en')

/**
 * Every ordered pair on which the two comparisons disagree, and nothing else.
 *
 * The earlier shape of this helper asserted inside the loop and returned the
 * number of pairs it had walked, which it incremented unconditionally -- so
 * `assert.equal(everyOrderedPairAgrees(values), values.length ** 2)` compared a
 * counter against the only value it could hold. It could not fail, and it read
 * exactly like the assertion that carries the proof.
 *
 * Returning the disagreements instead puts the claim in the caller, where a
 * disagreement is a value the assertion can show rather than a throw from
 * inside a helper.
 */
function orderedPairsThatDisagree(values) {
  const disagreements = []
  for (const left of values) {
    for (const right of values) {
      if (Math.sign(byCodeUnit(left, right)) !== Math.sign(collator.compare(left, right))) {
        disagreements.push(`"${left}" vs "${right}"`)
      }
    }
  }
  return disagreements
}

/**
 * The size of the enumeration, asserted against the literal `docs/integrity-
 * rules.md` publishes. A proof over 1681 pairs that quietly became a proof over
 * 1600 because a rule was dropped is a weaker proof than the document claims,
 * and this is the line that says so.
 */
function assertEnumerated(values, pairs, label) {
  assert.equal(new Set(values).size, values.length, `${label}: a duplicate would shrink the enumeration`)
  assert.equal(values.length ** 2, pairs, `${label}: the enumeration is no longer the ${pairs} pairs the docs claim`)
}

const cp = (document, overrides) => checkpointAtEnd(document, overrides)
const one = (overrides = {}) => chain('billing.eu-west-1', [event('evt-0001', overrides)])
const withCheckpoint = (document, checkpoint = cp(document), options = {}) =>
  apiReport({ [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint }, { checkpoint: CHECKPOINT_NAME, ...options })

/**
 * Inputs chosen to make the tool emit at least one finding of every pointer
 * shape this package can produce.
 */
const CORPUS = Object.freeze([
  () => apiReport({ [TRAIL_NAME]: { records: [] } }),
  () => apiReport({ [TRAIL_NAME]: { ...cleanTrail(), schemaVersion: '2' } }),
  () => apiReport({ [TRAIL_NAME]: { ...cleanTrail(), trail: 5 } }),
  () => apiReport({ [TRAIL_NAME]: { ...cleanTrail(), records: 5 } }),
  () => apiReport({ [TRAIL_NAME]: cleanTrail() }, { limits: { maxRecords: 1 } }),
  () => apiReport({ [TRAIL_NAME]: cleanTrail() }),
  () => withCheckpoint(one({ actor: 1, action: 2, target: 3, details: 4 })),
  () => withCheckpoint(one({ timestamp: 'x' })),
  () => withCheckpoint(one({ details: { a: { b: { c: 1 } } } }), undefined, { limits: { maxDetailDepth: 2 } }),
  () => withCheckpoint(one({ details: { a: 1, b: 2, c: 3 } }), undefined, { limits: { maxDetailNodes: 3 } }),
  () => withCheckpoint(chain('billing.eu-west-1', [event('a'), event('a')])),
  () => withCheckpoint(chain('billing.eu-west-1', [event('a'), event('b', { sequence: 9 })])),
  () => withCheckpoint(chain('billing.eu-west-1', [event('a'), event('b', { sequence: 1 })])),
  () => withCheckpoint(chain('billing.eu-west-1', [event('a', { sequence: 9 }), event('b', { sequence: 2 })])),
  () => withCheckpoint(cleanTrail(), undefined, { firstSequence: 7 }),
  () => withCheckpoint(cleanTrail(), undefined, { anchorHash: 'c'.repeat(64) }),
  () => withCheckpoint(chain('t', [event('a')], { previousHash: 'b'.repeat(64) })),
  () => {
    const document = cleanTrail()
    delete document.records[1].id
    document.records[2].sequence = 'x'
    document.records[3].hash = 'x'
    return withCheckpoint(document)
  },
  () => {
    const document = cleanTrail()
    document.records[1].previousHash = 'x'
    document.records[2].actor = 'rewritten'
    return withCheckpoint(document)
  },
  () => {
    const document = cleanTrail()
    document.records[2].previousHash = null
    return withCheckpoint(document)
  },
  () => {
    const document = cleanTrail()
    return withCheckpoint(document, checkpointAt(document, 1))
  },
  () => {
    const document = cleanTrail()
    const checkpoint = cp(document)
    document.records.length = 2
    return withCheckpoint(document, checkpoint)
  },
  () => withCheckpoint(cleanTrail(), cp(cleanTrail(), { trail: 'other.trail' })),
  () => withCheckpoint(cleanTrail(), { ...cp(cleanTrail()), recordId: 'evt-9999' }),
  () => withCheckpoint(cleanTrail(), { ...cp(cleanTrail()), recordHash: 'd'.repeat(64) }),
  () => withCheckpoint(cleanTrail(), { ...cp(cleanTrail()), recordId: 5 }),
  () => withCheckpoint(cleanTrail(), { ...cp(cleanTrail()), recordHash: 'AB' }),
  () => withCheckpoint(cleanTrail(), { ...cp(cleanTrail()), sequence: -1 }),
  () => withCheckpoint(cleanTrail(), { ...cp(cleanTrail()), signature: 'x' }),
  () => withCheckpoint(cleanTrail(), { ...cp(cleanTrail()), issuedAt: 'x' }),
  () => withCheckpoint(cleanTrail(), { ...cp(cleanTrail()), extra: 1 }),
  () => withCheckpoint(cleanTrail(), { ...cp(cleanTrail()), schemaVersion: '9' }),
  () => withCheckpoint(
    chain('t', [event('a', { sequence: 5 }), event('b')]),
    { schemaVersion: '1', trail: 't', sequence: 2, recordId: 'q', recordHash: 'e'.repeat(64) },
  ),
  () => withCheckpoint(
    chain('t', [event('a', { sequence: 5 }), event('b', { sequence: 9 })]),
    { schemaVersion: '1', trail: 't', sequence: 7, recordId: 'q', recordHash: 'e'.repeat(64) },
  ),
  () => apiReport({ [TRAIL_NAME]: 'x\n' }),
  () => apiReport({}),
  () => apiReport({ [TRAIL_NAME]: cleanTrail() }, { limits: { maxFileBytes: 10 } }),
])

const reports = async () => Promise.all(CORPUS.map((build) => build()))

test('every ordered pair of real rule ids collates exactly as it compares by code unit', () => {
  const ruleIds = Object.keys(RULE_SEVERITY)

  assert.equal(ruleIds.length > 30, true, 'the catalog must be the real one for this to prove anything')
  for (const ruleId of ruleIds) assert.match(ruleId, /^[a-z][a-z0-9-]*[a-z0-9]$/, 'the alphabet this proof rests on')
  assertEnumerated(ruleIds, 1681, 'rule id')
  assert.deepEqual(orderedPairsThatDisagree(ruleIds), [], 'these rule ids would move under collation')
})

test('every ordered pair of real limit names collates exactly as it compares by code unit', () => {
  const names = Object.keys(DEFAULT_LIMITS)

  assert.equal(names.length, 6)
  assertEnumerated(names, 36, 'limit name')
  assert.deepEqual(orderedPairsThatDisagree(names), [], 'these limit names would move under collation')
})

/**
 * The pointer vocabulary, written out as the shapes the tool can emit. Indices
 * are sampled across the digit-length boundaries where a numeric collator would
 * disagree even though a plain one does not -- 9 before 10, 99 before 100.
 */
const POINTER_SHAPES = Object.freeze({
  document: /^$/,
  'trail member': /^\/(records|schemaVersion|trail)$/,
  'checkpoint member': /^\/(issuedAt|recordHash|recordId|schemaVersion|sequence|signature|trail)$/,
  record: /^\/records\/\d+$/,
  'record member': /^\/records\/\d+\/(action|actor|details|hash|id|previousHash|sequence|target|timestamp)$/,
  'detail path': /^\/records\/\d+\/(#\d+|action|actor|details|id|previousHash|sequence|target|timestamp)(\/#?\d+)+$/,
})

const INDEX_SAMPLE = Object.freeze([0, 1, 2, 9, 10, 11, 99, 100, 101])

function structuralPointers() {
  const pointers = new Set([''])
  for (const member of ['records', 'schemaVersion', 'trail']) pointers.add(`/${member}`)
  for (const member of ['issuedAt', 'recordHash', 'recordId', 'schemaVersion', 'sequence', 'signature', 'trail']) {
    pointers.add(`/${member}`)
  }
  for (const index of INDEX_SAMPLE) {
    pointers.add(`/records/${index}`)
    for (const member of ['action', 'actor', 'details', 'hash', 'id', 'previousHash', 'sequence', 'target', 'timestamp']) {
      pointers.add(`/records/${index}/${member}`)
    }
  }
  return [...pointers]
}

test('the pointer vocabulary this proof enumerates still covers everything the tool emits', async () => {
  const emitted = new Set()
  for (const report of await reports()) {
    for (const finding of report.findings) emitted.add(finding.location.pointer)
  }

  assert.equal(emitted.size > 20, true, 'the corpus must produce a real spread of pointers')
  const covered = new Set()
  for (const pointer of emitted) {
    const shape = Object.entries(POINTER_SHAPES).find(([, pattern]) => pattern.test(pointer))
    assert.notEqual(shape, undefined, `pointer "${pointer}" matches no declared shape`)
    covered.add(shape[0])
  }
  assert.deepEqual(
    [...covered].sort(byCodeUnit),
    Object.keys(POINTER_SHAPES).sort(byCodeUnit),
    'every declared shape is really emitted, and no other shape is',
  )
})

test('every ordered pair of structural pointers collates exactly as it compares by code unit', () => {
  const pointers = structuralPointers()

  assert.equal(pointers.length > 90, true)
  assertEnumerated(pointers, 9801, 'pointer')
  assert.deepEqual(orderedPairsThatDisagree(pointers), [], 'these pointers would move under collation')
})

/**
 * The refusal path into a record once carried key names from the file, which
 * made it the one pointer shape a collator could be handed an arbitrary string
 * in. It no longer does -- a key contributes its position in canonical order,
 * never its spelling, see `refusalPointer` -- so every segment is now drawn
 * from the same digits and closed word list as every other shape above.
 *
 * The count is kept anyway, because it is the other half of the argument: the
 * canonical walk stops at the first value it refuses, so a record produces at
 * most one such finding, and where two exist they belong to different records
 * whose index decides the order long before any segment below is reached.
 */
test('at most one finding per record anchors inside details, so no segment decides an order', async () => {
  for (const report of await reports()) {
    const perRecord = new Map()
    for (const finding of report.findings) {
      const match = /^(\/records\/\d+)\/details\/.+$/.exec(finding.location.pointer)
      if (match === null) continue
      perRecord.set(match[1], (perRecord.get(match[1]) ?? 0) + 1)
    }
    for (const [record, count] of perRecord) assert.equal(count, 1, `${record} produced ${count} detail findings`)
  }
})

/**
 * The message is the last component of the documented sort key, and no two
 * findings ever reach it: the first three components are already unique. A
 * collator there cannot change an order that was decided before it was called.
 */
test('file, pointer and rule id are unique together, so the message never decides an order', async () => {
  for (const report of await reports()) {
    const keys = report.findings.map((finding) =>
      JSON.stringify([finding.location.file, finding.location.pointer, finding.ruleId]))
    assert.equal(new Set(keys).size, keys.length, 'two findings shared the first three components of the sort key')
  }
})
