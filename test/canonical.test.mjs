import assert from 'node:assert/strict'
import test from 'node:test'

import { DEFAULT_LIMITS, canonicalize, hashRecord, refusalPointer, sha256Hex } from '../src/index.mjs'

/**
 * The canonical form, pinned by literal expected strings.
 *
 * Everything else in this package rests on this: two implementations that
 * disagree about the byte string produce different digests for the same record
 * and report each other as tampering. The fixtures the rest of the suite uses
 * are chained with this same function, so if it were only tested against itself
 * a change to it would regenerate every fixture and stay invisible. The
 * expectations here are written out by hand instead.
 */

const limits = DEFAULT_LIMITS

test('the digest is really SHA-256', () => {
  // The published SHA-256 of the empty string. If this line ever needs editing,
  // the algorithm changed, and every digest this tool ever wrote is stale.
  assert.equal(sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
})

test('object keys are ordered by code unit, not by collation', () => {
  const result = canonicalize({ 'X-Request-Id': 'r', actor_ip: 'i', amountMinor: 1 }, limits)

  assert.equal(result.ok, true)
  // Under English collation "actor_ip" sorts first. Under code-unit order the
  // upper-case X does. A digest that changed with the host's ICU data would be
  // useless, so this is the order.
  assert.equal(result.text, '{"X-Request-Id":"r","actor_ip":"i","amountMinor":1}')
})

test('nested objects are ordered at every level and arrays keep their order', () => {
  const result = canonicalize({ b: [1, { d: 2, c: 3 }], a: null }, limits)

  assert.equal(result.ok, true)
  assert.equal(result.text, '{"a":null,"b":[1,{"c":3,"d":2}]}')
})

test('scalars serialise exactly as the format declares', () => {
  assert.equal(canonicalize(null, limits).text, 'null')
  assert.equal(canonicalize(true, limits).text, 'true')
  assert.equal(canonicalize(false, limits).text, 'false')
  assert.equal(canonicalize(-12, limits).text, '-12')
  assert.equal(canonicalize(1.5, limits).text, '1.5')
  assert.equal(canonicalize('a"b', limits).text, '"a\\"b"')
  assert.equal(canonicalize([], limits).text, '[]')
  assert.equal(canonicalize({}, limits).text, '{}')
})

test('a record hashes over every member except its own hash', () => {
  const record = {
    action: 'invoice.issued',
    actor: 'svc-billing',
    id: 'evt-0001',
    previousHash: null,
    sequence: 1,
    timestamp: '2026-01-02T09:00:00.000Z',
    hash: '0'.repeat(64),
  }

  const digest = hashRecord(record, limits)

  assert.equal(digest.ok, true)
  assert.equal(
    digest.canonical,
    '{"action":"invoice.issued","actor":"svc-billing","id":"evt-0001","previousHash":null,"sequence":1,"timestamp":"2026-01-02T09:00:00.000Z"}',
  )
  assert.equal(digest.hash, 'd1a188c12de5489c86d29590c54f93edfdc886daf93a6d148224f4cf09b33dd3')
  assert.equal(digest.hash, sha256Hex(digest.canonical))
})

test('the stored hash does not change the digest, and every other member does', () => {
  const base = { id: 'evt-0001', previousHash: null, sequence: 1, hash: '0'.repeat(64) }
  const digest = hashRecord(base, limits).hash

  assert.equal(hashRecord({ ...base, hash: 'f'.repeat(64) }, limits).hash, digest)
  assert.notEqual(hashRecord({ ...base, sequence: 2 }, limits).hash, digest)
  assert.notEqual(hashRecord({ ...base, id: 'evt-0002' }, limits).hash, digest)
  assert.notEqual(hashRecord({ ...base, previousHash: 'a'.repeat(64) }, limits).hash, digest)
  assert.notEqual(hashRecord({ ...base, extra: 1 }, limits).hash, digest)
})

test('a structure deeper than the limit is refused rather than hashed in part', () => {
  const result = canonicalize({ a: { b: { c: 1 } } }, { ...limits, maxDetailDepth: 2 })

  assert.equal(result.ok, false)
  assert.equal(result.reason, 'depth')
  // The route is positions, never spellings: `a`, `b` and `c` are each the
  // first key of their object once keys are in canonical order.
  assert.deepEqual(result.path, [{ index: 0, key: 'a' }, { index: 0, key: 'b' }, { index: 0, key: 'c' }])
  assert.equal(refusalPointer(result.path), '/#0/#0/#0')
})

test('a structure with more values than the limit is refused rather than hashed in part', () => {
  const result = canonicalize({ a: 1, b: 2, c: 3 }, { ...limits, maxDetailNodes: 3 })

  assert.equal(result.ok, false)
  assert.equal(result.reason, 'nodes')
})

test('a value the form does not define is refused, never hashed as something else', () => {
  // Nothing parsed from JSON can be one of these. They are refused anyway: a
  // digest computed over a value the format does not define is a digest nobody
  // else can reproduce.
  assert.deepEqual(canonicalize(undefined, limits), { ok: false, reason: 'unsupported', path: [] })
  assert.equal(canonicalize(Number.NaN, limits).ok, false)
  assert.equal(canonicalize(Number.POSITIVE_INFINITY, limits).ok, false)
  assert.equal(canonicalize(new Map([['a', 1]]), limits).ok, false)
  assert.equal(canonicalize(() => 1, limits).ok, false)
  assert.equal(hashRecord({ id: 'x', extra: new Map() }, limits).ok, false)
})
