/**
 * The canonical form a record hash is computed over, and the hash itself.
 *
 * A hash chain is only as portable as the byte string each side hashes. Two
 * implementations that agree on SHA-256 and disagree on whether `{"b":1,"a":2}`
 * serialises with `a` first will produce different digests for identical
 * records, and the disagreement shows up as a tamper finding -- the worst
 * possible way to learn about a serialisation difference. So the byte string is
 * defined here, exactly, and `docs/integrity-rules.md` states the same
 * definition in prose for whoever writes the producer.
 *
 * The definition:
 *
 * - `null`, `true` and `false` serialise as those three words.
 * - A number serialises as `JSON.stringify` writes it, which ECMA-262 pins
 *   exactly. Only finite numbers are accepted.
 * - A string serialises as `JSON.stringify` writes it, which ECMA-262 also
 *   pins exactly, including the escaping of control characters and of lone
 *   surrogates.
 * - An array serialises as `[` + each element + `]`, joined by `,`, in the
 *   order given. Array order is content: reordering an array changes the hash.
 * - An object serialises as `{` + each `"key":value` + `}`, joined by `,`,
 *   with keys ordered by UTF-16 code unit -- never by locale collation, which
 *   differs between hosts and would make the digest host-dependent.
 * - No whitespace anywhere.
 *
 * The value hashed is the record with its own `hash` member removed and
 * nothing else changed. Everything else the record carries is covered: its id,
 * its sequence number, its timestamp, its actor, its action, its details, and
 * the `previousHash` that makes the chain a chain.
 */

import { createHash } from 'node:crypto'

import { byCodeUnit, isPlainObject } from './text.mjs'

/** The member a record's own digest is stored in, and the one member it cannot cover. */
export const HASH_KEY = 'hash'

export const HASH_ALGORITHM = 'sha256'

/**
 * Serialise a parsed JSON value into the canonical byte string, or refuse it.
 *
 * Refusal has three shapes and each one is reported by the caller rather than
 * worked around: a value this form does not define (`unsupported`), a structure
 * deeper than the declared limit (`depth`), and a structure with more nodes
 * than the declared limit (`nodes`). A refused record is never hashed and never
 * counted as verified, because "I could not compute the digest" and "the digest
 * matched" are not the same sentence.
 */
export function canonicalize(value, limits) {
  const maxDepth = limits.maxDetailDepth
  const maxNodes = limits.maxDetailNodes
  let nodes = 0

  function walk(node, depth, path) {
    nodes += 1
    if (nodes > maxNodes) return { ok: false, reason: 'nodes', path }
    if (depth > maxDepth) return { ok: false, reason: 'depth', path }

    if (node === null) return { ok: true, text: 'null' }
    const type = typeof node
    if (type === 'boolean') return { ok: true, text: node ? 'true' : 'false' }
    if (type === 'number') {
      if (!Number.isFinite(node)) return { ok: false, reason: 'unsupported', path }
      return { ok: true, text: JSON.stringify(node) }
    }
    if (type === 'string') return { ok: true, text: JSON.stringify(node) }

    if (Array.isArray(node)) {
      const parts = []
      for (let index = 0; index < node.length; index += 1) {
        const item = walk(node[index], depth + 1, `${path}/${index}`)
        if (!item.ok) return item
        parts.push(item.text)
      }
      return { ok: true, text: `[${parts.join(',')}]` }
    }

    if (isPlainObject(node)) {
      // The one ordering decision inside the digest. See byCodeUnit.
      const keys = Object.keys(node).sort(byCodeUnit)
      const parts = []
      for (const key of keys) {
        const item = walk(node[key], depth + 1, `${path}/${key}`)
        if (!item.ok) return item
        parts.push(`${JSON.stringify(key)}:${item.text}`)
      }
      return { ok: true, text: `{${parts.join(',')}}` }
    }

    return { ok: false, reason: 'unsupported', path }
  }

  return walk(value, 0, '')
}

/** SHA-256 of a UTF-8 string, as 64 lower-case hex digits. */
export function sha256Hex(text) {
  return createHash(HASH_ALGORITHM).update(Buffer.from(text, 'utf8')).digest('hex')
}

/**
 * The digest of one record: SHA-256 over the canonical form of the record with
 * its `hash` member removed.
 *
 * Returns the refusal from `canonicalize` unchanged when the record cannot be
 * serialised. The caller turns that into a finding; it never turns it into a
 * verified link.
 */
export function hashRecord(record, limits) {
  const covered = {}
  for (const key of Object.keys(record)) {
    if (key === HASH_KEY) continue
    covered[key] = record[key]
  }
  const canonical = canonicalize(covered, limits)
  if (!canonical.ok) return canonical
  return { ok: true, hash: sha256Hex(canonical.text), canonical: canonical.text }
}
