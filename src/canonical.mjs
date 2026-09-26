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
 *
 * A refusal carries `path`: the route to the value that was refused, as one
 * segment per level. An array item contributes `{ index }` and an object member
 * contributes `{ index, key }`, where `index` is the member's position in
 * canonical (code-unit) key order. The raw key is carried but is *not* a
 * renderable thing: see `refusalPointer`, which is the only way this package
 * turns a path into output.
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
        const item = walk(node[index], depth + 1, [...path, { index }])
        if (!item.ok) return item
        parts.push(item.text)
      }
      return { ok: true, text: `[${parts.join(',')}]` }
    }

    if (isPlainObject(node)) {
      // The one ordering decision inside the digest. See byCodeUnit.
      const keys = Object.keys(node).sort(byCodeUnit)
      const parts = []
      for (let index = 0; index < keys.length; index += 1) {
        const key = keys[index]
        const item = walk(node[key], depth + 1, [...path, { index, key }])
        if (!item.ok) return item
        parts.push(`${JSON.stringify(key)}:${item.text}`)
      }
      return { ok: true, text: `{${parts.join(',')}}` }
    }

    return { ok: false, reason: 'unsupported', path }
  }

  return walk(value, 0, [])
}

/**
 * Render a refusal path as a pointer that carries no value from the document.
 *
 * A key name inside a record is content. `details` is where an audit record
 * keeps the card number, the address and the access token, and its *keys* are
 * written by the same producer as its values -- a payload keyed by account
 * number is an ordinary shape. Concatenating those keys into a finding put
 * them on stdout and stderr, past every redactor, which is exactly what this
 * package says it never does.
 *
 * So a key contributes its position in canonical order, never its spelling:
 * `#3` is the fourth key of that object once the keys are sorted by code unit,
 * which is the order this file already defines and `docs/integrity-rules.md`
 * already states, so a reader can find the value without being told its name.
 * An array index is structure rather than content and is kept as it is.
 *
 * `vocabulary` is the one exception and it is not an echo: a top-level segment
 * whose key is in the caller's own fixed, closed list is rendered as that
 * word. The list is the tool's, not the document's, so the output is drawn
 * from a set of nine words decided before the file was read. A top-level key
 * outside the list -- which is to say, any key the document invented -- falls
 * back to its position like every deeper one.
 */
export function refusalPointer(path, vocabulary = []) {
  let rendered = ''
  for (let depth = 0; depth < path.length; depth += 1) {
    const segment = path[depth]
    if (segment.key === undefined) {
      rendered += `/${segment.index}`
    } else if (depth === 0 && vocabulary.includes(segment.key)) {
      rendered += `/${segment.key}`
    } else {
      rendered += `/#${segment.index}`
    }
  }
  return rendered
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
