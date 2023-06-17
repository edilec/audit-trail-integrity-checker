/**
 * Decoding, sanitising, ordering and the identifier shapes.
 *
 * Nothing here touches the filesystem, the network, a locale or a clock. Every
 * value it handles arrived in a file this tool did not write, so every value it
 * returns is data on its way into a report -- never something allowed to shape
 * a line of output.
 */

/**
 * Order by UTF-16 code unit.
 *
 * Locale-aware comparison -- the string method and the collator class alike --
 * reads ICU data that differs between Node builds and between hosts, and it
 * weighs punctuation differently from its code point: under English collation
 * `requestId` sorts after `request_id` while by code unit it sorts before.
 * That is not a cosmetic difference here. Object keys are sorted by this
 * function inside the canonical form a record hash is computed over, so a
 * collated sort would compute a different hash for the same record on a
 * different machine and report a tamper finding that is purely an artefact of
 * ICU data.
 *
 * Neither spelling of the locale-aware comparison appears anywhere in this
 * package, and `test/ordering.test.mjs` pins what the tool *emits* rather than
 * what its source says: a scan of the source cannot tell one comparator from
 * the other, so a scan is not the test.
 */
export function byCodeUnit(left, right) {
  if (left === right) return 0
  return left < right ? -1 : 1
}

/**
 * The characters no untrusted value may carry into output, in four classes.
 *
 * Built from code points rather than written literally: a literal U+2028 or
 * U+2029 inside a module is a line terminator to the JavaScript parser, and the
 * rest are invisible in an editor. Spelling each one out keeps this file plain
 * ASCII and keeps the list reviewable.
 *
 * - **C0** (U+0000-U+001F) and **DEL** (U+007F). A newline forges a line in the
 *   human report, ESC opens a terminal escape sequence, NUL truncates a value
 *   in anything that receives it through C.
 * - **C1** (U+0080-U+009F). Easy to forget once C0 is handled, and two of them
 *   need no help: U+0085 NEL is a line break to a great many consumers, and
 *   U+009B is the 8-bit CSI, a terminal control introducer that needs no ESC in
 *   front of it.
 * - **Line and paragraph separators** (U+2028, U+2029).
 * - **Bidi and isolate controls** (U+200E, U+200F, U+202A-U+202E,
 *   U+2066-U+2069). U+202E RIGHT-TO-LEFT OVERRIDE reverses everything printed
 *   after it, so a record id that reads `evt-0007` in a terminal can be a
 *   different string entirely from the one the chain was verified over.
 *   Ordinary right-to-left text -- Arabic, Hebrew -- needs none of these: the
 *   letters carry their own direction, so refusing the overrides refuses
 *   nothing legitimate.
 */
const DEL_AND_C1 = `${String.fromCharCode(0x7f)}-${String.fromCharCode(0x9f)}`
const SEPARATORS = `${String.fromCharCode(0x2028)}${String.fromCharCode(0x2029)}`
const BIDI =
  `${String.fromCharCode(0x200e)}${String.fromCharCode(0x200f)}` +
  `${String.fromCharCode(0x202a)}-${String.fromCharCode(0x202e)}` +
  `${String.fromCharCode(0x2066)}-${String.fromCharCode(0x2069)}`

/**
 * Stripped from every untrusted string on its way into output -- record ids,
 * key names, file names, pointers, messages, suggestions and evidence alike,
 * not only an excerpt field. Tab, newline and carriage return are left out of
 * this class deliberately: `excerpt` collapses them into a single space in the
 * very next step, which is the same result by a shorter route.
 */
const CONTROL = new RegExp(
  `[${String.fromCharCode(0)}-${String.fromCharCode(8)}` +
  `${String.fromCharCode(11)}${String.fromCharCode(12)}` +
  `${String.fromCharCode(14)}-${String.fromCharCode(31)}` +
  `${DEL_AND_C1}${SEPARATORS}${BIDI}]`,
  'g',
)

/**
 * What an identifier may not contain: the same four classes, plus the three
 * ASCII whitespace controls `CONTROL` leaves to the collapse. An identifier
 * gets no second pass; a record id that prints differently from the value the
 * chain was verified over is a record nobody can audit, so it is refused at the
 * door rather than repaired.
 */
const FORBIDDEN_IN_IDENTIFIER = new RegExp(
  `[${String.fromCharCode(0)}-${String.fromCharCode(31)}` +
  `${DEL_AND_C1}${SEPARATORS}${BIDI}]`,
)

/**
 * Detects any of the four classes anywhere in a string. Exported so a test can
 * walk an entire serialized report and assert that nothing survived anywhere,
 * rather than checking the one field somebody remembered to sanitise.
 */
export function hasForbiddenCharacter(value) {
  return FORBIDDEN_IN_IDENTIFIER.test(String(value))
}

export const EXCERPT_LIMIT = 160
export const MAX_IDENTIFIER_LENGTH = 200

/**
 * A bounded, single-line, control-free rendering of an untrusted string.
 *
 * Every id, file name, pointer, message and piece of evidence that reaches a
 * finding goes through here. A tool in this catalog sanitised its evidence
 * carefully and left its identifiers raw, so a record id holding a newline
 * printed two lines into the human report and invented a finding that was never
 * emitted.
 */
export function excerpt(value, limit = EXCERPT_LIMIT) {
  const flattened = String(value).replace(CONTROL, ' ').replace(/\s+/g, ' ').trim()
  if (flattened.length <= limit) return flattened
  return `${flattened.slice(0, limit)}...`
}

/**
 * The identifier alphabet: record ids, trail ids, actors, actions and targets.
 *
 * Wide enough for the spellings real audit systems use -- `evt-0001`,
 * `svc-billing`, `invoice.issued`, `urn:acme:tenant/42`, `arn:aws:iam::1:role/x`
 * -- which means upper case, `-` and `_` all occur, which in turn is why every
 * order in this package is decided by code unit.
 */
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/

export function isIdentifier(value) {
  if (typeof value !== 'string') return false
  if (value.length === 0 || value.length > MAX_IDENTIFIER_LENGTH) return false
  if (FORBIDDEN_IN_IDENTIFIER.test(value)) return false
  return IDENTIFIER.test(value)
}

/** A SHA-256 digest as this tool writes and reads it: 64 lower-case hex digits. */
export const HASH_PATTERN = /^[0-9a-f]{64}$/

export function isHash(value) {
  return typeof value === 'string' && HASH_PATTERN.test(value)
}

/**
 * The timestamp dialect: RFC 3339 in UTC, `Z`, with optional millisecond
 * precision.
 *
 * Validated and compared as text on purpose. Turning a timestamp into a `Date`
 * would drag a calendar implementation into a determinism-critical path for no
 * gain, and this package reads no clock at all -- there is no `Date.now`, no
 * `new Date` and no locale anywhere in it. Fractional seconds are normalised to
 * three digits for comparison only; the hash always covers the literal text the
 * record carried, never a normalised rewrite of it.
 *
 * The range checks below are shape checks. A day that does not exist in its
 * month -- 2026-02-31 -- passes them, and `docs/integrity-rules.md` says so:
 * this tool checks that a timestamp is well formed and monotonic, not that it
 * is a real instant.
 */
const TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/

export function parseTimestamp(value) {
  if (typeof value !== 'string' || value.length > 32) return null
  const match = TIMESTAMP.exec(value)
  if (match === null) return null
  const [, year, month, day, hour, minute, second, fraction] = match
  if (Number(month) < 1 || Number(month) > 12) return null
  if (Number(day) < 1 || Number(day) > 31) return null
  if (Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59) return null
  const milliseconds = (fraction ?? '').padEnd(3, '0')
  return { sortKey: `${year}-${month}-${day}T${hour}:${minute}:${second}.${milliseconds}Z` }
}

/**
 * Say what a refused value was, without reproducing any of it.
 *
 * A rejected field is arbitrary content from an audit record, which is exactly
 * the kind of document that carries names, addresses and identifiers of real
 * people. The report goes to stdout -- a stream that is piped, logged and
 * pasted somewhere more public than the trail ever was. The pointer on the
 * finding names the exact position in the file, which is all a reader needs;
 * the value stays in the file, where it started.
 */
export function describeValue(value) {
  if (value === undefined) return 'nothing'
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') return Number.isInteger(value) ? 'an integer' : 'a number'
  if (typeof value === 'string') return `a string of ${value.length} character(s)`
  if (Array.isArray(value)) return `an array of ${value.length} item(s)`
  if (typeof value === 'object') return 'an object'
  return `a ${typeof value}`
}

/**
 * Decode bytes as UTF-8, strictly.
 *
 * `fatal: true` is the whole point. Decoding leniently and then hunting for
 * U+FFFD cannot tell undecodable bytes from a file that legitimately contains a
 * replacement character, and that confusion has already let an unread input
 * report a pass in this catalog. The decoder decides; the decoded text never
 * gets a vote. Every file this tool opens goes through here, the checkpoint
 * included, because a checkpoint read as configuration rather than as evidence
 * is exactly where a sibling tool forgot.
 */
export function decodeUtf8(bytes) {
  try {
    return { ok: true, text: new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes) }
  } catch {
    return { ok: false, reason: 'not-utf8' }
  }
}

/** True for a plain object -- not an array, not null, not a class instance dressed up as one. */
export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}
