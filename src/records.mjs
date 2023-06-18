/**
 * The trail document, compiled from parsed JSON into the record list the
 * sequence and chain checks work on.
 *
 * This module is the **schema** check, and it is deliberately a separate check
 * from the chain. A trail can have a chain that verifies perfectly and still be
 * missing a required field, carry a field this build does not understand, or
 * repeat a record id -- because the digest covers whatever the record happens
 * to contain, including a key nobody declared. A tool that folded the two
 * together would report a schema defect as a tamper signal, or worse, take a
 * verified digest as evidence that the record was well formed.
 *
 * Two grades of defect are distinguished, and the difference decides whether
 * the run can still be complete:
 *
 * - **Chain-critical**: `id`, `sequence`, `previousHash` and `hash`. Without
 *   all four in the right shape the record cannot take part in the chain at
 *   all, so it is excluded from it. Excluding a record means the run examined
 *   fewer records than the document declares, which is missing evidence.
 * - **Schema-only**: `timestamp`, `actor`, `action`, `target`, the shape of
 *   `details`, and any key outside the declared set. These are reported as
 *   errors and the record still takes part in the chain, because the digest
 *   over it is computable and checking it is real evidence. A defect in the
 *   record is not a reason to stop knowing whether the record was edited.
 */

import {
  byCodeUnit,
  describeValue,
  excerpt,
  isHash,
  isIdentifier,
  isPlainObject,
  parseTimestamp,
} from './text.mjs'

/** The only document version this build reads. Anything else is unsupported, not ignored. */
export const DOCUMENT_SCHEMA_VERSION = '1'

export const TRAIL_DOCUMENT_KEYS = Object.freeze(['records', 'schemaVersion', 'trail'])

/**
 * Every key a record may carry.
 *
 * The list is closed on purpose. An unknown key is refused rather than ignored
 * for two reasons: a typo in `previousHash` would otherwise silently remove a
 * record's link from the chain while the digest still verified, and a producer
 * that adds a `signature` or `attestation` member deserves to be told this
 * build does not check it rather than to have it quietly hashed and forgotten.
 */
export const RECORD_KEYS = Object.freeze([
  'action', 'actor', 'details', 'hash', 'id', 'previousHash', 'sequence', 'target', 'timestamp',
])

/** Chain-critical members, named here so the grading above is visible in one place. */
export const CHAIN_CRITICAL_KEYS = Object.freeze(['hash', 'id', 'previousHash', 'sequence'])

function unknownKeys(value, allowed) {
  return Object.keys(value).filter((key) => !allowed.includes(key)).sort(byCodeUnit)
}

/**
 * Compile one record.
 *
 * Returns the compiled record, or `null` when a chain-critical member is
 * unusable. Schema-only defects are added to the sink and the record is
 * returned anyway.
 */
function compileRecord(sink, file, index, raw) {
  const pointer = `/records/${index}`

  if (!isPlainObject(raw)) {
    sink.add({
      file,
      pointer,
      ruleId: 'record-invalid',
      message: `A record must be a JSON object; this is ${describeValue(raw)}. It was excluded from the chain rather than skipped over silently.`,
    })
    return null
  }

  if (!isIdentifier(raw.id)) {
    sink.add({
      file,
      pointer: `${pointer}/id`,
      ruleId: 'identifier-invalid',
      message: `This record has no usable id; it is ${describeValue(raw.id)}. A record that cannot be named cannot be reported on, so it was excluded from the chain.`,
      suggestion: 'An id is 1-200 characters from [A-Za-z0-9._:/@+-], starting with a letter or digit.',
    })
    return null
  }

  if (!Number.isSafeInteger(raw.sequence) || raw.sequence < 0) {
    sink.add({
      file,
      pointer: `${pointer}/sequence`,
      ruleId: 'record-invalid',
      message: `"sequence" must be an integer between 0 and ${Number.MAX_SAFE_INTEGER}; it is ${describeValue(raw.sequence)}. The record was excluded from the chain.`,
    })
    return null
  }

  if (!isHash(raw.hash)) {
    sink.add({
      file,
      pointer: `${pointer}/hash`,
      ruleId: 'hash-format-invalid',
      message: `"hash" must be 64 lower-case hex digits; it is ${describeValue(raw.hash)}. Nothing was compared against it, so this record's digest is unknown rather than wrong.`,
      suggestion: 'Re-export the trail with SHA-256 digests written as lower-case hex.',
    })
    return null
  }

  if (raw.previousHash !== null && !isHash(raw.previousHash)) {
    sink.add({
      file,
      pointer: `${pointer}/previousHash`,
      ruleId: 'hash-format-invalid',
      message: `"previousHash" must be 64 lower-case hex digits, or null on the first record of a trail; it is ${describeValue(raw.previousHash)}. The link into this record is unknown, not broken.`,
      suggestion: 'Re-export the trail with SHA-256 digests written as lower-case hex.',
    })
    return null
  }

  const stray = unknownKeys(raw, RECORD_KEYS)
  if (stray.length > 0) {
    sink.add({
      file,
      pointer,
      ruleId: 'record-invalid',
      message: `This record declares unknown key(s) ${stray.map((key) => `"${excerpt(key, 60)}"`).join(', ')}; known keys are ${RECORD_KEYS.join(', ')}. The digest covers them, so the chain still verifies, but this build does not know what they mean and will not imply that it checked them.`,
    })
  }

  const timestamp = parseTimestamp(raw.timestamp)
  if (timestamp === null) {
    sink.add({
      file,
      pointer: `${pointer}/timestamp`,
      ruleId: 'timestamp-invalid',
      message: `"timestamp" must be RFC 3339 UTC such as 2026-01-02T03:04:05.678Z; it is ${describeValue(raw.timestamp)}. This record takes no part in the ordering check.`,
      suggestion: 'Re-export timestamps in UTC with a trailing Z.',
    })
  }

  for (const key of ['action', 'actor']) {
    if (!isIdentifier(raw[key])) {
      sink.add({
        file,
        pointer: `${pointer}/${key}`,
        ruleId: 'record-invalid',
        message: `"${key}" must be an identifier of 1-200 characters from [A-Za-z0-9._:/@+-]; it is ${describeValue(raw[key])}.`,
      })
    }
  }

  if (raw.target !== undefined && !isIdentifier(raw.target)) {
    sink.add({
      file,
      pointer: `${pointer}/target`,
      ruleId: 'record-invalid',
      message: `"target" is optional, and when present must be an identifier of 1-200 characters from [A-Za-z0-9._:/@+-]; it is ${describeValue(raw.target)}.`,
    })
  }

  if (raw.details !== undefined && !isPlainObject(raw.details)) {
    sink.add({
      file,
      pointer: `${pointer}/details`,
      ruleId: 'record-invalid',
      message: `"details" is optional, and when present must be an object; it is ${describeValue(raw.details)}.`,
    })
  }

  return {
    index,
    pointer,
    id: raw.id,
    sequence: raw.sequence,
    timestampSortKey: timestamp === null ? null : timestamp.sortKey,
    previousHash: raw.previousHash,
    hash: raw.hash,
    raw,
  }
}

/**
 * Compile the trail document.
 *
 * Returns `null` when the document as a whole is unusable -- wrong shape, a
 * version this build does not implement, or more records than the limit allows.
 * A document that compiles may still have excluded records: `declared` and
 * `records.length` differ in that case, and the caller treats the gap as
 * missing evidence rather than as a clean result.
 */
export function compileTrail(sink, file, value, limits) {
  if (!isPlainObject(value)) {
    sink.add({
      file,
      pointer: '',
      ruleId: 'document-invalid',
      message: `${file} must hold a JSON object with "schemaVersion", "trail" and "records"; it holds ${describeValue(value)}.`,
    })
    return null
  }

  const stray = unknownKeys(value, TRAIL_DOCUMENT_KEYS)
  if (stray.length > 0) {
    sink.add({
      file,
      pointer: '',
      ruleId: 'document-invalid',
      message: `${file} declares unknown key(s) ${stray.map((key) => `"${excerpt(key, 60)}"`).join(', ')}; known keys are ${TRAIL_DOCUMENT_KEYS.join(', ')}. An unknown key is refused rather than ignored, so a typo cannot disable a check.`,
    })
    return null
  }

  if (value.schemaVersion !== DOCUMENT_SCHEMA_VERSION) {
    sink.add({
      file,
      pointer: '/schemaVersion',
      ruleId: 'schema-version-unsupported',
      message: `${file} declares schemaVersion ${describeValue(value.schemaVersion)}; this build implements version "${DOCUMENT_SCHEMA_VERSION}" only, and it does not guess at another one.`,
      suggestion: `Re-export the trail as schemaVersion "${DOCUMENT_SCHEMA_VERSION}".`,
    })
    return null
  }

  if (!isIdentifier(value.trail)) {
    sink.add({
      file,
      pointer: '/trail',
      ruleId: 'document-invalid',
      message: `"trail" must name the trail with an identifier of 1-200 characters from [A-Za-z0-9._:/@+-]; it is ${describeValue(value.trail)}. Without it a checkpoint cannot be matched to this trail.`,
    })
    return null
  }

  if (!Array.isArray(value.records)) {
    sink.add({
      file,
      pointer: '/records',
      ruleId: 'document-invalid',
      message: `"records" must be an array; it is ${describeValue(value.records)}.`,
    })
    return null
  }

  if (value.records.length > limits.maxRecords) {
    sink.add({
      file,
      pointer: '/records',
      ruleId: 'too-many-records',
      message: `${file} declares ${value.records.length} record(s), above the maxRecords limit of ${limits.maxRecords}; nothing was compiled from it rather than a prefix being read and reported as the whole trail.`,
      suggestion: 'Raise --max-records, or verify the trail in segments.',
    })
    return null
  }

  if (value.records.length === 0) {
    sink.add({
      file,
      pointer: '/records',
      ruleId: 'no-records',
      message: `${file} declares no records at all, so there is no evidence here to be green on.`,
      suggestion: 'Point --trail at the exported trail, or verify the segment that holds the records.',
    })
    return null
  }

  const records = []
  const firstById = new Map()

  for (let index = 0; index < value.records.length; index += 1) {
    const record = compileRecord(sink, file, index, value.records[index])
    if (record === null) continue

    const earlier = firstById.get(record.id)
    if (earlier === undefined) firstById.set(record.id, record)
    else {
      sink.add({
        file,
        pointer: `${record.pointer}/id`,
        ruleId: 'record-id-duplicate',
        message: `Record id "${excerpt(record.id, 120)}" appears at ${earlier.pointer} and again here; an audit record id names one event, so one of these two is not the event it claims to be.`,
        suggestion: 'Re-export the trail with a unique id per record.',
      })
    }

    records.push(record)
  }

  return { trail: value.trail, declared: value.records.length, records }
}
