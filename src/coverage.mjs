/**
 * Tail coverage: the one thing a hash chain cannot do, and the checkpoint that
 * partly repairs it.
 *
 * Remove the last n records from a hash-chained trail and the remaining file
 * verifies perfectly. Every digest still matches its record, every link still
 * matches its predecessor, and the sequence still runs consecutively from the
 * first record to the new last one. There is nothing inside the file to compare
 * the end of the file against, so no amount of checking inside it can notice
 * that the end is missing. This is a property of hash chains, not a gap in this
 * implementation, and it is the single most important sentence this tool says.
 *
 * A trusted checkpoint is a statement made elsewhere -- written to storage the
 * trail's writer cannot reach, printed, countersigned, whatever the operator
 * arranged -- that says "at sequence N the record was id X with digest H". With
 * one, a trail that stops before N is caught: the records that should be there
 * are not. Coverage then reaches exactly as far as N and no further, so records
 * after N are in the same position the whole trail was in before.
 *
 * This module therefore produces three kinds of statement and never confuses
 * them:
 *
 * - **covered**: a checkpoint matched, and it names the last record in the file.
 * - **partly covered**: a checkpoint matched an earlier record; the run is
 *   incomplete, because deletion after that point remains undetectable.
 * - **uncovered**: no checkpoint was supplied; deletion of the tail is
 *   undetectable, the run is incomplete, and this is emphatically not a pass.
 *
 * What this module never does is verify that a checkpoint is authentic. It has
 * no key material and does no cryptographic verification of provenance: the
 * checkpoint's authority comes from where the operator kept it. A checkpoint
 * carrying a `signature` is reported as an unsupported construct rather than
 * treated as verified, because reporting a control as checked on evidence
 * nobody obtained is the worst thing a tool like this can do.
 */

import { byCodeUnit, describeValue, excerpt, isHash, isIdentifier, isPlainObject, parseTimestamp } from './text.mjs'

export const CHECKPOINT_SCHEMA_VERSION = '1'

export const CHECKPOINT_KEYS = Object.freeze([
  'issuedAt', 'recordHash', 'recordId', 'schemaVersion', 'sequence', 'signature', 'trail',
])

const DIGEST_EVIDENCE = 16
const digestExcerpt = (hash) => `${hash.slice(0, DIGEST_EVIDENCE)}...`

/**
 * Compile the checkpoint document.
 *
 * Returns `null` when it cannot be used. A checkpoint that is not usable is
 * missing evidence about the tail -- never a reason to treat the tail as
 * covered, and never a reason to fall back silently to no checkpoint at all.
 */
export function compileCheckpoint(sink, file, value) {
  if (!isPlainObject(value)) {
    sink.add({
      file,
      pointer: '',
      ruleId: 'checkpoint-invalid',
      message: `${file} must hold a JSON object naming the trail, a sequence number, a record id and that record's digest; it holds ${describeValue(value)}.`,
    })
    return null
  }

  const stray = Object.keys(value).filter((key) => !CHECKPOINT_KEYS.includes(key)).sort(byCodeUnit)
  if (stray.length > 0) {
    sink.add({
      file,
      pointer: '',
      ruleId: 'checkpoint-invalid',
      message: `${file} declares unknown key(s) ${stray.map((key) => `"${excerpt(key, 60)}"`).join(', ')}; known keys are ${CHECKPOINT_KEYS.join(', ')}. An unknown key is refused rather than ignored, so a typo cannot turn a checkpoint into a weaker one.`,
    })
    return null
  }

  if (value.schemaVersion !== CHECKPOINT_SCHEMA_VERSION) {
    sink.add({
      file,
      pointer: '/schemaVersion',
      ruleId: 'schema-version-unsupported',
      message: `${file} declares schemaVersion ${describeValue(value.schemaVersion)}; this build implements version "${CHECKPOINT_SCHEMA_VERSION}" only, and it does not guess at another one.`,
      suggestion: `Re-issue the checkpoint as schemaVersion "${CHECKPOINT_SCHEMA_VERSION}".`,
    })
    return null
  }

  if (!isIdentifier(value.trail)) {
    sink.add({
      file,
      pointer: '/trail',
      ruleId: 'checkpoint-invalid',
      message: `"trail" must name the trail this checkpoint was taken from; it is ${describeValue(value.trail)}. A checkpoint that does not say which trail it covers covers nothing.`,
    })
    return null
  }

  if (!Number.isSafeInteger(value.sequence) || value.sequence < 0) {
    sink.add({
      file,
      pointer: '/sequence',
      ruleId: 'checkpoint-invalid',
      message: `"sequence" must be an integer between 0 and ${Number.MAX_SAFE_INTEGER}; it is ${describeValue(value.sequence)}.`,
    })
    return null
  }

  if (!isIdentifier(value.recordId)) {
    sink.add({
      file,
      pointer: '/recordId',
      ruleId: 'checkpoint-invalid',
      message: `"recordId" must name the record at that sequence; it is ${describeValue(value.recordId)}.`,
    })
    return null
  }

  if (!isHash(value.recordHash)) {
    sink.add({
      file,
      pointer: '/recordHash',
      ruleId: 'checkpoint-invalid',
      message: `"recordHash" must be 64 lower-case hex digits; it is ${describeValue(value.recordHash)}. Without it the checkpoint fixes a position but not a content.`,
    })
    return null
  }

  if (value.issuedAt !== undefined && parseTimestamp(value.issuedAt) === null) {
    sink.add({
      file,
      pointer: '/issuedAt',
      ruleId: 'checkpoint-invalid',
      message: `"issuedAt" is optional, and when present must be RFC 3339 UTC such as 2026-01-02T03:04:05.678Z; it is ${describeValue(value.issuedAt)}. It is recorded for the reader and takes no part in any check -- this tool reads no clock.`,
    })
    return null
  }

  const signaturePresent = value.signature !== undefined
  if (signaturePresent) {
    sink.add({
      file,
      pointer: '/signature',
      ruleId: 'checkpoint-signature-unsupported',
      message: 'This checkpoint carries a signature. This build verifies no signature and holds no key material, so the signature was not checked and this run must not be read as having established the checkpoint is authentic.',
      suggestion: 'Verify the signature with the tool that issued it, then re-run this check against the verified copy.',
    })
  }

  return {
    trail: value.trail,
    sequence: value.sequence,
    recordId: value.recordId,
    recordHash: value.recordHash,
    signaturePresent,
  }
}

/**
 * Decide how far the tail is covered, and say so without overstating it.
 *
 * `digestVerified` is the per-record result from the chain pass. A checkpoint
 * that matches the digest stored in the file, on a record whose digest was
 * never recomputed, establishes that the file agrees with the checkpoint and
 * not that the record is intact -- so the coverage claim is withheld in that
 * case rather than granted.
 */
export function evaluateCoverage(sink, files, compiled, checkpoint, digestVerified, requested) {
  const { records } = compiled
  const coverage = {
    checkpointApplied: false,
    coveredThroughSequence: null,
    uncoveredTailRecords: records.length,
    tailDeletionDetectable: false,
  }

  if (checkpoint === null) {
    if (requested) return { coverage, incomplete: true }
    sink.add({
      file: files.trail,
      pointer: '/records',
      ruleId: 'tail-deletion-undetectable',
      message: 'No checkpoint was supplied, so nothing here can detect records removed from the end of this trail: deleting the last n records leaves a file whose digests, links and sequence all still verify. This run therefore did not check that the trail is complete, and it is not a pass.',
      suggestion: 'Supply --checkpoint with a record id, sequence and digest recorded somewhere the trail writer cannot reach.',
    })
    return { coverage, incomplete: true }
  }

  if (checkpoint.trail !== compiled.trail) {
    sink.add({
      file: files.checkpoint,
      pointer: '/trail',
      ruleId: 'checkpoint-trail-mismatch',
      message: `The checkpoint covers trail "${excerpt(checkpoint.trail, 80)}" and the file holds trail "${excerpt(compiled.trail, 80)}". A checkpoint from another trail was not applied to this one, so the tail of this trail is unchecked.`,
    })
    return { coverage, incomplete: true }
  }

  let minSequence = Number.MAX_SAFE_INTEGER
  let maxSequence = -1
  let match = null
  let matchIndex = -1
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index]
    if (record.sequence < minSequence) minSequence = record.sequence
    if (record.sequence > maxSequence) maxSequence = record.sequence
    if (match === null && record.sequence === checkpoint.sequence) {
      match = record
      matchIndex = index
    }
  }

  if (match === null) {
    if (checkpoint.sequence > maxSequence) {
      // The detection the checkpoint exists for: the trail stops short of a
      // record that was recorded as being in it.
      sink.add({
        file: files.trail,
        pointer: '/records',
        ruleId: 'tail-truncated-below-checkpoint',
        message: `The checkpoint records sequence ${checkpoint.sequence} as part of this trail and the file ends at sequence ${maxSequence}, so ${checkpoint.sequence - maxSequence} record(s) that existed when the checkpoint was taken are not in this file.`,
        suggestion: 'Recover the missing tail from the writer, or treat the file as truncated.',
      })
      coverage.tailDeletionDetectable = true
      return { coverage, incomplete: false }
    }
    if (checkpoint.sequence < minSequence) {
      sink.add({
        file: files.checkpoint,
        pointer: '/sequence',
        ruleId: 'checkpoint-outside-segment',
        message: `The checkpoint names sequence ${checkpoint.sequence} and this file starts at sequence ${minSequence}, so the checkpoint sits before the segment and says nothing about its tail.`,
        suggestion: 'Use a checkpoint taken at or after the end of this segment.',
      })
      return { coverage, incomplete: true }
    }
    sink.add({
      file: files.trail,
      pointer: '/records',
      ruleId: 'checkpoint-record-missing',
      message: `The checkpoint names sequence ${checkpoint.sequence}, which falls inside this file's range of ${minSequence} to ${maxSequence}, and no record carries that number. The record the checkpoint was taken over is not here.`,
    })
    return { coverage, incomplete: true }
  }

  coverage.checkpointApplied = true
  let matched = true

  if (match.id !== checkpoint.recordId) {
    matched = false
    sink.add({
      file: files.trail,
      pointer: `${match.pointer}/id`,
      ruleId: 'checkpoint-record-mismatch',
      message: `The checkpoint records sequence ${checkpoint.sequence} as record "${excerpt(checkpoint.recordId, 80)}" and this file carries "${excerpt(match.id, 80)}" there.`,
    })
  }

  if (match.hash !== checkpoint.recordHash) {
    matched = false
    sink.add({
      file: files.trail,
      pointer: `${match.pointer}/hash`,
      ruleId: 'checkpoint-hash-mismatch',
      message: `The record at sequence ${checkpoint.sequence} carries a different digest than the checkpoint recorded for it, so the record was rewritten after the checkpoint was taken.`,
      evidence: `checkpoint ${digestExcerpt(checkpoint.recordHash)} file ${digestExcerpt(match.hash)}`,
    })
  }

  if (!matched) return { coverage, incomplete: false }

  if (digestVerified[matchIndex] !== true) {
    // The checkpoint agrees with a digest this run did not recompute. That is
    // agreement between two files, not evidence the record is intact.
    sink.add({
      file: files.trail,
      pointer: `${match.pointer}/hash`,
      ruleId: 'checkpoint-record-unverified',
      message: `The checkpoint agrees with the digest stored at sequence ${checkpoint.sequence}, but this run did not recompute that digest from the record, so the agreement is between two stored values rather than evidence the record is intact.`,
    })
    return { coverage, incomplete: true }
  }

  coverage.coveredThroughSequence = checkpoint.sequence
  coverage.tailDeletionDetectable = true
  coverage.uncoveredTailRecords = records.length - (matchIndex + 1)

  if (coverage.uncoveredTailRecords > 0) {
    sink.add({
      file: files.trail,
      pointer: `/records/${matchIndex + 1}`,
      ruleId: 'tail-beyond-checkpoint',
      message: `${coverage.uncoveredTailRecords} record(s) follow the checkpointed record at sequence ${checkpoint.sequence}. Coverage reaches that record and stops: records after it could be removed and everything in this file would still verify.`,
      suggestion: 'Take a checkpoint at the end of the trail, or read this run as covering only up to the checkpointed sequence.',
    })
    return { coverage, incomplete: true }
  }

  return { coverage, incomplete: checkpoint.signaturePresent }
}
