/**
 * The two checks that are not the schema check: sequence continuity, and the
 * previous-record hash chain.
 *
 * They are kept apart because they answer different questions and one of them
 * cannot answer the other's. A chain verifies that each record is byte-for-byte
 * what it was when its successor was written; it says nothing about whether a
 * number was skipped when the trail was produced. A sequence check notices the
 * skip; it says nothing about whether the surviving records were edited. Both
 * of them together still say nothing about records removed from the *end* --
 * see `coverage.mjs`, which is where that limit lives.
 *
 * Every conclusion in this module is derived from counters that only advance
 * when evidence was actually obtained. A loop that stops early leaves
 * `processed` below the record count, and every verdict this module returns is
 * gated on `processed === records.length`. That is deliberate and it is the
 * single most important line of defence here: a tool in this catalog reported
 * "equivalence confirmed" for a group it never finished checking, because its
 * budget ran out mid-loop and the `break` fell through into the success branch.
 * The re-check happens *after* the loop, where a `break` cannot skip it.
 */

import { hashRecord } from './canonical.mjs'
import { excerpt } from './text.mjs'

/** How much of a digest is quoted as evidence. Digests are not secrets; the records they cover are. */
const DIGEST_EVIDENCE = 16

const digestExcerpt = (hash) => `${hash.slice(0, DIGEST_EVIDENCE)}...`

/**
 * Recompute every record's digest and check every link.
 *
 * @returns {object} counters and verdicts. `chainVerified` is true only when
 *   every declared record was compiled, every one of them was hashed, every
 *   digest matched and every link matched -- and the loop reached the end.
 */
export function verifyChain(sink, file, compiled, limits, budget, anchorHash) {
  const { records, declared } = compiled
  const digestOk = new Array(records.length).fill(false)

  let processed = 0
  let stoppedEarly = false
  let hashesVerified = 0
  let hashMismatches = 0
  let linksVerified = 0
  let linkFailures = 0
  let unhashable = 0
  let anchorState = 'genesis'

  for (let index = 0; index < records.length; index += 1) {
    if (budget.exceeded()) {
      stoppedEarly = true
      break
    }

    const record = records[index]
    const digest = hashRecord(record.raw, limits)

    if (!digest.ok) {
      unhashable += 1
      if (digest.reason === 'depth') {
        sink.add({
          file,
          pointer: `${record.pointer}${digest.path}`,
          ruleId: 'detail-depth-exceeded',
          message: `This record nests deeper than the maxDetailDepth limit of ${limits.maxDetailDepth}, so its canonical form was not built and its digest is unknown rather than wrong.`,
          suggestion: 'Raise --max-detail-depth, or flatten the record.',
        })
      } else if (digest.reason === 'nodes') {
        sink.add({
          file,
          pointer: `${record.pointer}${digest.path}`,
          ruleId: 'too-many-detail-nodes',
          message: `This record holds more values than the maxDetailNodes limit of ${limits.maxDetailNodes}, so its canonical form was not built and its digest is unknown rather than wrong.`,
          suggestion: 'Raise --max-detail-nodes, or trim the record.',
        })
      } else {
        sink.add({
          file,
          pointer: `${record.pointer}${digest.path}`,
          ruleId: 'record-not-canonical',
          message: 'This record holds a value the canonical form does not define, so its digest was not computed. An uncomputed digest is unknown; it is never treated as a match.',
        })
      }
    } else if (digest.hash !== record.hash) {
      hashMismatches += 1
      sink.add({
        file,
        pointer: `${record.pointer}/hash`,
        ruleId: 'record-hash-mismatch',
        message: `The digest of record "${excerpt(record.id, 80)}" recomputes to a different value than the one stored with it, so this record is not the record its own hash was written for.`,
        evidence: `recorded ${digestExcerpt(record.hash)} recomputed ${digestExcerpt(digest.hash)}`,
        suggestion: 'Compare this record against a copy held somewhere the editor of this file could not reach.',
      })
    } else {
      digestOk[index] = true
      hashesVerified += 1
    }

    if (index === 0) {
      if (record.previousHash !== null) {
        if (anchorHash === null) {
          anchorState = 'unverified'
          sink.add({
            file,
            pointer: `${record.pointer}/previousHash`,
            ruleId: 'segment-anchor-unverified',
            message: 'The first record links to a predecessor that is not in this file, so this is a segment rather than a whole trail. Nothing here establishes what that predecessor was, so records before this point are outside what this run checked.',
            evidence: `links to ${digestExcerpt(record.previousHash)}`,
            suggestion: 'Pass --anchor-hash with the digest of the record immediately before this segment, obtained from somewhere other than this file.',
          })
        } else if (record.previousHash !== anchorHash) {
          anchorState = 'mismatch'
          sink.add({
            file,
            pointer: `${record.pointer}/previousHash`,
            ruleId: 'anchor-mismatch',
            message: 'The first record links to a different predecessor than the one --anchor-hash names, so this segment does not follow the record it was said to follow.',
            evidence: `links to ${digestExcerpt(record.previousHash)} anchor ${digestExcerpt(anchorHash)}`,
          })
        } else {
          anchorState = 'verified'
        }
      } else if (anchorHash !== null) {
        anchorState = 'mismatch'
        sink.add({
          file,
          pointer: `${record.pointer}/previousHash`,
          ruleId: 'anchor-mismatch',
          message: 'The first record declares itself the start of the trail, but --anchor-hash names a predecessor it should follow. One of the two is describing a different trail.',
          evidence: `anchor ${digestExcerpt(anchorHash)}`,
        })
      }
      processed += 1
      continue
    }

    const previous = records[index - 1]

    if (record.previousHash === null) {
      linkFailures += 1
      sink.add({
        file,
        pointer: `${record.pointer}/previousHash`,
        ruleId: 'chain-link-missing',
        message: `Record "${excerpt(record.id, 80)}" declares itself the start of the trail, but ${previous.pointer} comes before it. A null link in the middle of a file breaks the chain into two pieces that nothing ties together.`,
      })
    } else if (record.previousHash !== previous.hash) {
      linkFailures += 1
      sink.add({
        file,
        pointer: `${record.pointer}/previousHash`,
        ruleId: 'chain-link-broken',
        message: `Record "${excerpt(record.id, 80)}" links to a predecessor whose digest is not the one ${previous.pointer} carries. Either a record between them was removed, or one of the two was rewritten.`,
        evidence: `links to ${digestExcerpt(record.previousHash)} predecessor ${digestExcerpt(previous.hash)}`,
        suggestion: 'Look for the record whose digest is the one this link names; it was in the trail when this record was written.',
      })
    } else if (digestOk[index] && digestOk[index - 1]) {
      // A link is only verified when both ends were verified. Matching a stored
      // digest that was never recomputed proves the file is self-consistent,
      // which is not the same as proving the record was not edited.
      linksVerified += 1
    }

    processed += 1
  }

  /**
   * The re-check that has to be after the loop.
   *
   * `break` leaves every counter above frozen at whatever it had reached, and
   * the verdicts below are computed from those counters rather than from the
   * absence of a finding. `budget.exceeded()` is asked again here because a
   * budget that was exhausted on the last iteration would otherwise never be
   * noticed: the loop condition ended the loop first.
   */
  const completed = processed === records.length && records.length === declared
  const timedOut = stoppedEarly || budget.exceeded()

  const chainVerified =
    completed &&
    !timedOut &&
    unhashable === 0 &&
    hashMismatches === 0 &&
    linkFailures === 0 &&
    hashesVerified === records.length &&
    linksVerified === Math.max(records.length - 1, 0) &&
    anchorState !== 'unverified' &&
    anchorState !== 'mismatch'

  return {
    processed,
    stoppedEarly: timedOut,
    completed,
    digestVerified: digestOk,
    hashesVerified,
    hashMismatches,
    linksVerified,
    linkFailures,
    unhashable,
    anchorState,
    chainVerified,
  }
}

/**
 * Check that sequence numbers run consecutively, and that timestamps do not go
 * backwards.
 *
 * Entirely independent of the chain. A trail whose producer skipped a number
 * has a chain that verifies and a sequence that does not, and a trail that was
 * renumbered after the fact has a sequence that looks perfect and a chain that
 * does not. Neither check is allowed to stand in for the other.
 */
export function checkSequence(sink, file, compiled, budget, firstSequence) {
  const { records, declared } = compiled

  let processed = 0
  let stoppedEarly = false
  let gaps = 0
  let breaks = 0
  let regressions = 0

  if (records.length > 0 && firstSequence !== null && records[0].sequence !== firstSequence) {
    breaks += 1
    sink.add({
      file,
      pointer: `${records[0].pointer}/sequence`,
      ruleId: 'sequence-start-mismatch',
      message: `The first record carries sequence ${records[0].sequence}, and --first-sequence declares this segment starts at ${firstSequence}. Records before this one are either missing from the file or were never in it.`,
    })
  }

  for (let index = 0; index < records.length; index += 1) {
    if (budget.exceeded()) {
      stoppedEarly = true
      break
    }
    processed += 1
    if (index === 0) continue

    const record = records[index]
    const previous = records[index - 1]
    const step = record.sequence - previous.sequence

    if (step === 0) {
      breaks += 1
      sink.add({
        file,
        pointer: `${record.pointer}/sequence`,
        ruleId: 'sequence-duplicate',
        message: `Sequence ${record.sequence} is carried by both ${previous.pointer} and this record, so the two disagree about which event that number names.`,
      })
    } else if (step < 0) {
      breaks += 1
      sink.add({
        file,
        pointer: `${record.pointer}/sequence`,
        ruleId: 'sequence-out-of-order',
        message: `Sequence ${record.sequence} follows ${previous.sequence} in the file, so the records are not in the order their numbers give them.`,
      })
    } else if (step > 1) {
      gaps += 1
      sink.add({
        file,
        pointer: `${record.pointer}/sequence`,
        ruleId: 'sequence-gap',
        message: `Sequence jumps from ${previous.sequence} to ${record.sequence}, leaving ${step - 1} number(s) unaccounted for. A hash chain cannot see this: if the missing numbers were never written, every link here still matches.`,
        suggestion: 'Find out whether those numbers were issued. A producer that skips numbers makes deletion and non-issuance indistinguishable.',
      })
    }

    if (record.timestampSortKey !== null && previous.timestampSortKey !== null && record.timestampSortKey < previous.timestampSortKey) {
      regressions += 1
      sink.add({
        file,
        pointer: `${record.pointer}/timestamp`,
        ruleId: 'timestamp-regression',
        message: 'This record is timestamped before the record ahead of it in the trail. That is not by itself a chain defect -- clocks move backwards -- but an audit trail that is read in timestamp order will read these two the wrong way round.',
      })
    }
  }

  const completed = processed === records.length && records.length === declared
  const timedOut = stoppedEarly || budget.exceeded()

  return {
    processed,
    stoppedEarly: timedOut,
    completed,
    gaps,
    breaks,
    regressions,
    continuous: completed && !timedOut && gaps === 0 && breaks === 0,
    firstSequence: records.length > 0 ? records[0].sequence : null,
    lastSequence: records.length > 0 ? records[records.length - 1].sequence : null,
  }
}
