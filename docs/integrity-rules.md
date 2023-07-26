# Integrity rules, input format and limits

This document is the reference for `audit-trail-integrity-checker`: the two input documents it
reads, the exact byte string a record digest is computed over, every rule it can raise, and the
things it deliberately does not conclude.

## The two documents

### The trail

```json
{
  "schemaVersion": "1",
  "trail": "billing.eu-west-1",
  "records": [
    {
      "id": "evt-2026-0001",
      "sequence": 1,
      "timestamp": "2026-01-02T09:00:00.000Z",
      "actor": "svc-audit",
      "action": "trail.opened",
      "target": "invoice:8841",
      "details": { "amountMinor": 429900, "currency": "EUR" },
      "previousHash": null,
      "hash": "9f2c..."
    }
  ]
}
```

| Member | Required | Shape |
| --- | --- | --- |
| `schemaVersion` | yes | exactly `"1"` |
| `trail` | yes | identifier: 1–200 characters from `[A-Za-z0-9._:/@+-]`, starting with a letter or digit |
| `records` | yes | array, ordered as the trail was written |
| `records[].id` | yes | identifier |
| `records[].sequence` | yes | integer, 0 to `Number.MAX_SAFE_INTEGER` |
| `records[].timestamp` | yes | RFC 3339 UTC, `YYYY-MM-DDTHH:MM:SS[.sss]Z` |
| `records[].actor` | yes | identifier |
| `records[].action` | yes | identifier |
| `records[].target` | no | identifier |
| `records[].details` | no | object; nesting and size are bounded by the limits below |
| `records[].previousHash` | yes | 64 lower-case hex digits, or `null` on the first record of a trail |
| `records[].hash` | yes | 64 lower-case hex digits |

No other key is accepted, in the document or in a record. An unknown key is reported rather than
ignored: a typo in `previousHash` would otherwise remove a record's link from the chain while its
own digest still verified.

### The checkpoint

```json
{
  "schemaVersion": "1",
  "trail": "billing.eu-west-1",
  "sequence": 6,
  "recordId": "evt-2026-0006",
  "recordHash": "4d1e...",
  "issuedAt": "2026-01-03T00:05:00.000Z"
}
```

`issuedAt` is optional, is recorded for the reader and takes part in no check — this tool reads no
clock. `signature` is a recognised key and is **not** verified; see the rule below. No other key is
accepted.

## The canonical form

A record's digest is `SHA-256` over the UTF-8 bytes of the canonical form of that record with its
own `hash` member removed. The canonical form is:

- `null`, `true`, `false` → those three words.
- A number → as `JSON.stringify` writes it, which ECMA-262 pins exactly. Only finite numbers are
  accepted. Note that `1.0` and `1` are the same parsed value and hash identically, and that a
  number outside the double-precision integer range is the value JSON parsing produced, not the
  text in the file.
- A string → as `JSON.stringify` writes it, including escaping of control characters and lone
  surrogates.
- An array → `[` + each element + `]`, joined by `,`, in the order given. Array order is content.
- An object → `{` + each `"key":value` + `}`, joined by `,`, with keys ordered **by UTF-16 code
  unit**, never by locale collation.
- No whitespace anywhere.

A producer that writes trails for this tool must implement exactly this. The digest covers the
record's `sequence`, its `timestamp`, its `previousHash` and every other member it carries,
including one this build does not recognise.

## Rules

Severity is taken from one frozen table in `src/index.mjs`; an unknown rule id throws rather than
defaulting to anything. `error` decides `fail`; `warning` never does. A rule marked "incomplete"
also withholds the pass, and a run that is incomplete exits 2 whatever its error count.

| Rule | Severity | Raised when |
| --- | --- | --- |
| `anchor-mismatch` | error | The first record links to a different predecessor than `--anchor-hash` names, or names one where the record declares itself the start of the trail. |
| `chain-link-broken` | error | A record's `previousHash` is not the digest the record before it carries. A record between them was removed, or one of the two was rewritten. |
| `chain-link-missing` | error | A record other than the first declares `previousHash: null`, breaking the file into two pieces nothing ties together. |
| `checkpoint-hash-mismatch` | error | The record at the checkpointed sequence carries a different digest than the checkpoint recorded. |
| `checkpoint-invalid` | error | The checkpoint is not an object, declares an unknown key, or one of its members has the wrong shape. |
| `checkpoint-outside-segment` | error | The checkpoint names a sequence before the start of this file, so it says nothing about this file's tail. |
| `checkpoint-record-mismatch` | error | The checkpoint names a different record id at the checkpointed sequence. |
| `checkpoint-record-missing` | error | The checkpointed sequence falls inside the range this file covers and no record carries it. |
| `checkpoint-record-unverified` | error | The checkpoint agrees with a digest this run never recomputed, so the agreement is between two stored values rather than evidence the record is intact. |
| `checkpoint-signature-unsupported` | error | The checkpoint carries a `signature`. This build verifies no signature and holds no key material; the run is incomplete rather than treated as having established the checkpoint is authentic. |
| `checkpoint-trail-mismatch` | error | The checkpoint covers a different trail than the file declares. |
| `detail-depth-exceeded` | error | A record nests deeper than `maxDetailDepth`, so its canonical form was not built and its digest is unknown. |
| `document-invalid` | error | The trail document is not an object, declares an unknown key, or `trail` / `records` has the wrong shape. |
| `hash-format-invalid` | error | `hash` or `previousHash` is not 64 lower-case hex digits. |
| `identifier-invalid` | error | A record has no usable `id`. |
| `input-not-json` | error | A file was read and is not valid JSON. The message carries the parser's offset, line and column, or the offending token alone, never the snippet of the file the parser quotes back: V8 reports `Unexpected token 'A', "..." is not valid JSON`, which reproduces a short file in full. The quoting shape is recognised before the offset is looked for, because a document whose own text reads `at position 1` puts the offset inside the quoted span; and any detail still carrying a double quote is discarded for a generic sentence. |
| `input-not-utf8` | error | A file's bytes are not valid UTF-8. Decided by a strict decoder, never inferred from decoded text. |
| `input-too-large` | error | A file is larger than `maxFileBytes`; it was not read. |
| `input-unreadable` | error | A file could not be resolved, inspected or read, or is not a regular file. |
| `no-records` | error | The trail document declares an empty `records` array; there is no evidence here to be green on. |
| `path-escapes-root` | error | A declared file resolves outside `--root` once both sides are resolved to real paths. |
| `record-hash-mismatch` | error | A record's digest recomputes to a different value than the one stored with it: the record is not the record its own hash was written for. |
| `record-id-duplicate` | error | Two records carry the same `id`. |
| `record-invalid` | error | A record is not an object, declares an unknown key, or a member other than `id`, `sequence`, `hash` or `previousHash` has the wrong shape. |
| `record-not-canonical` | error | A record holds a value the canonical form does not define. No JSON file can reach this rule; it exists so an unserialisable value can never be hashed as though it were understood. |
| `records-not-all-verified` | error | Fewer records had a digest recomputed and compared than the document declares. Whatever the reason, the rest were not checked at all. |
| `schema-version-unsupported` | error | A document declares a `schemaVersion` this build does not implement. |
| `segment-anchor-unverified` | warning | The first record links to a predecessor that is not in this file and no `--anchor-hash` was given. Records before this point are outside what the run checked. |
| `sequence-duplicate` | error | Two consecutive records carry the same sequence number. |
| `sequence-gap` | error | Sequence numbers jump. A hash chain cannot see this: if the missing numbers were never written, every link still matches. |
| `sequence-out-of-order` | error | A record's sequence number is below the one before it in the file. |
| `sequence-start-mismatch` | error | The first record's sequence is not the one `--first-sequence` declares. |
| `tail-beyond-checkpoint` | warning | Records follow the checkpointed record. Coverage reaches the checkpoint and stops; the records after it could be removed and everything in the file would still verify. |
| `tail-deletion-undetectable` | warning | No checkpoint was supplied. Deleting the last n records leaves a file whose digests, links and sequence all still verify, so this run did not check that the trail is complete. |
| `tail-truncated-below-checkpoint` | error | The checkpoint records a sequence beyond the end of the file: records that existed when it was taken are not here. |
| `time-budget-exceeded` | error | The run passed `maxRuntimeMs` and stopped. Every verdict is then a floor, not an answer. |
| `timestamp-invalid` | error | A `timestamp` is not RFC 3339 UTC. That record takes no part in the ordering check. |
| `timestamp-regression` | warning | A record is timestamped before the record ahead of it. Not a chain defect — clocks move backwards — but the trail does not read in timestamp order. |
| `too-many-detail-nodes` | error | A record holds more values than `maxDetailNodes`, so its canonical form was not built and its digest is unknown. |
| `too-many-findings` | error | The run produced more findings than `maxFindings`; the report is partial. |
| `too-many-records` | error | The trail declares more records than `maxRecords`; nothing was compiled from it rather than a prefix being read and reported as the whole. |

## Limits

| Limit | Flag | Default | Cap |
| --- | --- | ---: | ---: |
| `maxDetailDepth` | `--max-detail-depth` | 8 | 64 |
| `maxDetailNodes` | `--max-detail-nodes` | 500 | 20000 |
| `maxFileBytes` | `--max-file-bytes` | 16777216 | 268435456 |
| `maxFindings` | `--max-findings` | 1000 | 20000 |
| `maxRecords` | `--max-records` | 50000 | 2000000 |
| `maxRuntimeMs` | `--max-runtime-ms` | 20000 | 600000 |

Exceeding a limit is always an explicit finding naming the limit, and always makes the run
incomplete. Nothing is silently truncated. An unknown limit name is refused rather than ignored, so
a one-character typo cannot disable a bound.

The time budget is read from an injected clock. Nothing in this package calls `Date.now`,
constructs a `Date`, or reads a locale.

## Determinism

- Findings are ordered by `location.file`, then `location.pointer`, then `ruleId`, then `message`.
- A `location.pointer` is a JSON Pointer built from the tool's own vocabulary and from positions,
  never from a string in the file. Where a finding anchors below a record member — the three rules
  that refuse a record's canonical form — each object key contributes `#n`, its position among its
  siblings in the canonical code-unit key order, and each array index contributes the index. A key
  inside `details` is written by the same producer as the value beside it, so `/records/0/details/#0`
  is what a reader gets instead of the key's spelling; sorting that object's keys by code unit and
  taking the first of them finds the value.
- All ordering is by UTF-16 code unit, including the object-key ordering inside the canonical form
  a digest is computed over. Locale collation varies with the ICU data a Node build carries, which
  would make a record's digest host-dependent.
- Running the tool twice over identical inputs produces byte-identical stdout.

## What this tool does not conclude

- **It cannot detect deletion from the end of a trail without a checkpoint.** Remove the last n
  records and everything above still verifies. Without `--checkpoint` the run is `incomplete` and
  says so in `coverage.tailDeletionDetectable`.
- **A checkpoint covers up to its own record and no further.** Records after it are in exactly the
  position the whole trail was in without one.
- **It verifies no signature and holds no key material.** A checkpoint's authority comes from where
  the operator kept it, not from anything this tool checked.
- **It does not establish that a trail is authentic**, that the writer was honest, or that the
  events described happened. Everything it says is about the bytes in the files it was given.
- **It does not detect a record that was never written.** A chain has nothing to say about an event
  the producer chose not to record.
- **A timestamp is checked for shape and monotonicity only.** `2026-02-31T00:00:00Z` is well formed
  by these rules; whether it is a real instant is not checked.
- **It reads only local files and opens no socket.** There is no remote checkpoint service, no
  transparency log client and no notarisation.

## How the severity and ordering guards were measured

Both guards were measured by mutation against the finished suite, because a guard that is only
declared is a guard an edit will satisfy.

**Severity, coordinated flip.** Each of the 41 rules had its severity flipped in the table in
`src/index.mjs` **and** in the catalog above, together, and the full suite was run against the
result. `test/severity-table.test.mjs` compares those two declarations and therefore stays green
under exactly this edit, which is the point of the exercise.

| Direction | Rules | Caught | Survived |
| --- | ---: | ---: | ---: |
| `error` to `warning` | 37 | 37 | 0 |
| `warning` to `error` | 4 | 4 | 0 |

**Ordering, per call site.** Each call site of `byCodeUnit` in `src/` was replaced, one at a time,
with `new Intl.Collator('en').compare`, and the suite was run without
`test/no-network.test.mjs` — that file scans the source for `Intl.` and would report every
mutation as caught without any of them changing what the tool emits.

| Call site | What it orders | Result |
| --- | --- | --- |
| `src/canonical.mjs` | object keys inside the digest | killed, 4 tests |
| `src/coverage.mjs` | unknown checkpoint keys | killed, 1 test |
| `src/index.mjs` `validateLimits` loop | which unknown limit is reported first | killed, 1 test |
| `src/index.mjs` `validateLimits` message | the known-limit list in the message | survived — equivalent |
| `src/index.mjs` `compareFindings` file | `location.file` | killed, 1 test |
| `src/index.mjs` `compareFindings` pointer | `location.pointer` | survived — equivalent |
| `src/index.mjs` `compareFindings` rule | `ruleId` | survived — equivalent |
| `src/index.mjs` `compareFindings` message | `message` | survived — equivalent |
| `src/index.mjs` option loop | which unknown option is reported first | killed, 1 test |
| `src/records.mjs` `unknownKeys` | unknown document and record keys | killed, 2 tests |

Six of the ten call sites are pinned by what the tool emits. The four that survived order values on
which the two comparisons agree for every pair, so no test could catch the substitution;
`test/ordering-equivalence.test.mjs` proves each one instead of leaving it as a gap:

- 1681 ordered pairs of the 41 real rule ids,
- 36 ordered pairs of the 6 real limit names,
- 9801 ordered pairs of the 99 structural JSON Pointers, with a completeness check that the corpus
  emits no pointer shape outside the enumerated vocabulary, and a check that at most one finding
  per record anchors inside `details` — and no pointer carries a key name from a file at all, so
  a key name can never decide a comparison,
- and, for the message, a check that `location.file`, `location.pointer` and `ruleId` are unique
  together in every corpus report, so the message component never decides an order at all.
