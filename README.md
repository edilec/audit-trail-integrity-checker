# audit-trail-integrity-checker

Verify a local audit trail: the schema of each record, the continuity of the sequence numbers, and
the previous-record hash chain. Then say exactly how far that verification reaches — which is
further than most readers assume in one direction, and much shorter in another.

- **Repository:** [edilec/audit-trail-integrity-checker](https://github.com/edilec/audit-trail-integrity-checker)
- **Area:** Security & Privacy
- **License:** MIT

No dependencies, runtime or development. Node 22 or newer. It reads files and computes SHA-256
digests; it opens no socket, holds no key material and writes nothing anywhere.

## The one thing to read before using it

**A hash chain cannot detect truncation of its own tail.** Remove the last _n_ records from a
chained trail and the file that remains verifies perfectly: every digest still matches its record,
every link still matches its predecessor, and the sequence still runs consecutively from the first
record to the new last one. There is nothing inside the file to compare the end of the file
against.

This tool therefore refuses to report a run without a checkpoint as a pass. It reports
`incomplete`, exits 2, and says so in a field of its own:

```json
"coverage": {
  "checkpointRequested": false,
  "checkpointApplied": false,
  "coveredThroughSequence": null,
  "uncoveredTailRecords": 6,
  "tailDeletionDetectable": false
}
```

Supply `--checkpoint` — a record id, sequence number and digest recorded somewhere the trail's
writer cannot reach — and coverage reaches that record and stops there. A trail that stops short of
its checkpoint is then caught, and it is the only way tail deletion is caught at all.

## Install

```sh
npm install --global audit-trail-integrity-checker
```

Or run it from a checkout with `node bin/audit-trail-integrity-checker.mjs`.

## Use

```sh
# The shape that can pass: a trail plus a checkpoint over its last record.
audit-trail-integrity-checker --root examples/clean --checkpoint checkpoint.json

# Three defects at once; exits 1.
audit-trail-integrity-checker --root examples/broken --checkpoint checkpoint.json

# The same records with no checkpoint; exits 2, and says why.
audit-trail-integrity-checker --root examples/no-checkpoint
```

stdout carries the JSON report and nothing else, so it pipes straight into a parser. stderr carries
the human summary. A non-empty stderr is normal.

```
trail trail.json (billing.eu-west-1): 6 of 6 record(s) examined, 6 digest(s) and 5 link(s) verified.
chain verified: true. sequence continuous: true. status pass.
tail coverage: complete through sequence 6, the last of 6 record(s).
```

| Exit | Meaning |
| ---: | --- |
| `0` | the trail was verified as far as the checkpoint reaches |
| `1` | the trail was verified and at least one error-severity rule fired |
| `2` | invalid configuration (**stdout is empty**), or evidence that could not be obtained (an `incomplete` report on stdout, never a `pass`) |

Run `audit-trail-integrity-checker --help` for every option, and see
[`docs/integrity-rules.md`](./docs/integrity-rules.md) for the input format, the exact canonical
form a digest is computed over, the full rule catalog and the limits.

## The three checks, and why they are separate

**Schema.** Every record carries the members this build understands, in the shapes it understands,
and no others. An unknown key is reported rather than ignored — a typo in `previousHash` would
otherwise quietly remove a record's link from the chain while its own digest still verified.

**Sequence.** The numbers run consecutively. A chain that verifies perfectly can still skip a
number, because the digest covers whatever the record happens to contain and has no opinion about
what is missing between two records. A producer that skips numbers makes deletion and
non-issuance indistinguishable, which is worth knowing.

**Chain.** Every record's digest recomputes to the value stored with it, and every record links to
the digest of the record before it. This is what catches a record edited anywhere in the file, and
a record removed from the middle of it. Editing a record breaks its own digest; recomputing that
digest to hide the edit then breaks the link the next record carries; removing a record breaks the
link of the record that followed it.

None of the three is allowed to stand in for another, and the report carries each verdict
separately: `summary.chainVerified`, `summary.sequenceContinuous`, and the `coverage` block.

## Using it as a library

```js
import { checkAuditTrail } from 'audit-trail-integrity-checker'

const report = await checkAuditTrail({
  root: 'var/audit',
  trail: 'trail.json',
  checkpoint: 'checkpoint.json',
})

if (report.status !== 'pass') process.exitCode = report.status === 'fail' ? 1 : 2
```

`checkAuditTrail` throws on a configuration error — an unknown option, a limit outside its range, a
file name that climbs out of the root — and returns a report for everything else. The time budget
reads an injected `clock`, so nothing in the package reads a wall clock.

## Limits and non-goals

What this tool **cannot** conclude, stated plainly, because a checker that is vague about its edges
is worse than no checker:

- **It cannot detect deletion from the end of a trail without a checkpoint,** and with one it
  cannot detect deletion after the checkpointed record. That is a property of hash chains. The
  report says which case it is in rather than leaving it to be inferred from the absence of a
  finding.
- **It verifies no signature and holds no key material.** A checkpoint carrying a `signature` is
  reported as unsupported, never as verified. A checkpoint's authority comes from where the
  operator kept it.
- **A pass is not tamper-proofing.** It means the file is internally consistent and reaches as far
  as its checkpoint. It does not mean the trail is authentic, that the writer was honest, that the
  records describe events that happened, or that anyone with write access to both the trail and the
  checkpoint could not rewrite both.
- **It cannot detect a record that was never written.** A chain has nothing to say about an event
  the producer chose not to record.
- **It does not check that a timestamp is a real instant.** Shape and monotonicity only:
  `2026-02-31T00:00:00Z` is well formed by these rules.
- **It reads one local directory.** There is no remote checkpoint service, no transparency-log
  client, no notarisation, and no network access of any kind.
- **It reads a JSON document, not a log stream.** Append-only text logs, syslog, JSONL and vendor
  export formats must be converted first; the format is specified in `docs/integrity-rules.md`.
- **The canonical form is this tool's definition.** A producer computing digests differently — a
  different key order, different whitespace — will have every record reported as edited. That is a
  serialisation disagreement, not tampering, and the definition is written out exactly so a
  producer can match it.
- **The report names three strings from the file, and only three.** A record's `id`, a trail's
  name, and the name of any key the tool does not know are quoted into findings on stdout and
  stderr, because a report that cannot say *which* record is duplicated or *which* trail the
  checkpoint covers is one nobody can act on. Nothing else from a record reaches a stream: a
  refused value is described by its type and length, a pointer into `details` names key
  **positions** rather than key names, evidence is only ever the first sixteen digits of a digest,
  and a document that fails to parse is described without the parser quoting it back.
  `test/redaction.test.mjs` measures that list by planting a canary in every member of every
  document shape in turn, so it fails if the list grows. Treat a record id or a trail name as
  disclosed to wherever this tool's output goes.
- **It is not an attack tool.** It performs static verification of files it was pointed at. It does
  not probe a log service, test credentials, or attempt to produce a forged trail.

## Development

```sh
npm run check    # lint, test, example, pack:check
```

No dependencies are installed and none are needed; `npm run check` works in a fresh checkout.

## License

MIT. See [LICENSE](./LICENSE).
