# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). A rule id is part of the public
interface: renaming one is a breaking change and is recorded here.

## [Unreleased]

### Added

- `checkAuditTrail`, the CLI, and the report envelope: schema, sequence and hash-chain verification
  of a local audit trail, with the tail-coverage verdict reported in a `coverage` block of its own.
- 41 rules, each with a severity taken from one frozen table and documented in
  `docs/integrity-rules.md`.
- The canonical form a record digest is computed over, specified exactly in
  `docs/integrity-rules.md` and pinned by a literal known-answer test.
- Six enforced limits, each reported by name when reached, with an `incomplete` result rather than
  a silent truncation.
- Examples covering a trail that passes, a trail with three separate defects, and a trail with no
  checkpoint whose verdict is identical before and after its tail is deleted.

### Fixed

- A parse error no longer quotes the document it failed on. V8 embeds the input in its message, and
  the earlier helper looked for `at position N` before recognising the quoting shape, so a document
  whose own text reads `at position 1` was sliced back out onto stdout and stderr. The quoting shape
  is now recognised first, and any detail still carrying a double quote is discarded.
- `location.pointer` no longer carries a key name from the file. A refusal inside `details` built
  its pointer from raw keys, so a record keyed by a credential printed it past every redactor; a key
  now contributes its position in canonical order.
- The human coverage sentence no longer reads `tail coverage: through sequence null`. It read
  `uncoveredTailRecords`, which is a floor rather than a claim; `coveredThroughSequence` decides.
- `--max-runtime-ms` now bounds the compile loop as well as the two verification loops. It was
  checked only during verification, so a large malformed trail ran to the end of compilation
  whatever the budget said.

### Documented

- README's non-goals names the three strings this tool echoes from a file -- a record id, a trail
  name, and an unknown key's name -- and `test/redaction.test.mjs` measures that list rather than
  restating it.
- `--help` describes the time budget as a budget checked between records in three loops, not as a
  deadline for the verification.

No release has been published.
