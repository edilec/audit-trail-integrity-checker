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

No release has been published.
