#!/usr/bin/env node

import process from 'node:process'

import {
  DEFAULT_TRAIL_NAME,
  checkAuditTrail,
  describeCoverage,
  excerpt,
  exitCodeFor,
  formatReport,
  serializeReport,
} from '../src/index.mjs'

const VERSION = '0.1.0'

const HELP = `audit-trail-integrity-checker

Verify a local audit trail: the schema of each record, the continuity of the
sequence numbers, and the previous-record hash chain. Reads files and computes
SHA-256 digests; opens no socket, holds no key material and writes nothing.

What it detects: a record edited anywhere in the file, and a record removed
from the middle of it.

What it cannot detect on its own: records removed from the END of the file.
Delete the last n records of a hash-chained trail and every digest, every link
and every sequence number in what remains still verifies. Without --checkpoint
that is an unsupported claim, not a passing check: the run reports "incomplete"
and exits 2. With --checkpoint, coverage reaches the checkpointed record and
stops there.

Usage:
  audit-trail-integrity-checker --root DIR [--trail FILE] [--checkpoint FILE]
                                [--anchor-hash HEX] [--first-sequence N]
                                [--json] [--max-records N] [--max-file-bytes N]
                                [--max-detail-depth N] [--max-detail-nodes N]
                                [--max-runtime-ms N] [--max-findings N]

Options:
  --root DIR             Directory holding the documents (required)
  --trail FILE           Trail document, relative to --root
                         (default ${DEFAULT_TRAIL_NAME})
  --checkpoint FILE      Trusted checkpoint, relative to --root. Without it the
                         tail of the trail is unchecked and the run is
                         incomplete by construction.
  --anchor-hash HEX      Digest of the record immediately before this segment,
                         for a file whose first record is not the start of the
                         trail
  --first-sequence N     Sequence number this file is expected to start at
  --json                 Suppress the human summary on stderr
  --max-records N        Maximum records in one trail (default 50000)
  --max-file-bytes N     Maximum bytes per document (default 16777216)
  --max-detail-depth N   Maximum nesting inside one record (default 8)
  --max-detail-nodes N   Maximum values inside one record (default 500)
  --max-runtime-ms N     Time budget, checked between records in each of the
                         three record loops: compile, chain, sequence. It is
                         not a hard deadline -- a run overshoots by the cost
                         of the record in hand plus assembling the report --
                         and a run that passes it is incomplete, never a
                         shorter pass (default 20000)
  --max-findings N       Maximum findings in one report (default 1000)
  -h, --help             Show this help
  -v, --version          Show the version

Every option that carries a value may be given only once: a repeated flag is a
configuration error, not a silent last-wins.

Output:
  stdout  the JSON report only, so it can be piped straight into a parser
  stderr  the human summary and diagnostics

What a pass means:
  Every record declared in the file had its digest recomputed and matched, every
  link matched its predecessor, the sequence ran consecutively, and a checkpoint
  fixed the last record in the file. It means the file is internally consistent
  and reaches as far as the checkpoint. It does not mean the trail is complete
  beyond that checkpoint, that the checkpoint is authentic -- no signature is
  verified here -- or that the events described ever happened.

Exit codes:
  0  the trail was verified as far as the checkpoint reaches
  1  the trail was verified and at least one error-severity rule fired
  2  invalid configuration (no report on stdout), or evidence that could not be
     obtained (an "incomplete" report on stdout, never a "pass")
`

const LIMIT_FLAGS = new Map([
  ['--max-detail-depth', 'maxDetailDepth'],
  ['--max-detail-nodes', 'maxDetailNodes'],
  ['--max-file-bytes', 'maxFileBytes'],
  ['--max-findings', 'maxFindings'],
  ['--max-records', 'maxRecords'],
  ['--max-runtime-ms', 'maxRuntimeMs'],
])

const VALUE_FLAGS = new Map([
  ['--anchor-hash', 'anchorHash'],
  ['--checkpoint', 'checkpoint'],
  ['--root', 'root'],
  ['--trail', 'trail'],
])

function parseArguments(argv) {
  if (argv.includes('-h') || argv.includes('--help')) return { help: true }
  if (argv.includes('-v') || argv.includes('--version')) return { version: true }

  const options = {
    root: null, trail: null, checkpoint: null, anchorHash: null, firstSequence: null,
    json: false, limits: {},
  }
  const given = new Set()

  /**
   * A flag that carries a value is accepted once.
   *
   * Letting it repeat discards the earlier value with no diagnostic, so
   * `--checkpoint real.json --checkpoint stale.json` checks a tail against a
   * document nobody named. That is the same defect as an ignored typo, which
   * this tool also refuses.
   */
  const once = (name) => {
    if (given.has(name)) throw new Error(`${name} was given more than once`)
    given.add(name)
  }

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    const takeValue = (name) => {
      const value = argv[index + 1]
      if (value === undefined || value.startsWith('-')) throw new Error(`${name} requires a value`)
      index += 1
      return value
    }

    if (argument === '--json') options.json = true
    else if (argument === '--first-sequence') {
      once(argument)
      const raw = takeValue(argument)
      if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) {
        throw new Error('--first-sequence requires a non-negative integer')
      }
      options.firstSequence = Number(raw)
    } else if (VALUE_FLAGS.has(argument)) {
      once(argument)
      options[VALUE_FLAGS.get(argument)] = takeValue(argument)
    } else if (LIMIT_FLAGS.has(argument)) {
      once(argument)
      const raw = takeValue(argument)
      if (!/^\d+$/.test(raw) || Number(raw) < 1) throw new Error(`${argument} requires a positive integer`)
      options.limits[LIMIT_FLAGS.get(argument)] = Number(raw)
    // argv is the one untrusted string that reaches a stream without passing
    // through a finding, so it is flattened exactly as a finding would be.
    } else throw new Error(`Unknown option "${excerpt(argument, 60)}"`)
  }

  if (options.root === null) throw new Error('--root is required')
  return options
}

async function main(argv) {
  let options
  try {
    options = parseArguments(argv)
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${HELP}`)
    return 2
  }
  if (options.help) {
    process.stdout.write(HELP)
    return 0
  }
  if (options.version) {
    process.stdout.write(`${VERSION}\n`)
    return 0
  }

  let report
  try {
    report = await checkAuditTrail({
      root: options.root,
      limits: options.limits,
      ...(options.trail === null ? {} : { trail: options.trail }),
      ...(options.checkpoint === null ? {} : { checkpoint: options.checkpoint }),
      ...(options.anchorHash === null ? {} : { anchorHash: options.anchorHash }),
      ...(options.firstSequence === null ? {} : { firstSequence: options.firstSequence }),
    })
  } catch (error) {
    // A configuration error never had a subject, so stdout stays empty and the
    // consumer that pipes stdout gets nothing rather than a fabricated report.
    process.stderr.write(`${excerpt(error.message, 400)}\n`)
    return 2
  }

  process.stdout.write(`${serializeReport(report)}\n`)
  if (!options.json) {
    process.stderr.write(formatReport(report, { trail: options.trail ?? DEFAULT_TRAIL_NAME }))
  }
  if (report.status === 'incomplete') {
    process.stderr.write(`incomplete: this run is not a pass. ${describeCoverage(report)}\n`)
  }
  return exitCodeFor(report)
}

process.exitCode = await main(process.argv.slice(2))
