import assert from 'node:assert/strict'
import test from 'node:test'

import { CHECKPOINT_NAME, TRAIL_NAME, WITH_CHECKPOINT, cleanFiles, cliHuman, cliReport, cliRun, withRoot } from './support.mjs'

/**
 * The command-line surface, driven as a real process.
 *
 * The two stream rules are the ones a consumer depends on: stdout carries the
 * JSON report and nothing else, and a configuration error leaves stdout empty
 * rather than fabricating a report about a run that never had a subject.
 */

test('--help explains what the tool cannot detect, and exits 0', async () => {
  const { code, stdout, stderr } = await cliRun(['--help'])

  assert.equal(code, 0)
  assert.equal(stderr, '')
  assert.match(stdout, /audit-trail-integrity-checker/)
  assert.match(stdout, /cannot detect on its own: records removed from the END/)
  assert.match(stdout, /--checkpoint FILE/)
  assert.match(stdout, /Exit codes:/)
})

test('-h is the same help', async () => {
  const long = await cliRun(['--help'])
  const short = await cliRun(['-h'])

  assert.equal(short.stdout, long.stdout)
  assert.equal(short.code, 0)
})

test('--version prints the version and nothing else', async () => {
  const { code, stdout } = await cliRun(['--version'])

  assert.equal(code, 0)
  assert.equal(stdout, '0.1.0\n')
})

test('--root is required, and its absence leaves stdout empty', async () => {
  const { code, stdout, stderr } = await cliRun([])

  assert.equal(code, 2)
  assert.equal(stdout, '')
  assert.match(stderr, /--root is required/)
})

test('an unknown option leaves stdout empty', async () => {
  const { code, stdout, stderr } = await cliRun(['--root', '.', '--strict'])

  assert.equal(code, 2)
  assert.equal(stdout, '')
  assert.match(stderr, /Unknown option "--strict"/)
})

test('an option given twice is refused rather than silently last-wins', async () => {
  await withRoot(cleanFiles(), async (root) => {
    const { code, stdout, stderr } = await cliRun([
      '--root', root, '--checkpoint', CHECKPOINT_NAME, '--checkpoint', 'other.json',
    ])

    assert.equal(code, 2)
    assert.equal(stdout, '')
    assert.match(stderr, /--checkpoint was given more than once/)
  })
})

test('an option that needs a value and has none is refused', async () => {
  const { code, stdout, stderr } = await cliRun(['--root'])

  assert.equal(code, 2)
  assert.equal(stdout, '')
  assert.match(stderr, /--root requires a value/)
})

test('a run without --json prints the human summary on stderr and the report on stdout', async () => {
  const { code, stdout, stderr } = await cliHuman(cleanFiles(), WITH_CHECKPOINT)

  assert.equal(code, 0)
  assert.equal(JSON.parse(stdout).status, 'pass')
  assert.match(stderr, /^trail trail\.json \(billing\.eu-west-1\): 4 of 4 record\(s\) examined/m)
  assert.match(stderr, /^chain verified: true\. sequence continuous: true\. status pass\./m)
  assert.match(stderr, /^tail coverage: complete through sequence 4, the last of 4 record\(s\)\.$/m)
})

test('--json silences the human summary but never the incomplete notice', async () => {
  const quiet = await cliReport({ [TRAIL_NAME]: cleanFiles()[TRAIL_NAME] }, [])

  assert.equal(quiet.code, 2)
  assert.equal(quiet.stderr.split('\n').filter((line) => line !== '').length, 1)
  assert.match(quiet.stderr, /^incomplete: this run is not a pass\./)
})

test('the tool reads the trail from --trail, relative to --root', async () => {
  const files = cleanFiles()
  const renamed = { 'audit-2026-01.json': files[TRAIL_NAME], [CHECKPOINT_NAME]: files[CHECKPOINT_NAME] }

  const { code, report } = await cliReport(renamed, ['--trail', 'audit-2026-01.json', ...WITH_CHECKPOINT])

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.equal(report.findings.length, 0)
})

test('stdout stays parseable when the run could not start reading anything', async () => {
  const { code, stdout } = await cliReport({}, [])

  assert.equal(code, 2)
  assert.equal(JSON.parse(stdout).status, 'incomplete')
})
