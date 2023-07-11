import assert from 'node:assert/strict'
import test from 'node:test'
import { readFile, writeFile } from 'node:fs/promises'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { CHECKPOINT_NAME, TRAIL_NAME, cliRun, projectDirectory } from './support.mjs'

/**
 * The three shipped examples, run exactly as the README says to run them.
 *
 * The last test is the one worth reading: it takes the checkpoint-less example,
 * deletes the last three records, and asserts the tool reports the truncated
 * file exactly as it reports the whole one. That is the limit this package is
 * built to state, demonstrated on the files a reader can open.
 */

const example = (name) => join(projectDirectory, 'examples', name)

test('the clean example passes and exits 0', async () => {
  const { code, stdout } = await cliRun(['--root', example('clean'), '--checkpoint', CHECKPOINT_NAME, '--json'])
  const report = JSON.parse(stdout)

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.deepEqual(report.findings, [])
  assert.equal(report.summary.records, 6)
  assert.equal(report.summary.checked, 6)
  assert.equal(report.summary.hashesVerified, 6)
  assert.equal(report.summary.linksVerified, 5)
  assert.equal(report.coverage.coveredThroughSequence, 6)
})

test('the broken example fails and exits 1, with one finding per defect', async () => {
  const { code, stdout } = await cliRun(['--root', example('broken'), '--checkpoint', CHECKPOINT_NAME, '--json'])
  const report = JSON.parse(stdout)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.deepEqual(
    report.findings.map((finding) => finding.ruleId),
    ['tail-truncated-below-checkpoint', 'chain-link-broken', 'sequence-gap'],
  )
  assert.equal(report.summary.chainVerified, false)
  assert.equal(report.summary.sequenceContinuous, false)
})

test('the checkpoint-less example is incomplete and exits 2, with no error at all', async () => {
  const { code, stdout } = await cliRun(['--root', example('no-checkpoint'), '--json'])
  const report = JSON.parse(stdout)

  assert.equal(code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.chainVerified, true)
  assert.equal(report.summary.sequenceContinuous, true)
  assert.equal(report.coverage.tailDeletionDetectable, false)
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['tail-deletion-undetectable'])
})

test('the checkpoint-less example reports the same way after its tail is deleted', async () => {
  const whole = JSON.parse(await readFile(join(example('no-checkpoint'), TRAIL_NAME), 'utf8'))
  const base = await mkdtemp(join(tmpdir(), 'audit-trail-examples-'))

  try {
    const truncated = { ...whole, records: whole.records.slice(0, 3) }
    await writeFile(join(base, TRAIL_NAME), `${JSON.stringify(truncated, null, 2)}\n`)

    const cut = JSON.parse((await cliRun(['--root', base, '--json'])).stdout)
    const full = JSON.parse((await cliRun(['--root', example('no-checkpoint'), '--json'])).stdout)

    // Half the trail is gone and every verdict is identical. Nothing inside the
    // file can tell the two apart, which is why neither of them is a pass.
    assert.equal(cut.summary.chainVerified, full.summary.chainVerified)
    assert.equal(cut.summary.sequenceContinuous, full.summary.sequenceContinuous)
    assert.equal(cut.summary.errors, full.summary.errors)
    assert.equal(cut.status, full.status)
    assert.deepEqual(
      cut.findings.map((finding) => finding.ruleId),
      full.findings.map((finding) => finding.ruleId),
    )
    assert.equal(cut.summary.records, 3)
    assert.equal(full.summary.records, 6)
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})

test('the shipped examples are the documented format, byte for byte', async () => {
  for (const name of ['clean', 'broken', 'no-checkpoint']) {
    const text = await readFile(join(example(name), TRAIL_NAME), 'utf8')
    const document = JSON.parse(text)

    assert.equal(document.schemaVersion, '1')
    assert.equal(document.trail, 'billing.eu-west-1')
    assert.equal(text.endsWith('}\n'), true)
    for (const record of document.records) {
      assert.match(record.hash, /^[0-9a-f]{64}$/)
      assert.equal(record.previousHash === null || /^[0-9a-f]{64}$/.test(record.previousHash), true)
    }
  }
})
