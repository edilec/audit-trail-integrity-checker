import assert from 'node:assert/strict'
import test from 'node:test'

import { checkAuditTrail, validateLimits } from '../src/index.mjs'
import {
  CHECKPOINT_NAME,
  TRAIL_NAME,
  WITH_CHECKPOINT,
  chain,
  checkpointAtEnd,
  cleanFiles,
  cliReport,
  event,
  findingsFor,
} from './support.mjs'

/**
 * Ordering, pinned by what the tool emits.
 *
 * Every case below uses values whose order genuinely differs between UTF-16
 * code-unit comparison and English collation -- `Z` before `a`, an upper-case
 * initial before a lower-case one -- and asserts the exact result. Substituting
 * `new Intl.Collator('en').compare` at the call site each case covers makes
 * that case fail; a scan of the source for a method name cannot tell one
 * comparator from the other, which is why no such scan appears here.
 *
 * `test/ordering-equivalence.test.mjs` covers the remaining call sites, whose
 * values are drawn from alphabets on which the two orders agree on every pair.
 */

test('the digest sorts a record key by code unit, so the same record hashes the same everywhere', async () => {
  // The third record of the clean trail carries `X-Request-Id` and `actor_ip`.
  // Collation puts `actor_ip` first; code unit puts the upper-case X first.
  // Ordering them the other way changes the canonical form, which changes the
  // digest, which makes this trail report a record that was never touched as
  // having been edited.
  const { code, report } = await cliReport(cleanFiles(), WITH_CHECKPOINT)

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.equal(report.summary.hashesVerified, 4)
})

test('unknown record keys are listed in code-unit order', async () => {
  const document = chain('billing.eu-west-1', [event('evt-0001')])
  document.records[0] = { ...document.records[0], Zed: 1, alpha: 2 }

  const { report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    WITH_CHECKPOINT,
  )

  const finding = findingsFor(report, 'record-invalid')[0]
  assert.match(finding.message, /unknown key\(s\) "Zed", "alpha";/)
})

test('unknown checkpoint keys are listed in code-unit order', async () => {
  const document = chain('billing.eu-west-1', [event('evt-0001')])
  const checkpoint = { ...checkpointAtEnd(document), Zed: 1, alpha: 2 }

  const { report } = await cliReport({ [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint }, WITH_CHECKPOINT)

  const finding = findingsFor(report, 'checkpoint-invalid')[0]
  assert.match(finding.message, /unknown key\(s\) "Zed", "alpha";/)
})

test('unknown document keys are listed in code-unit order', async () => {
  const document = { ...chain('billing.eu-west-1', [event('evt-0001')]), Zed: 1, alpha: 2 }

  const { report } = await cliReport({ [TRAIL_NAME]: document })

  const finding = findingsFor(report, 'document-invalid')[0]
  assert.match(finding.message, /unknown key\(s\) "Zed", "alpha";/)
})

test('the first unknown limit reported is the first by code unit', () => {
  assert.throws(() => validateLimits({ Zed: 1, alpha: 2 }), /Unknown limit "Zed"/)
})

test('the first unknown option reported is the first by code unit', async () => {
  await assert.rejects(
    () => checkAuditTrail({ root: '.', Zed: 1, alpha: 2 }),
    /Unknown option "Zed"/,
  )
})

test('findings are ordered by file name, by code unit', async () => {
  // Two files that both fail to be read, named so that collation would put them
  // the other way round.
  const { report } = await cliReport(
    { 'Zed.json': 'not json\n', 'alpha.json': 'not json\n' },
    ['--trail', 'Zed.json', '--checkpoint', 'alpha.json'],
  )

  assert.deepEqual(
    report.findings.map((finding) => finding.location.file),
    ['Zed.json', 'alpha.json'],
  )
})

test('findings at the same file are ordered by pointer, then by rule id', async () => {
  const document = chain('billing.eu-west-1', [
    event('evt-0001', { actor: 4 }),
    event('evt-0002', { timestamp: 'no' }),
  ])

  const { report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    WITH_CHECKPOINT,
  )

  const keys = report.findings.map((finding) => `${finding.location.file}${finding.location.pointer} ${finding.ruleId}`)
  assert.deepEqual(keys, [...keys].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0)))
  assert.equal(keys.length > 1, true)
})

test('the same input produces byte-identical output twice', async () => {
  const files = cleanFiles()
  const first = await cliReport(files, WITH_CHECKPOINT)
  const second = await cliReport(files, WITH_CHECKPOINT)

  assert.equal(first.stdout, second.stdout)
})
