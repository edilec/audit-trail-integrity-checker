import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CHECKPOINT_NAME,
  TRAIL_NAME,
  WITH_CHECKPOINT,
  chain,
  checkpointAtEnd,
  cliHuman,
  cliReport,
  event,
} from './support.mjs'

/**
 * An audit record is exactly the kind of document that carries a card number, a
 * token, an address or a name, and this tool's output goes to stdout -- a
 * stream that is piped into a CI log and pasted into a ticket. No value from
 * inside a record is ever echoed: the pointer on a finding says where to look,
 * and the value stays in the file.
 *
 * The canaries below are published placeholders, never real credentials: the
 * example key from the AWS documentation, the standard test card number that
 * authorises nothing, and a hostname under the RFC 2606 `.invalid` reserved
 * top-level domain.
 *
 * The scan checks **every prefix** of each canary on **both** streams. A
 * redaction test that checks the one field somebody remembered is a test the
 * next field passes for free, and a test that checks only the whole value
 * passes for a report that leaks all but the last character.
 */

const CANARIES = Object.freeze({
  'AWS example access key id': 'AKIAIOSFODNN7EXAMPLE',
  'standard test card number': '4111111111111111',
  'reserved example host': 'api.example.invalid',
  'bearer-looking token': 'Bearer-ZXhhbXBsZS10b2tlbg',
})

/**
 * Prefixes shorter than this are not evidence of a leak: eight hex-compatible
 * digits of the card number would collide with a digest excerpt roughly once in
 * a hundred million positions, and shorter still would collide with ordinary
 * English. Everything from eight characters up is scanned.
 */
const MIN_PREFIX = 8

function prefixes(value) {
  const list = []
  for (let length = MIN_PREFIX; length <= value.length; length += 1) list.push(value.slice(0, length))
  return list
}

/**
 * A trail whose every record carries every canary, and whose records are broken
 * in several different ways at once so that as many findings as possible are
 * built over records holding them.
 */
function loadedTrail() {
  const details = {
    accessKeyId: CANARIES['AWS example access key id'],
    card: CANARIES['standard test card number'],
    host: CANARIES['reserved example host'],
    token: CANARIES['bearer-looking token'],
  }
  const document = chain('billing.eu-west-1', [
    event('evt-0001', { details }),
    event('evt-0002', { details, actor: 4 }),
    event('evt-0003', { details, timestamp: 'not-a-time' }),
    event('evt-0004', { details }),
  ])
  // An edit that fires the digest rule, and an extra key that fires the schema
  // rule, on records holding every canary.
  document.records[1] = { ...document.records[1], details: { ...details, extra: CANARIES['standard test card number'] } }
  document.records[3] = { ...document.records[3], leaked: CANARIES['AWS example access key id'] }
  return document
}

test('no prefix of any canary reaches stdout or stderr', async () => {
  const document = loadedTrail()
  const files = { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) }

  const machine = await cliReport(files, WITH_CHECKPOINT)
  const human = await cliHuman(files, WITH_CHECKPOINT)

  assert.equal(machine.report.findings.length > 3, true, 'the corpus must really produce findings')

  for (const [name, canary] of Object.entries(CANARIES)) {
    for (const prefix of prefixes(canary)) {
      for (const [stream, text] of [['stdout', machine.stdout], ['stderr', machine.stderr], ['human stdout', human.stdout], ['human stderr', human.stderr]]) {
        assert.equal(text.includes(prefix), false, `${name}: "${prefix}" reached ${stream}`)
      }
    }
  }
})

test('the report names where a defect is without quoting what is there', async () => {
  const document = loadedTrail()

  const { report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) },
    WITH_CHECKPOINT,
  )

  const pointers = report.findings.map((finding) => finding.location.pointer)
  assert.equal(pointers.some((pointer) => pointer.startsWith('/records/')), true)
  // A refused value is described, never reproduced.
  const described = report.findings.find((finding) => /a string of \d+ character/.test(finding.message))
  assert.notEqual(described, undefined)
})

test('evidence is only ever digests, and only their first sixteen digits', async () => {
  const document = loadedTrail()
  const checkpoint = checkpointAtEnd(document)
  document.records[2] = { ...document.records[2], actor: 'user:intruder' }

  const { report } = await cliReport(
    { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint },
    WITH_CHECKPOINT,
  )

  const withEvidence = report.findings.filter((finding) => finding.evidence !== undefined)
  assert.equal(withEvidence.length > 0, true)
  for (const finding of withEvidence) {
    for (const token of finding.evidence.split(' ')) {
      if (!token.endsWith('...')) continue
      assert.match(token, /^[0-9a-f]{16}\.\.\.$/)
    }
  }
})

/**
 * The parse-failure path, which every test above walks past.
 *
 * Every canary above rides inside a *parsed* record, so every assertion above
 * is about a value the tool chose to describe. A file that does not parse never
 * reaches that code: it is described by V8's own error message instead, and
 * that message quotes the input -- `Unexpected token 'A', "AKIA..." is not
 * valid JSON` -- reproducing a short file in full. Sanitising cannot repair it,
 * because the quoted snippet is at the front of the message and `excerpt` cuts
 * from the back.
 */
/**
 * The card number is by itself a valid JSON number, so a leading letter is put
 * in front of it to make the file unparseable while leaving the canary whole.
 * Everything else is already not JSON.
 */
function unparseable(canary) {
  try {
    JSON.parse(canary)
    return `x${canary}`
  } catch {
    return canary
  }
}

test('an unparseable file is not quoted back by its own parse error', async () => {
  for (const [name, canary] of Object.entries(CANARIES)) {
    const planted = unparseable(canary)
    const files = { [TRAIL_NAME]: planted, [CHECKPOINT_NAME]: planted }
    const machine = await cliReport(files, WITH_CHECKPOINT)
    const human = await cliHuman(files, WITH_CHECKPOINT)

    assert.equal(
      machine.report.findings.some((finding) => finding.ruleId === 'input-not-json'),
      true,
      'the file must really have failed to parse',
    )

    for (const prefix of prefixes(canary)) {
      for (const [stream, text] of [
        ['stdout', machine.stdout],
        ['stderr', machine.stderr],
        ['human stdout', human.stdout],
        ['human stderr', human.stderr],
      ]) {
        assert.equal(text.includes(prefix), false, `${name}: "${prefix}" reached ${stream} through a parse error`)
      }
    }
  }
})

/**
 * The other half of the fix: a diagnostic that says nothing is a different
 * defect. A truncated document fails deep inside the text, where V8 reports a
 * position rather than a quotation, and that position is what a reader needs.
 */
test('a parse failure still says where the document went wrong', async () => {
  const broken = `{"schemaVersion":"1","trail":"billing.eu-west-1","records":[{"sequence":1,`
  const { report } = await cliReport({ [TRAIL_NAME]: broken })

  const finding = report.findings.find((row) => row.ruleId === 'input-not-json')
  assert.notEqual(finding, undefined)
  assert.match(finding.message, /position \d+/)
  assert.match(finding.message, /line \d+ column \d+/)
})
