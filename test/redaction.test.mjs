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
import { byCodeUnit, parseFailureDetail } from '../src/text.mjs'

/**
 * An audit record is exactly the kind of document that carries a card number, a
 * token, an address or a name, and this tool's output goes to stdout -- a
 * stream that is piped into a CI log and pasted into a ticket. No value from
 * inside a record is ever echoed: the pointer on a finding says where to look,
 * and the value stays in the file.
 *
 * Three classes of string are echoed on purpose, and saying so is part of the
 * guarantee rather than an exception to it: a record's `id`, a trail's name,
 * and the name of a key the tool does not know. A report that cannot name the
 * duplicated record or the trail the checkpoint actually covers is a report
 * nobody can act on. The list is closed, it is enumerated at the bottom of
 * this file by planting the canary in every member of every document shape in
 * turn, and README's non-goals states it too -- so "only these three" is a
 * measured claim and not a recollection.
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

/**
 * The ordering inside `parseFailureDetail`, pinned against the document that
 * breaks the obvious order.
 *
 * V8 has two shapes and only one of them quotes the input. Looking for the
 * offset first is the natural reading -- keep the safe half, drop the rest --
 * and it is wrong: a document whose own text is `at position 1` produces
 * `Unexpected token 'a', "at position 1" is not valid JSON`, the offset is
 * found INSIDE the quoted span, and slicing up to it hands back the document.
 * So the quoting shape has to be recognised before the offset is looked for,
 * and nothing but a test over real parser output can hold that order in place.
 *
 * Every case below is a real `JSON.parse` failure, never a hand-written string:
 * a test that asserts against a message it wrote itself proves nothing about
 * the messages V8 emits.
 */

function parseFailure(document) {
  try {
    JSON.parse(document)
  } catch (error) {
    return error
  }
  throw new Error(`fixture parses as JSON: ${document}`)
}

test('a parse failure is described without any fragment of the document', () => {
  const longDocument = `${CANARIES['AWS example access key id']}     ${'x'.repeat(4000)}`
  const documents = {
    // The document that defeats offset-first ordering: its own text is the
    // thing the offset pattern looks for.
    'a document whose text reads "at position 1"': 'at position 1',
    // A file short enough to be nothing but the credential, quoted in full.
    'a credential-only document': CANARIES['AWS example access key id'],
    // Long, so V8 truncates -- but it truncates from the BACK, and the
    // credential is at the front.
    'a long document with a sensitive prefix': longDocument,
    // The quoted span can carry a newline, which is why the pattern needs `s`.
    'a quoted span containing a newline': `${CANARIES['AWS example access key id'].slice(0, 9)}\n${CANARIES['AWS example access key id'].slice(9)} zz`,
    // The quoted window is cut from the MIDDLE, with a leading ellipsis.
    'a quoted window cut from the middle': `{"records":[{"sequence":1,"actor":"x"}],"k":${CANARIES['AWS example access key id']}}`,
  }

  for (const [name, document] of Object.entries(documents)) {
    const error = parseFailure(document)
    const detail = parseFailureDetail(error)

    assert.equal(detail.includes('"'), false, `${name}: a double quote survived, so a quoted snippet may have`)
    // Safety alone is not the property. Recognising the quoting shape only
    // after looking for the offset is still safe -- the closing guard catches
    // it -- but every one of these documents then collapses to the generic
    // sentence and the reader is told nothing. The order is what keeps the
    // diagnostic, so the diagnostic is what pins the order.
    assert.notEqual(detail, 'the document could not be parsed as JSON', `${name}: the detail degraded to the generic sentence`)
    assert.match(detail, /^unexpected token /, `${name}: the offending token is what a reader gets instead of the document`)
    for (const [canaryName, canary] of Object.entries(CANARIES)) {
      for (const prefix of prefixes(canary)) {
        if (!document.includes(prefix)) continue
        assert.equal(detail.includes(prefix), false, `${name}: "${prefix}" of the ${canaryName} survived into the detail`)
      }
    }
    // A leak can also be any run of the document that is not a canary, so the
    // whole document is checked a second time, window by window.
    for (let start = 0; start + MIN_PREFIX <= document.length; start += 1) {
      const window = document.slice(start, start + MIN_PREFIX)
      if (/^[\s{}[\],:"]*$/.test(window)) continue
      assert.equal(detail.includes(window), false, `${name}: the document window "${window}" survived into the detail`)
    }
  }
})

test('the safe positional form is kept whole, offset and line and column', () => {
  const error = parseFailure('{"schemaVersion":"1","trail":"billing.eu-west-1","records":[{"sequence":1,')

  const detail = parseFailureDetail(error)
  assert.match(detail, /at position \d+ \(line \d+ column \d+\)$/)
  assert.equal(detail, error.message, 'the whole positional message carries no content and is kept')
})

test('a document that reads "at position 1" is not quoted back by the CLI', async () => {
  const planted = 'at position 1'
  const files = { [TRAIL_NAME]: planted, [CHECKPOINT_NAME]: planted }

  const machine = await cliReport(files, WITH_CHECKPOINT)
  const human = await cliHuman(files, WITH_CHECKPOINT)

  assert.equal(
    machine.report.findings.some((finding) => finding.ruleId === 'input-not-json'),
    true,
    'the file must really have failed to parse',
  )
  for (const [stream, text] of [
    ['stdout', machine.stdout],
    ['stderr', machine.stderr],
    ['human stdout', human.stdout],
    ['human stderr', human.stderr],
  ]) {
    assert.equal(text.includes('"at position 1'), false, `the document was quoted back on ${stream}`)
  }
})

/**
 * The closing guard, which is the reason this function is safe against parser
 * wordings that did not exist when it was written.
 *
 * Every branch above is a pattern matched against V8 messages observed today,
 * and the dangerous case is not a wording that misses every branch -- that one
 * already ends at the generic sentence. It is a wording that MATCHES the branch
 * believed safe: put a quoted snippet in front of the offset and the offset
 * branch keeps the snippet along with it, which is exactly the shape older Node
 * releases used (`Unexpected token A in JSON at position 7`). The last line
 * exists for that: a double quote surviving to the end means a quoted snippet
 * survived, whatever branch produced it, so the generic sentence is used
 * instead. Delete it and this test fails.
 */
test('an unrecognised parser wording that still quotes the input is refused whole', () => {
  const unseen = { message: 'Unexpected string "' + CANARIES['standard test card number'] + '" in JSON at position 41 (line 1 column 42)' }

  const detail = parseFailureDetail(unseen)

  assert.equal(detail, 'the document could not be parsed as JSON')
  for (const canary of Object.values(CANARIES)) {
    for (const prefix of prefixes(canary)) {
      assert.equal(detail.includes(prefix), false, `"${prefix}" survived an unrecognised parser wording`)
    }
  }
})

/**
 * Keys are content too, and `details` is where the content lives.
 *
 * Every canary above rides in a record *value*, and the assertion that catches
 * it is about what the tool chooses to describe. A key is different: it is
 * written by the same producer as the value beside it, and a payload keyed by
 * account number, email address or access token is an ordinary shape for an
 * audit record. The refusal path through `details` used to be concatenated
 * from those keys straight onto the finding's pointer, so `--max-detail-depth`
 * -- a limit the operator sets, on a record the tool never even hashed --
 * printed them to stdout and stderr past every redactor.
 *
 * What replaces them still has to be usable, which is why the position is
 * asserted and not just the absence: `#0` is the first key of that object in
 * the canonical code-unit order this package already defines, so the value is
 * still findable by hand.
 */
test('a key from inside a record never reaches a pointer', async () => {
  const canary = CANARIES['AWS example access key id']
  const document = chain('billing.eu-west-1', [
    event('evt-0001', { details: { [canary]: { a: { b: { c: 1 } } } } }),
  ])
  const files = { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) }
  const args = [...WITH_CHECKPOINT, '--max-detail-depth', '3']

  const machine = await cliReport(files, args)
  const human = await cliHuman(files, args)

  const refused = machine.report.findings.find((finding) => finding.ruleId === 'detail-depth-exceeded')
  assert.notEqual(refused, undefined, 'the record must really have been refused')
  assert.equal(refused.location.pointer, '/records/0/details/#0/#0/#0')

  for (const prefix of prefixes(canary)) {
    for (const [stream, text] of [
      ['stdout', machine.stdout],
      ['stderr', machine.stderr],
      ['human stdout', human.stdout],
      ['human stderr', human.stderr],
    ]) {
      assert.equal(text.includes(prefix), false, `"${prefix}" reached ${stream} as a pointer segment`)
    }
  }
})

/**
 * An array index is structure, not content -- reordering an array changes the
 * digest, so the index is part of what the tool is talking about -- and it
 * stays. This pins the two segment kinds apart, so a fix that redacted
 * everything would fail here rather than quietly making the pointer useless.
 */
test('an array index in a refusal path is kept, a key beside it is not', async () => {
  const canary = CANARIES['reserved example host']
  const document = chain('billing.eu-west-1', [
    event('evt-0001', { details: { [canary]: [0, { deep: { deeper: 1 } }] } }),
  ])
  const files = { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpointAtEnd(document) }
  const args = [...WITH_CHECKPOINT, '--max-detail-depth', '3']

  const machine = await cliReport(files, args)

  const refused = machine.report.findings.find((finding) => finding.ruleId === 'detail-depth-exceeded')
  assert.notEqual(refused, undefined)
  assert.equal(refused.location.pointer, '/records/0/details/#0/1/#0')
  for (const prefix of prefixes(canary)) {
    assert.equal(machine.stdout.includes(prefix), false, `"${prefix}" reached stdout as a pointer segment`)
  }
})

/**
 * The echo boundary, enumerated rather than described.
 *
 * Three classes of string from a file do reach stdout and stderr, and they are
 * there on purpose: a report that says "a record is duplicated" without saying
 * which record, or "the checkpoint covers a different trail" without naming
 * either trail, is a report nobody can act on. `test/sanitisation.test.mjs`
 * plants control characters in exactly these fields for the same reason -- they
 * are the untrusted strings this tool deliberately prints.
 *
 * The risk is not that they are printed. It is that the list drifts: one more
 * field quoted into one more message, and a guarantee everybody still believes
 * has quietly stopped being true. So the list is measured here rather than
 * asserted field by field -- every member of every document shape gets the
 * canary in turn, and the set that comes back must be exactly this set. A new
 * echo fails this test, and so does an echo that silently disappears, because
 * a stale list is the thing being guarded against.
 */

const ECHOED_ON_PURPOSE = Object.freeze([
  'an unknown key name in a record',
  'an unknown key name in the checkpoint',
  'an unknown key name in the document',
  'the record id in a record',
  'the record id in the checkpoint',
  'the trail name in the checkpoint',
  'the trail name in the document',
])

function plantings(canary) {
  const base = () => {
    const document = chain('billing.eu-west-1', [event('evt-0001'), event('evt-0002')])
    return { document, checkpoint: checkpointAtEnd(document) }
  }
  const at = (mutate) => {
    const files = base()
    mutate(files)
    return { [TRAIL_NAME]: files.document, [CHECKPOINT_NAME]: files.checkpoint }
  }

  return {
    'the record id in a record': at((f) => { f.document.records[0].id = canary }),
    'the timestamp in a record': at((f) => { f.document.records[0].timestamp = canary }),
    'the actor in a record': at((f) => { f.document.records[0].actor = canary }),
    'the action in a record': at((f) => { f.document.records[0].action = canary }),
    'the target in a record': at((f) => { f.document.records[0].target = canary }),
    'a details value in a record': at((f) => { f.document.records[0].details = { k: canary } }),
    'a details key in a record': at((f) => { f.document.records[0].details = { [canary]: 1 } }),
    'the hash in a record': at((f) => { f.document.records[0].hash = canary }),
    'the previousHash in a record': at((f) => { f.document.records[0].previousHash = canary }),
    'an unknown key name in a record': at((f) => { f.document.records[0][canary] = 1 }),
    'an unknown key value in a record': at((f) => { f.document.records[0].spare = canary }),
    'the trail name in the document': at((f) => { f.document.trail = canary }),
    'the schemaVersion in the document': at((f) => { f.document.schemaVersion = canary }),
    'an unknown key name in the document': at((f) => { f.document[canary] = 1 }),
    'an unknown key value in the document': at((f) => { f.document.spare = canary }),
    'the trail name in the checkpoint': at((f) => { f.checkpoint.trail = canary }),
    'the record id in the checkpoint': at((f) => { f.checkpoint.recordId = canary }),
    'the recordHash in the checkpoint': at((f) => { f.checkpoint.recordHash = canary }),
    'the issuedAt in the checkpoint': at((f) => { f.checkpoint.issuedAt = canary }),
    'the signature in the checkpoint': at((f) => { f.checkpoint.signature = canary }),
    'an unknown key name in the checkpoint': at((f) => { f.checkpoint[canary] = 1 }),
    'an unknown key value in the checkpoint': at((f) => { f.checkpoint.spare = canary }),
  }
}

test('exactly three classes of string from a file reach a stream, and they are the documented three', async () => {
  const canary = CANARIES['AWS example access key id']
  const echoed = []

  for (const [where, files] of Object.entries(plantings(canary))) {
    const machine = await cliReport(files, WITH_CHECKPOINT)
    const human = await cliHuman(files, WITH_CHECKPOINT)
    const streams = [machine.stdout, machine.stderr, human.stdout, human.stderr]

    if (!streams.some((text) => text.includes(canary))) continue
    // The human summary may never disclose something the machine report does
    // not: a reader who pipes stdout to a parser and stderr to a log would
    // otherwise find the log carries more than the artefact does.
    assert.equal(machine.stdout.includes(canary), true, `${where}: a stream carried it and the report did not`)
    echoed.push(where)
  }

  assert.deepEqual(echoed.sort(byCodeUnit), [...ECHOED_ON_PURPOSE], 'the set of strings this tool echoes has changed')
})
