import assert from 'node:assert/strict'
import test from 'node:test'

import { excerpt, hasForbiddenCharacter, isIdentifier, serializeReport } from '../src/index.mjs'
import {
  CHECKPOINT_NAME,
  FORBIDDEN,
  TRAIL_NAME,
  WITH_CHECKPOINT,
  chain,
  checkpointAtEnd,
  cleanTrail,
  cliHuman,
  cliReport,
  cliRun,
  event,
} from './support.mjs'

/**
 * Nothing from an input file reaches either stream carrying a control, a
 * separator or a bidi override.
 *
 * The corpus below plants each character in a different *kind* of field, not
 * only in something that ends up in an excerpt: a record id, a key name, the
 * trail's own name, an actor, a value nested in `details`. A sibling tool
 * sanitised its evidence field carefully and left identifiers raw, so a record
 * id holding a newline forged a whole line in the human report -- which is why
 * the assertions below walk every string in the report rather than the one
 * field somebody remembered.
 */

function* strings(value, path = '') {
  if (typeof value === 'string') yield [path, value]
  else if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) yield* strings(value[index], `${path}/${index}`)
  } else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      yield [`${path}/${key} (key)`, key]
      yield* strings(item, `${path}/${key}`)
    }
  }
}

function corpus(character) {
  const document = chain(`trail${character}name`, [
    event(`evt${character}0001`),
    event('evt-0002', { actor: `svc${character}billing` }),
    event('evt-0003', { details: { [`key${character}name`]: `value${character}here` } }),
  ])
  document.records[1] = { ...document.records[1], [`unknown${character}key`]: 1 }
  const checkpoint = { ...checkpointAtEnd(document), recordId: `evt${character}0003` }
  return { [TRAIL_NAME]: document, [CHECKPOINT_NAME]: checkpoint }
}

for (const [name, character] of Object.entries(FORBIDDEN)) {
  test(`${name} never reaches stdout or stderr, whichever field it arrived in`, async () => {
    const { stdout, stderr, report } = await cliReport(corpus(character), WITH_CHECKPOINT)

    for (const [path, value] of strings(report)) {
      assert.equal(hasForbiddenCharacter(value), false, `${name} survived at ${path}`)
    }
    // The serialized form too. JSON escapes the C0 range inside a string but
    // emits U+2028, U+2029 and every bidi control as themselves, so the text
    // has to be scanned as well as the parsed values. The newlines the
    // pretty-printer writes between members are the only ones there are, and a
    // string value cannot add another: a raw newline inside one would have been
    // escaped by the serializer, and every line is scanned on its own below.
    for (const line of stdout.split('\n')) {
      assert.equal(hasForbiddenCharacter(line), false, `${name} survived in the serialized report`)
    }
    for (const line of stderr.split('\n')) {
      assert.equal(hasForbiddenCharacter(line), false, `${name} survived on stderr`)
    }
    assert.equal(stdout, `${serializeReport(report)}\n`)
  })
}

test('the human report keeps one line per finding whatever a record id contains', async () => {
  // The forging test: a line-feed arriving through a record id, a key name and
  // the trail's own name, with the human summary switched on.
  const human = await cliHuman(corpus(FORBIDDEN['C0 LF']), WITH_CHECKPOINT)

  const lines = human.stderr.split('\n').filter((line) => /^(ERROR|WARNING|INFO)\s/.test(line))
  assert.equal(human.report.findings.length > 0, true)
  assert.equal(lines.length, human.report.findings.length)

  const quiet = await cliReport(corpus(FORBIDDEN['C0 LF']), WITH_CHECKPOINT)
  const quietLines = quiet.stderr.split('\n').filter((line) => /^(ERROR|WARNING|INFO)\s/.test(line))
  assert.equal(quietLines.length, 0, '--json silences the human summary entirely')
})

test('an identifier carrying any of the four classes is refused, never repaired', () => {
  for (const character of Object.values(FORBIDDEN)) {
    assert.equal(isIdentifier(`evt${character}0001`), false)
  }
  assert.equal(isIdentifier('evt-0001'), true)
  assert.equal(isIdentifier('urn:acme:tenant/42'), true)
  assert.equal(isIdentifier(''), false)
  assert.equal(isIdentifier('a'.repeat(201)), false)
  assert.equal(isIdentifier('-leading'), false)
})

test('excerpt flattens whitespace, bounds length and strips every class', () => {
  assert.equal(excerpt('a\tb\nc'), 'a b c')
  assert.equal(excerpt(`a${FORBIDDEN['bidi RLO']}b`), 'a b')
  assert.equal(excerpt(`a${FORBIDDEN['C1 CSI']}b`), 'a b')
  assert.equal(excerpt('x'.repeat(200)), `${'x'.repeat(160)}...`)
  assert.equal(excerpt('x'.repeat(20), 10), `${'x'.repeat(10)}...`)
})

test('an unknown option carrying a control character is flattened before it is quoted', async () => {
  const { code, stdout, stderr } = await cliRun(['--root', '.', `--nonsense${FORBIDDEN['C0 ESC']}flag`])

  assert.equal(code, 2)
  assert.equal(stdout, '')
  for (const line of stderr.split('\n')) assert.equal(hasForbiddenCharacter(line), false)
})

test('a trail name carrying a bidi override is refused, and nothing from it is echoed', async () => {
  const document = cleanTrail()
  document.trail = `billing${FORBIDDEN['bidi RLO']}eu`

  const { report } = await cliReport({ [TRAIL_NAME]: document }, [])

  assert.equal(report.summary.trail, null)
  assert.equal(report.findings[0].location.pointer, '/trail')
  assert.equal(hasForbiddenCharacter(JSON.stringify(report)), false)
})
