import assert from 'node:assert/strict'
import test from 'node:test'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'

import { RULE_SEVERITY, byCodeUnit } from '../src/index.mjs'
import { projectDirectory } from './support.mjs'

/**
 * The table and the documented catalog, checked against each other in both
 * directions.
 *
 * This is worth having and it is **not** the test that defends severity. A
 * table and a catalog are two declarations, and one edit that changes both
 * leaves every assertion here satisfied. `test/severity-exit.test.mjs` and
 * `test/severity-word.test.mjs` pin the behaviour instead, with literal values
 * written where they are asserted.
 */

const CATALOG_ROW = /^\| `([a-z0-9-]+)` \| (error|warning|info) \|/

async function documentedRules() {
  const text = await readFile(join(projectDirectory, 'docs/integrity-rules.md'), 'utf8')
  const rows = new Map()
  for (const line of text.split('\n')) {
    const match = CATALOG_ROW.exec(line)
    if (match !== null) rows.set(match[1], match[2])
  }
  return rows
}

test('every rule in the table is documented with the same severity', async () => {
  const documented = await documentedRules()

  for (const [ruleId, severity] of Object.entries(RULE_SEVERITY)) {
    assert.equal(documented.get(ruleId), severity, `${ruleId} is documented as ${documented.get(ruleId)}`)
  }
})

test('every documented rule is in the table', async () => {
  const documented = await documentedRules()

  for (const ruleId of documented.keys()) {
    assert.equal(Object.hasOwn(RULE_SEVERITY, ruleId), true, `${ruleId} is documented and not in the table`)
  }
  assert.equal(documented.size, Object.keys(RULE_SEVERITY).length)
})

test('the table is frozen, ordered, and holds only known severities', () => {
  assert.equal(Object.isFrozen(RULE_SEVERITY), true)
  assert.deepEqual(Object.keys(RULE_SEVERITY), [...Object.keys(RULE_SEVERITY)].sort(byCodeUnit))
  for (const severity of Object.values(RULE_SEVERITY)) {
    assert.equal(['error', 'warning', 'info'].includes(severity), true)
  }
})

test('every rule id in the table is actually raised somewhere in the source', async () => {
  const sources = await Promise.all(
    ['src/index.mjs', 'src/chain.mjs', 'src/coverage.mjs', 'src/records.mjs']
      .map((name) => readFile(join(projectDirectory, name), 'utf8')),
  )
  const text = sources.join('\n')

  for (const ruleId of Object.keys(RULE_SEVERITY)) {
    assert.equal(text.includes(`ruleId: '${ruleId}'`), true, `${ruleId} is in the table and raised nowhere`)
  }
})
