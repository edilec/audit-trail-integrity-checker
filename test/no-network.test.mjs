import assert from 'node:assert/strict'
import test from 'node:test'
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'

import { projectDirectory } from './support.mjs'

/**
 * This package talks to nobody and writes nothing.
 *
 * A source scan is a weak instrument and it is used here for what it is good
 * at: catching the accidental reintroduction of a networking or writing import
 * in a package that should have neither. The behavioural half lives elsewhere
 * -- `test/confinement.test.mjs` asserts the input root is byte-for-byte
 * unchanged after a run, which is what "writes nothing" actually means.
 */

const FORBIDDEN_IMPORTS = Object.freeze([
  'node:net', 'node:http', 'node:https', 'node:http2', 'node:dgram', 'node:tls',
  'node:dns', 'node:worker_threads', 'node:child_process', 'node:vm', 'node:repl',
])

const FORBIDDEN_CALLS = Object.freeze([
  'fetch(', 'XMLHttpRequest', 'WebSocket', 'navigator.', 'process.env',
])

/** The writing half of `node:fs/promises`. Reading is the whole job; writing is not part of it. */
const FORBIDDEN_FS = Object.freeze([
  'writeFile', 'appendFile', 'mkdir(', 'rm(', 'rmdir', 'unlink', 'rename', 'copyFile',
  'truncate(', 'createWriteStream', 'chmod', 'chown', 'utimes', 'fs.link', 'symlink(',
])

/**
 * Strip the prose before scanning the code.
 *
 * Every module here documents what it deliberately does not do, in those words
 * -- "no `Date.now`", "records removed from the end", "truncation" -- so a scan
 * of the raw text finds the promise rather than a violation of it. Block
 * comments and whole-line `//` comments are removed; a `//` inside a string or
 * a regular expression is left alone, because it never starts a line.
 */
function code(text) {
  return text
    .replaceAll(/\/\*[\s\S]*?\*\//g, ' ')
    .split('\n')
    .filter((line) => !/^\s*\/\//.test(line))
    .join('\n')
}

async function sources() {
  const directory = join(projectDirectory, 'src')
  const names = (await readdir(directory)).filter((name) => name.endsWith('.mjs')).sort()
  const files = []
  for (const name of names) files.push([name, code(await readFile(join(directory, name), 'utf8'))])
  files.push(['bin', code(await readFile(join(projectDirectory, 'bin/audit-trail-integrity-checker.mjs'), 'utf8'))])
  return files
}

test('no module in this package imports a network or process facility', async () => {
  for (const [name, text] of await sources()) {
    for (const module of FORBIDDEN_IMPORTS) {
      assert.equal(text.includes(`'${module}'`), false, `${name} imports ${module}`)
    }
  }
})

test('no module in this package reaches for a network client or the environment', async () => {
  for (const [name, text] of await sources()) {
    for (const call of FORBIDDEN_CALLS) {
      assert.equal(text.includes(call), false, `${name} uses ${call}`)
    }
  }
})

test('no module in this package writes to the filesystem', async () => {
  for (const [name, text] of await sources()) {
    for (const call of FORBIDDEN_FS) {
      assert.equal(text.includes(call), false, `${name} uses ${call}`)
    }
  }
})

test('nothing in this package reads a clock or a locale', async () => {
  for (const [name, text] of await sources()) {
    assert.equal(text.includes('Date.now'), false, `${name} reads a wall clock`)
    assert.equal(text.includes('new Date'), false, `${name} constructs a Date`)
    assert.equal(text.includes('Math.random'), false, `${name} uses a random source`)
    assert.equal(text.includes('localeCompare'), false, `${name} orders by locale`)
    assert.equal(text.includes('Intl.'), false, `${name} orders by locale`)
    assert.equal(text.includes('toLocale'), false, `${name} formats by locale`)
  }
})

test('the package declares no dependency of any kind', async () => {
  const manifest = JSON.parse(await readFile(join(projectDirectory, 'package.json'), 'utf8'))

  assert.equal(manifest.dependencies, undefined)
  assert.equal(manifest.devDependencies, undefined)
  assert.equal(manifest.peerDependencies, undefined)
  assert.equal(manifest.optionalDependencies, undefined)
})
