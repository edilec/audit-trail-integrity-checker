import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdir, mkdtemp, readdir, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { checkAuditTrail, isInside } from '../src/index.mjs'
import {
  CHECKPOINT_NAME,
  TRAIL_NAME,
  WITH_CHECKPOINT,
  cleanFiles,
  cliReport,
  cliRun,
  raised,
  withRoot,
} from './support.mjs'

/**
 * Confinement, and the false refusals hardening tends to cause.
 *
 * Rejecting `..` and absolute paths is configuration hygiene, not confinement:
 * a symbolic link planted inside the root contains no `..` at all. Both sides
 * are resolved to their real paths and compared. Resolving only one side is the
 * other defect: on macOS a temporary directory is reached through a symbolic
 * link, so a tool that compares a real target against an unresolved root
 * refuses every legitimate run on that host.
 */

async function scratch(body) {
  const base = await mkdtemp(join(tmpdir(), 'audit-trail-confinement-'))
  try {
    return await body(base)
  } finally {
    await rm(base, { recursive: true, force: true })
  }
}

test('a root reached through a symbolic link is not refused', async () => {
  await scratch(async (base) => {
    const real = join(base, 'real')
    await mkdir(real)
    const files = cleanFiles()
    for (const [name, value] of Object.entries(files)) {
      await writeFile(join(real, name), `${JSON.stringify(value, null, 2)}\n`)
    }
    const link = join(base, 'link')
    await symlink(real, link)

    const report = await checkAuditTrail({ root: link, checkpoint: CHECKPOINT_NAME })

    assert.equal(report.status, 'pass')
  })
})

test('a symbolic link inside the root that points out of it is refused unread', async () => {
  await scratch(async (base) => {
    const outside = join(base, 'outside.json')
    await writeFile(outside, JSON.stringify({ schemaVersion: '1', trail: 'x', records: [] }))
    const root = join(base, 'root')
    await mkdir(root)
    await symlink(outside, join(root, TRAIL_NAME))

    const report = await checkAuditTrail({ root })

    assert.equal(report.status, 'incomplete')
    assert.equal(raised(report, 'path-escapes-root'), true)
    assert.equal(report.findings[0].location.file, TRAIL_NAME)
    // The refusal names the file and nothing from inside it.
    assert.equal(report.findings[0].message.includes('trail'), true)
  })
})

test('a checkpoint reached through a link out of the root is refused unread', async () => {
  await scratch(async (base) => {
    const outside = join(base, 'outside.json')
    await writeFile(outside, JSON.stringify({ schemaVersion: '1' }))
    const root = join(base, 'root')
    await mkdir(root)
    for (const [name, value] of Object.entries(cleanFiles())) {
      if (name === CHECKPOINT_NAME) continue
      await writeFile(join(root, name), `${JSON.stringify(value, null, 2)}\n`)
    }
    await symlink(outside, join(root, CHECKPOINT_NAME))

    const report = await checkAuditTrail({ root, checkpoint: CHECKPOINT_NAME })

    assert.equal(report.status, 'incomplete')
    assert.equal(raised(report, 'path-escapes-root'), true)
    assert.equal(report.coverage.tailDeletionDetectable, false)
  })
})

test('an absolute or climbing file name is a configuration error, not a finding', async () => {
  for (const name of ['/etc/hosts', '../trail.json', 'a/../../trail.json']) {
    await assert.rejects(() => checkAuditTrail({ root: '.', trail: name }), /--trail/)
  }
  for (const name of ['/etc/hosts', '../checkpoint.json']) {
    await assert.rejects(() => checkAuditTrail({ root: '.', checkpoint: name }), /--checkpoint/)
  }
})

test('a file name carrying a control character is refused before anything is read', async () => {
  await assert.rejects(
    () => checkAuditTrail({ root: '.', trail: `trail${String.fromCharCode(0x0a)}.json` }),
    /control, separator or bidi/,
  )
})

test('a root that is not a directory is a configuration error with an empty stdout', async () => {
  await withRoot(cleanFiles(), async (root) => {
    const { code, stdout, stderr } = await cliRun(['--root', join(root, TRAIL_NAME)])

    assert.equal(code, 2)
    assert.equal(stdout, '')
    assert.match(stderr, /--root must be a directory/)
  })
})

test('a directory where a file was expected is reported, not read', async () => {
  await scratch(async (base) => {
    await mkdir(join(base, TRAIL_NAME))

    const report = await checkAuditTrail({ root: base })

    assert.equal(report.status, 'incomplete')
    assert.equal(raised(report, 'input-unreadable'), true)
  })
})

test('the tool writes nothing: the root holds exactly what it held before', async () => {
  await withRoot(cleanFiles(), async (root) => {
    const before = (await readdir(root)).sort()
    await checkAuditTrail({ root, checkpoint: CHECKPOINT_NAME })
    const after = (await readdir(root)).sort()

    assert.deepEqual(after, before)
  })
})

test('isInside compares whole path segments, not string prefixes', () => {
  assert.equal(isInside('/a/root', '/a/root'), true)
  assert.equal(isInside('/a/root', '/a/root/trail.json'), true)
  assert.equal(isInside('/a/root', '/a/rootless/trail.json'), false)
  assert.equal(isInside('/a/root/', '/a/root/trail.json'), true)
})

test('the confined run still reports relative file names, never a host path', async () => {
  const { report } = await cliReport(cleanFiles(), [...WITH_CHECKPOINT, '--max-file-bytes', '32'])

  for (const finding of report.findings) {
    assert.equal(finding.location.file.startsWith('/'), false)
    assert.equal([TRAIL_NAME, CHECKPOINT_NAME].includes(finding.location.file), true)
  }
})
