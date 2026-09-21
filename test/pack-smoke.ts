// Offline pack smoke test. test/consumers.ts also exercises a real npm install.
//
// Most hermetic suites import `../src/**/*.ts` directly through tsx,
// so nothing verifies that `dist/` resolves, that the `exports` map is correct,
// or that a consumer can actually `import 'tasra-sdk'`. Packaging bugs are
// invisible until someone installs the tarball.
//
// This packs the real tarball, lays it out as a consumer's node_modules would
// see it, and resolves every subpath through the `exports` map — ESM and CJS.
//
// Offline by design: instead of `npm install <tarball>` (which would hit the
// registry for @noble/* and viem), the tarball is extracted into a scratch
// node_modules and the runtime deps are symlinked from this repo's own tree.
// Resolution walks up from the package to the scratch node_modules exactly as
// it would for a real install, so the exports map is genuinely under test.

import {execFileSync} from 'node:child_process'
import {mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {dirname, join, resolve} from 'node:path'
import {fileURLToPath} from 'node:url'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const pkg = JSON.parse(
  execFileSync('node', ['-e', 'process.stdout.write(require("fs").readFileSync("package.json","utf8"))'], {
    cwd: repoRoot,
    encoding: 'utf8',
  }),
) as {
  name: string
  dependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
}

// viem is an OPTIONAL PEER dependency: a core-only consumer never installs it,
// but `tasra-sdk/chain` needs it, so the scratch consumer must provide it the
// way a real chain consumer would. Link peers alongside real deps.
const linkedDeps = [
  ...Object.keys(pkg.dependencies ?? {}),
  ...Object.keys(pkg.peerDependencies ?? {}),
]

let passed = 0
const failures: string[] = []
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) {
    passed++
    console.log(`  ✓ ${label}`)
  } else {
    failures.push(detail ? `${label} — ${detail}` : label)
    console.log(`  ✗ ${label}${detail ? ` — ${detail}` : ''}`)
  }
}

// Run a snippet inside the scratch consumer and return its stdout. Returns null
// (and prints the stderr tail) when node exits non-zero, so a resolution failure
// reads as a failed check rather than a crashed harness.
function runInConsumer(dir: string, ext: 'mjs' | 'cjs', code: string): string | null {
  const file = join(dir, `probe.${ext}`)
  writeFileSync(file, code)
  try {
    return execFileSync(process.execPath, [file], {cwd: dir, encoding: 'utf8'}).trim()
  } catch (e) {
    const err = e as {stderr?: string; message?: string}
    const detail = (err.stderr || err.message || '').trim().split('\n').slice(-3).join(' | ')
    console.log(`    node ${ext} probe failed: ${detail}`)
    return null
  }
}

const scratch = mkdtempSync(join(tmpdir(), 'kk-pack-smoke-'))
try {
  // 1. Pack. `npm pack` runs prepack/prepare, so this builds dist/ from source.
  console.log('packing…')
  execFileSync('npm', ['pack', '--pack-destination', scratch, '--loglevel', 'error'], {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  const tarball = readdirSync(scratch).find(f => f.endsWith('.tgz'))
  if (!tarball) throw new Error(`npm pack produced no .tgz in ${scratch}`)
  const packedNames = execFileSync('tar', ['-tzf', join(scratch, tarball)], {encoding: 'utf8'}).trim().split('\n')
  ok('tarball contains no private source or source maps', !packedNames.some(p => p.startsWith('package/src/') || p.endsWith('.map')))
  ok('tarball contains all 11 agent skills', packedNames.filter(p => p.endsWith('/SKILL.md')).length === 11)
  for (const skill of packedNames.filter(p => p.endsWith('/SKILL.md'))) {
    const content = execFileSync('tar', ['-xOzf', join(scratch, tarball), skill], {encoding: 'utf8'})
    const references = [...content.matchAll(/^ {4}- (.+)$/gm)].map(m => m[1]!.split('#')[0]!)
    ok(`${skill}: metadata references are available in the installed package`, references.every(p => /^https?:/.test(p) || packedNames.includes(`package/${p}`)))
  }

  // 2. Lay out a consumer: node_modules/<name>/ ← tarball, deps symlinked.
  const consumer = join(scratch, 'consumer')
  const nodeModules = join(consumer, 'node_modules')
  const installed = join(nodeModules, pkg.name)
  mkdirSync(installed, {recursive: true})
  writeFileSync(
    join(consumer, 'package.json'),
    JSON.stringify({name: 'pack-smoke-consumer', private: true, type: 'module'}, null, 2),
  )
  // --strip-components=1 drops the tarball's leading `package/` directory.
  execFileSync('tar', ['-xzf', join(scratch, tarball), '-C', installed, '--strip-components=1'])

  for (const dep of linkedDeps) {
    const target = join(repoRoot, 'node_modules', dep)
    const link = join(nodeModules, dep)
    mkdirSync(dirname(link), {recursive: true}) // scoped deps need @scope/ first
    symlinkSync(target, link, 'dir')
  }

  // 3. Resolve through the exports map.
  console.log('resolving…')

  for (const subpath of ['', '/chain', '/chain/node', '/committee', '/oid4vp', '/verifier-agent']) {
    const specifier = `${pkg.name}${subpath}`
    ok(`ESM: ${specifier}`, runInConsumer(consumer, 'mjs', `import * as sdk from '${specifier}'; console.log(Object.keys(sdk).length)`) !== null)
    ok(`CJS: ${specifier}`, runInConsumer(consumer, 'cjs', `console.log(Object.keys(require('${specifier}')).length)`) !== null)
  }

  const esmMain = runInConsumer(
    consumer,
    'mjs',
    `import * as m from '${pkg.name}'
     if (typeof m.createTasraClient !== 'function') throw new Error('createTasraClient missing')
     console.log(Object.keys(m).length)`,
  )
  ok('ESM: import "tasra-sdk" resolves and exports createTasraClient', esmMain !== null)
  if (esmMain !== null) {
    ok(`ESM: main entry exports ${esmMain} symbols`, Number(esmMain) > 0)
  }

  const esmChain = runInConsumer(
    consumer,
    'mjs',
    `import * as m from '${pkg.name}/chain'
     if (typeof m.createTasraChainClient !== 'function') throw new Error('createTasraChainClient missing')
     console.log(Object.keys(m).length)`,
  )
  ok('ESM: import "tasra-sdk/chain" resolves and exports createTasraChainClient', esmChain !== null)
  if (esmChain !== null) {
    ok(`ESM: chain entry exports ${esmChain} symbols`, Number(esmChain) > 0)
  }

  const esmChainNode = runInConsumer(
    consumer, 'mjs',
    `import {createNodeServiceDiscoveryTransport} from '${pkg.name}/chain/node'
     if (typeof createNodeServiceDiscoveryTransport !== 'function') throw new Error('service transport missing')`,
  )
  ok('ESM: Node service discovery transport resolves from chain/node', esmChainNode !== null)

  const esmCommittee = runInConsumer(
    consumer,
    'mjs',
    `import * as m from '${pkg.name}/committee'
     if (typeof m.verifyCompoundToken !== 'function') throw new Error('verifyCompoundToken missing')
     console.log(Object.keys(m).length)`,
  )
  ok('ESM: import "tasra-sdk/committee" resolves and exports verifyCompoundToken', esmCommittee !== null)
  if (esmCommittee !== null) {
    ok(`ESM: committee entry exports ${esmCommittee} symbols`, Number(esmCommittee) > 0)
  }

  const esmRp = runInConsumer(
    consumer,
    'mjs',
    `import * as m from '${pkg.name}/verifier-agent'
     if (typeof m.createOid4vpSession !== 'function') throw new Error('createOid4vpSession missing')
     console.log(Object.keys(m).length)`,
  )
  ok('ESM: import "tasra-sdk/verifier-agent" resolves and exports createOid4vpSession', esmRp !== null)
  if (esmRp !== null) {
    ok(`ESM: verifierAgent entry exports ${esmRp} symbols`, Number(esmRp) > 0)
  }

  // The `default` condition is what makes this work: the package is ESM-only,
  // and Node >= 22.12 can require() an ES module — but only if the
  // exports map offers a condition other than `import` to resolve. Without it
  // this fails with ERR_PACKAGE_PATH_NOT_EXPORTED even on a new Node.
  const [major = 0, minor = 0] = process.versions.node.split('.').map(Number)
  const requireEsmSupported = major > 22 || (major === 22 && minor >= 12)
  if (requireEsmSupported) {
    const cjs = runInConsumer(
      consumer,
      'cjs',
      `const m = require('${pkg.name}')
       if (typeof m.createTasraClient !== 'function') throw new Error('createTasraClient missing')
       console.log('ok')`,
    )
    ok('CJS: require("tasra-sdk") works on Node >= 22.12 (the `default` condition)', cjs === 'ok')
  } else {
    console.log(`  – skipped require(esm) check: Node ${process.versions.node} < 22.12`)
  }

  // Tooling (bundler plugins, version sniffers, attw) probes this path directly.
  const pkgJson = runInConsumer(
    consumer,
    'cjs',
    `console.log(require('${pkg.name}/package.json').name)`,
  )
  ok('require.resolve("tasra-sdk/package.json") works', pkgJson === pkg.name)

  // Types ship alongside, and a consumer under NodeNext must find them.
  const types = runInConsumer(
    consumer,
    'cjs',
    `const {existsSync} = require('fs'), {join, dirname} = require('path')
     const root = dirname(require.resolve('${pkg.name}/package.json'))
     console.log([
       existsSync(join(root, 'dist/index.d.ts')),
       existsSync(join(root, 'dist/chain/index.d.ts')),
       existsSync(join(root, 'dist/verifier-agent/index.d.ts')),
       existsSync(join(root, 'src/index.ts')),
       existsSync(join(root, 'skills/tasra-getting-started/SKILL.md')),
     ].join(','))`,
  )
  ok(
    'tarball ships declarations and skills without private TypeScript sources',
    types === 'true,true,true,false,true',
    types ?? undefined,
  )

  // ── The optional-peer claim, actually tested ────────────────────────────────
  // The README says viem is only needed when you import `tasra-sdk/chain`.
  // That is only true if the MAIN entry loads with viem absent from the tree —
  // one stray top-level `import {…} from 'viem'` reachable from src/index.ts
  // would break every core-only consumer, and no other test would notice.
  const peerNames = Object.keys(pkg.peerDependencies ?? {})
  if (peerNames.length > 0) {
    const coreOnly = join(scratch, 'core-only')
    const coreModules = join(coreOnly, 'node_modules')
    const coreInstalled = join(coreModules, pkg.name)
    mkdirSync(coreInstalled, {recursive: true})
    writeFileSync(
      join(coreOnly, 'package.json'),
      JSON.stringify({name: 'core-only-consumer', private: true, type: 'module'}, null, 2),
    )
    execFileSync('tar', ['-xzf', join(scratch, tarball), '-C', coreInstalled, '--strip-components=1'])
    // Link the hard deps ONLY — deliberately omit the optional peers.
    for (const dep of Object.keys(pkg.dependencies ?? {})) {
      const link = join(coreModules, dep)
      mkdirSync(dirname(link), {recursive: true})
      symlinkSync(join(repoRoot, 'node_modules', dep), link, 'dir')
    }

    const coreWithoutPeers = runInConsumer(
      coreOnly,
      'mjs',
      `import * as m from '${pkg.name}'
       if (typeof m.createTasraClient !== 'function') throw new Error('createTasraClient missing')
       console.log('ok')`,
    )
    ok(
      `main entry loads with optional peers absent (${peerNames.join(', ')})`,
      coreWithoutPeers === 'ok',
    )

    // And the converse: /chain SHOULD fail there, which is what makes viem a
    // genuine requirement for that subpath rather than an accidental one.
    const chainWithoutPeers = runInConsumer(
      coreOnly,
      'mjs',
      `import('${pkg.name}/chain').then(() => console.log('resolved'), () => console.log('failed'))`,
    )
    ok('/chain requires the peer, as documented', chainWithoutPeers === 'failed')
  }
} finally {
  rmSync(scratch, {recursive: true, force: true})
}

if (failures.length) {
  console.error(`\npack-smoke FAILED (${failures.length}):`)
  for (const f of failures) console.error('  ✗', f)
  process.exit(1)
}
console.log(`\npack-smoke: ${passed} checks passed`)
