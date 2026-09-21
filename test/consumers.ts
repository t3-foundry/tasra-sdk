// Actual npm installation plus browser/framework consumers of the packed artifact.
// Generated fixture projects live in a temporary directory, never in the source tree.
import {execFileSync, spawn} from 'node:child_process'
import {cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join, resolve} from 'node:path'
import {createServer} from 'node:http'
import {chromium, firefox, webkit} from 'playwright'

const root = resolve(import.meta.dirname, '..')
const scratch = mkdtempSync(join(tmpdir(), 'tasra-consumers-'))
const env = {...process.env, NEXT_TELEMETRY_DISABLED: '1'}
const browserFailures: string[] = []
function run(cmd: string, args: string[], cwd = scratch) {
  execFileSync(cmd, args, {cwd, env, stdio: 'inherit', timeout: 240_000})
}
function write(name: string, value: string) { writeFileSync(join(scratch, name), value) }
function version(name: string): string {
  return (JSON.parse(readFileSync(join(root, 'node_modules', name, 'package.json'), 'utf8')) as {version: string}).version
}

try {
  run('npm', ['pack', '--pack-destination', scratch, '--loglevel', 'error'], root)
  const tarball = readdirSync(scratch).find(name => name.endsWith('.tgz'))!
  write('package.json', JSON.stringify({name: 'tasra-consumer', private: true, type: 'module'}))
  run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', join(scratch, tarball)])
  // Verify an ordinary core-only installation does not acquire the optional peer.
  if (existsSync(join(scratch, 'node_modules/viem/package.json'))) throw new Error('Core install acquired viem')
  cpSync(join(scratch, 'node_modules/tasra-sdk/examples'), join(scratch, 'examples'), {recursive: true})
  run(process.execPath, ['--import', join(root, 'node_modules/tsx/dist/loader.mjs'), 'examples/minimal.ts'])
  // Execute exactly the complete offline snippet advertised in the README.
  const readme = readFileSync(join(root, 'README.md'), 'utf8')
  const snippet = readme.match(/<!-- offline-example -->\s*```ts\n([\s\S]*?)```/)
  if (!snippet) throw new Error('Runnable README example is missing')
  write('readme.ts', snippet[1]!)
  run(process.execPath, ['--import', join(root, 'node_modules/tsx/dist/loader.mjs'), 'readme.ts'])

  const tooling = ['typescript', 'tsx', 'viem', 'vite', 'webpack', 'next', 'react', 'react-dom', '@types/react', '@types/react-dom', '@types/node']
  run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', ...tooling.map(name => `${name}@${version(name)}`)])
  const imports = `import * as core from 'tasra-sdk';
import * as chain from 'tasra-sdk/chain';
import * as committee from 'tasra-sdk/committee';
import * as oid4vp from 'tasra-sdk/oid4vp';
import * as agent from 'tasra-sdk/verifier-agent';`
  write('types.ts', `${imports}
const client: core.TasraClient = core.createTasraClient({nodes: ['https://example.invalid']});
console.log(client, chain.createTasraChainClient, committee.verifyCompoundToken, oid4vp, agent.createOid4vpSession);`)
  write('tsconfig.json', JSON.stringify({compilerOptions: {target: 'ES2022', module: 'ESNext', moduleResolution: 'Bundler', lib: ['ES2022', 'DOM'], types: [], strict: true, noEmit: true, skipLibCheck: false}, files: ['types.ts']}))
  run(process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'tsconfig.json'])

  write('browser.ts', `${imports}
import {offlineRoundTrip} from './examples/offline.ts';
async function main() {
  await core.createDpopKey();
  if (typeof globalThis.Buffer !== 'undefined') throw new Error('Unexpected Buffer polyfill');
  if (offlineRoundTrip() !== 'Hello Tasra') throw new Error('Crypto round trip failed');
  document.body.textContent = 'Hello Tasra';
  console.log(chain.createTasraChainClient, committee.verifyCompoundToken, oid4vp, agent.createOid4vpSession);
}
main().catch(e => { document.body.textContent = String(e); throw e; });`)
  write('index.html', '<!doctype html><html><body><script type="module" src="/browser.ts"></script></body></html>')
  run(process.execPath, ['node_modules/vite/bin/vite.js', 'build'])
  // No fallback/polyfill configuration: Node imports must fail a web build.
  // This fixture retains EVERY export, so ordinary application size hints do not apply.
  write('webpack-entry.js', `${imports}
window.sdk = {core, chain, committee, oid4vp, agent};`)
  write('webpack-build.mjs', `import webpack from 'webpack';
webpack({mode:'production',target:'web',performance:false,entry:process.cwd()+'/webpack-entry.js',output:{path:process.cwd()+'/webpack-dist',filename:'bundle.js'}}, (err, stats) => {
  if (err || stats.hasErrors() || stats.hasWarnings()) { console.error(err || stats.toString()); process.exitCode=1; }
});`)
  run(process.execPath, ['webpack-build.mjs'])

  const server = createServer((request, response) => {
    const path = new URL(request.url!, 'http://localhost').pathname
    const file = resolve(scratch, 'dist', `.${path === '/' ? '/index.html' : path}`)
    if (!file.startsWith(join(scratch, 'dist') + '/')) { response.writeHead(403).end(); return }
    try {
      response.setHeader('content-type', file.endsWith('.js') ? 'application/javascript' : 'text/html')
      response.end(readFileSync(file))
    } catch { response.writeHead(404).end() }
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  try {
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('Missing test port')
    for (const engine of [chromium, firefox, webkit]) {
      try {
        const browser = await engine.launch()
        try {
          const page = await browser.newPage()
          const errors: string[] = []
          page.on('pageerror', error => errors.push(error.message))
          await page.goto(`http://127.0.0.1:${address.port}`)
          await page.waitForFunction(() => document.body.textContent === 'Hello Tasra')
          if (errors.length) throw new Error(errors.join('\n'))
          console.log(`${engine.name()}: crypto and WebCrypto passed`)
        } finally { await browser.close() }
      } catch (error) {
        browserFailures.push(`${engine.name()}: ${String(error)}`)
        console.error(`${engine.name()} failed; continuing to check the remaining consumers`)
      }
    }
  } finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())) }

  const nextRoot = join(scratch, 'next-app')
  mkdirSync(join(nextRoot, 'app'), {recursive: true})
  write('next-app/package.json', JSON.stringify({name: 'tasra-next-consumer', private: true, type: 'module'}))
  write('next-app/app/layout.jsx', 'export default function Layout({children}) { return <html><body>{children}</body></html> }')
  write('next-app/app/client.jsx', `'use client';
import {useEffect, useState} from 'react';
import {createDpopKey, createTasraClient} from 'tasra-sdk';
export default function Client() {
  const [status, setStatus] = useState('pending');
  useEffect(() => { createDpopKey().then(() => setStatus(typeof createTasraClient)).catch(() => setStatus('failed')); }, []);
  return <p id="client">{status}</p>;
}`)
  write('next-app/app/page.jsx', `import Client from './client';
import {createTasraClient} from 'tasra-sdk';
import {createTasraChainClient} from 'tasra-sdk/chain';
import {createNodeServiceDiscoveryTransport} from 'tasra-sdk/chain/node';
export default function Page() {
  if ([createTasraClient, createTasraChainClient, createNodeServiceDiscoveryTransport].some(v => typeof v !== 'function')) throw new Error('Missing server exports');
  return <main>Server imports passed<Client /></main>;
}`)
  write('next-app/next.config.mjs', 'export default {experimental: {cpus: 2}}')
  // Use a separate config: Next owns its generated TypeScript configuration.
  rmSync(join(scratch, 'tsconfig.json'))
  run(process.execPath, [join(scratch, 'node_modules/next/dist/bin/next'), 'build', '--webpack'], nextRoot)
  const next = spawn(process.execPath, [join(scratch, 'node_modules/next/dist/bin/next'), 'start', '--hostname', '127.0.0.1', '--port', '0'], {cwd: nextRoot, env, stdio: ['ignore', 'pipe', 'pipe']})
  try {
    const url = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Next startup timed out')), 30_000)
      const parse = (chunk: Buffer) => {
        const match = chunk.toString().match(/http:\/\/127\.0\.0\.1:(\d+)/)
        if (match) { clearTimeout(timer); resolve(match[0]) }
      }
      next.stdout.on('data', parse)
      next.stderr.on('data', parse)
      next.once('error', error => { clearTimeout(timer); reject(error) })
      next.once('exit', code => { clearTimeout(timer); reject(new Error(`Next exited: ${code}`)) })
    })
    const browser = await chromium.launch()
    try {
      const page = await browser.newPage()
      await page.goto(url)
      await page.waitForFunction(() => document.querySelector('#client')?.textContent === 'function')
      if (!(await page.content()).includes('Server imports passed')) throw new Error('Server render missing')
    } finally { await browser.close() }
  } finally {
    if (next.exitCode === null) {
      next.kill('SIGTERM')
      await new Promise<void>(resolve => next.once('exit', () => resolve()))
    }
  }
  console.log('Next.js server render and client hydration passed')
  if (browserFailures.length) throw new Error(browserFailures.join('\n'))
  console.log('Packed package: core install, README, types, Vite, Webpack, three browsers, and Next.js passed')
} finally {
  rmSync(scratch, {recursive: true, force: true})
}
