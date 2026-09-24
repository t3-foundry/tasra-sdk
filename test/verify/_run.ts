// Shared plumbing for the verify orchestrator: child-process running with live
// output + metric capture, path discovery, and the StepResult shape the reporter
// consumes. No mocks — every step shells out to the real tool (npm/cargo/docker/
// bash) and we record its real exit code, wall time, and any ::metric:: lines.

import {spawn} from 'node:child_process'
import {existsSync, readFileSync} from 'node:fs'
import {dirname, resolve} from 'node:path'
import {fileURLToPath} from 'node:url'
import {loadFleetConfig, type FleetConfig} from '../fleet/_fleet.ts'

const here = dirname(fileURLToPath(import.meta.url)) // .../tasra-sdk/test/verify
export const sdkRoot = resolve(here, '..', '..')
// ⚠ THIS SDK IS NO LONGER A SIBLING OF THE NETWORK REPO. It moved to t3-foundry/ in 2026-09
// while keykeeper-network and keykeeper-explorer stayed under managination/, so `../<name>`
// resolves to a directory that does not exist. certify always passes KK_NETWORK_DIR and
// KK_EXPLORER_DIR explicitly, so these defaults matter only for a hand-run `verify:all` --
// which is exactly the case a stale default breaks silently.
const SIBLING_ORG = resolve(sdkRoot, '..', '..', 'managination')
export const networkDir = process.env.KK_NETWORK_DIR ?? resolve(SIBLING_ORG, 'keykeeper-network')
export const explorerDir = process.env.KK_EXPLORER_DIR ?? resolve(SIBLING_ORG, 'keykeeper-explorer')
export const outDir = resolve(here, 'out')

/**
 * The fleet config, which republishes `chain.env` into the environment itself (see
 * `test/fleet/_fleet.ts::hydrateFleetEnv`). Re-exported under the harness's own name because
 * every read here happens mid-provisioning, when the file may only just have appeared.
 */
export const fleetConfig = loadFleetConfig

// `chainEnvPath` is defined by the fleet config and re-exported here for the harness.
export {chainEnvPath} from '../fleet/_fleet.ts'

export interface Metric {
  name: string
  value: number
  unit?: string
  [k: string]: string | number | undefined
}
export type StepStatus = 'pass' | 'fail' | 'skip'
export interface StepResult {
  phase: string
  name: string
  status: StepStatus
  ms: number
  metrics: Metric[]
  detail?: string
  optional?: boolean
}

export interface ShResult {
  code: number | null
  spawnError?: string
  ms: number
  metrics: Metric[]
  tail: string
  passedTests: number
}

const C = {grey: '\x1b[2m', cyan: '\x1b[1;36m', red: '\x1b[0;31m', grn: '\x1b[0;32m', yel: '\x1b[0;33m', rst: '\x1b[0m'}
export const log = (m: string) => console.log(m)
export const banner = (m: string) => console.log(`\n${C.cyan}━━━ ${m} ━━━${C.rst}`)

const METRIC_RE = /^::metric:: (.+)$/

/** Run a command, streaming its output live while capturing stdout for metrics. */
export function sh(
  cmd: string,
  args: string[],
  opts: {cwd?: string; env?: Record<string, string>; timeoutMs?: number; quiet?: boolean} = {},
): Promise<ShResult> {
  return new Promise(res => {
    const t0 = Date.now()
    const metrics: Metric[] = []
    let stdoutBuf = ''
    let tail = ''
    let passedTests = 0
    let child: ReturnType<typeof spawn>
    try {
      child = spawn(cmd, args, {
        cwd: opts.cwd,
        env: {...process.env, ...opts.env},
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch (e) {
      return res({code: null, spawnError: String((e as Error).message), ms: Date.now() - t0, metrics, tail: '', passedTests})
    }

    let timer: NodeJS.Timeout | undefined
    if (opts.timeoutMs) {
      timer = setTimeout(() => {
        tail += `\n[verify] timeout after ${opts.timeoutMs}ms — killing\n`
        child.kill('SIGKILL')
      }, opts.timeoutMs)
    }

    const onChunk = (buf: Buffer, toStream: NodeJS.WriteStream) => {
      const text = buf.toString()
      if (!opts.quiet) toStream.write(text)
      stdoutBuf += text
      tail = (tail + text).slice(-4000)
      let nl: number
      while ((nl = stdoutBuf.indexOf('\n')) >= 0) {
        const line = stdoutBuf.slice(0, nl)
        stdoutBuf = stdoutBuf.slice(nl + 1)
        const result = /test result: ok\. (\d+) passed/.exec(line)
        if (result) passedTests += Number(result[1])
        const m = METRIC_RE.exec(line)
        if (m) {
          try {
            metrics.push(JSON.parse(m[1]!) as Metric)
          } catch {
            /* ignore malformed metric line */
          }
        }
      }
    }
    child.stdout?.on('data', b => onChunk(b, process.stdout))
    child.stderr?.on('data', b => onChunk(b, process.stderr))

    child.on('error', e => {
      if (timer) clearTimeout(timer)
      res({code: null, spawnError: String(e.message), ms: Date.now() - t0, metrics, tail, passedTests})
    })
    child.on('close', code => {
      if (timer) clearTimeout(timer)
      res({code, ms: Date.now() - t0, metrics, tail, passedTests})
    })
  })
}

export interface StepSpec {
  name: string
  cmd: string
  args: string[]
  cwd?: string
  env?: Record<string, string>
  timeoutMs?: number
  /** A step that may legitimately be skipped (missing prereq) without failing the run. */
  optional?: boolean
  /** Suppress live output (capture only). Used for steps run concurrently, so their
   *  streams don't interleave into noise; the start banner + pass/fail line still print,
   *  and a failure's captured tail is still surfaced in the report. */
  quiet?: boolean
  /** Fail-closed floor on executed tests: sum every `test result: ... N passed` in the
   *  output and refuse a "pass" below this. Guards the vacuous-green trap: a cargo
   *  suite whose tests are all #[ignore]d (or feature-gated away) exits 0 having run
   *  NOTHING - observed live when the accountant anvil suites "passed" in 0.8s. */
  minPassedTests?: number
}

/** Run one StepSpec → StepResult. spawn failure (missing tool) on an optional step = skip. */
export async function runStep(phase: string, spec: StepSpec): Promise<StepResult> {
  banner(`${phase} · ${spec.name}${spec.quiet ? ' (running concurrently…)' : ''}`)
  const r = await sh(spec.cmd, spec.args, {cwd: spec.cwd, env: spec.env, timeoutMs: spec.timeoutMs, quiet: spec.quiet})
  if (r.spawnError) {
    const status: StepStatus = spec.optional ? 'skip' : 'fail'
    log(`${status === 'skip' ? C.yel : C.red}[${status}] ${spec.name}: ${r.spawnError}${C.rst}`)
    return {phase, name: spec.name, status, ms: r.ms, metrics: r.metrics, detail: r.spawnError, optional: spec.optional}
  }
  let status: StepStatus = r.code === 0 ? 'pass' : 'fail'
  let detail: string | undefined
  if (status === 'pass' && spec.minPassedTests) {
    const passed = r.passedTests
    if (passed < spec.minPassedTests) {
      status = 'fail'
      detail = `exit 0 but only ${passed} tests ran (floor ${spec.minPassedTests}) - vacuous pass (all #[ignore]d? feature-gated out?)`
    }
  }
  const mark = status === 'pass' ? `${C.grn}✓` : `${C.red}✗`
  log(`${mark} ${spec.name} (exit ${r.code}, ${(r.ms / 1000).toFixed(1)}s)${detail ? ` ${C.red}${detail}${C.rst}` : ''}${C.rst}`)
  return {phase, name: spec.name, status, ms: r.ms, metrics: r.metrics, detail: detail ?? (status === 'fail' ? r.tail.slice(-600) : undefined), optional: spec.optional}
}

/** Is `cmd` runnable? Used to gate optional toolchains (forge, cargo, docker). */
export async function have(cmd: string): Promise<boolean> {
  if (process.platform === 'win32') return (await sh('where', [cmd], {quiet: true})).code === 0
  return (await sh('sh', ['-c', `command -v ${cmd}`], {quiet: true})).code === 0
}
