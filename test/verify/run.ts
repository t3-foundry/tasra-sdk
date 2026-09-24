// VERIFY · the one command. Brings up the real production-mode stack, runs the
// real economic onboarding, then sweeps correctness + performance + destructive
// across nodes / accountants / verifiers / SDK / explorer, and writes ONE
// consolidated report. No mocks: every step shells out to the real tool against
// the real fleet.
//
//   npm run verify:all
//
// PERFORMANCE MODEL (why this isn't one long serial list):
// Steps fall into two tracks that share NOTHING at runtime, so they run
// CONCURRENTLY:
//   • fleet-INDEPENDENT — the Rust anvil protocol tests (each spawns its OWN
//     ephemeral-port anvil) + the cargo crypto perf profiles + the in-process
//     crypto-throughput stress. None of these touch the demo fleet or its Besu.
//   • fleet-DEPENDENT — bootstrap onboarding, the SDK black-box suites,
//     key-op/slot load, and the destructive slashing demos. These all hit the
//     ONE fleet + chain, so they stay SERIAL relative to each other (concurrent
//     slot creation / load would contend and flake), and destructive runs LAST.
// Within the fleet-independent track the Rust anvil tests also run in parallel
// (capped) among themselves. Net: wall-clock ≈ max(two tracks) instead of their
// sum — roughly halves a clean run. Tune the Rust fan-out with KK_VERIFY_RUST_PAR
// (default 4) if the box is CPU-starved and the fleet times out under load.
//
// Env knobs (all default ON for verify:all):
//   KK_VERIFY_WIPE=1      clean slate — fleet-wipe (fresh Besu + contracts + DKG) before bring-up
//   KK_VERIFY_BRINGUP=0   reuse an already-running fleet (skip make fleet-up)
//   KK_VERIFY_PERF=0      skip the performance phase
//   KK_VERIFY_DESTRUCTIVE=0  skip the destructive (slashing/nuke) phase
//   KK_VERIFY_BENCH=1     also run criterion crypto micro-benchmarks (slow)
//   KK_VERIFY_RUST_PAR=N  max concurrent Rust anvil tests (default 4)
//   KK_KEEP=1             leave the stack up at the end (no teardown)

import os from 'node:os'
import {bringUp, tearDown} from './bringup.ts'
import {banner, have, log, networkDir, runStep, sdkRoot, type StepResult, type StepSpec} from './_run.ts'
import {writeReport} from './report.ts'

const off = (v: string | undefined) => v === '0' || v === 'false'
const on = (v: string | undefined) => v === '1' || v === 'true'
const DO_BRINGUP = !off(process.env.KK_VERIFY_BRINGUP)
const DO_BOOTSTRAP = !off(process.env.KK_VERIFY_BOOTSTRAP)
const DO_CORRECTNESS = !off(process.env.KK_VERIFY_CORRECTNESS)
const DO_RUST = !off(process.env.KK_VERIFY_RUST) // the (slow) in-process Rust anvil protocol tests
const DO_PERF = !off(process.env.KK_VERIFY_PERF)
const DO_DESTRUCTIVE = !off(process.env.KK_VERIFY_DESTRUCTIVE)
const DO_BENCH = on(process.env.KK_VERIFY_BENCH)
const KEEP = on(process.env.KK_KEEP)
const RUST_PAR = Math.max(1, Number(process.env.KK_VERIFY_RUST_PAR ?? '2') || 2)

// SDK live-fleet suites must fail RED when the fleet is down (no silent skip).
const FLEET = {KK_FLEET_REQUIRED:'1',KK_CERTIFICATION_REQUIRED:'1'}
const npm = (script: string): StepSpec => ({name: script, cmd: 'npm', args: ['run', '--silent', script], cwd: sdkRoot, env: FLEET})
// NB: NOT optional — the whole Rust block is gated by haveCargo/haveForge, so a
// step that actually RUNS and fails is a real regression and must count red.
// --include-ignored: the anvil suites mark their tests #[ignore] (they need forge+anvil,
// which this phase guarantees) - without it cargo runs ZERO tests and exits 0, and the
// accountant suites "passed" in under a second for at least two certs. minPassedTests
// turns any such vacuous green into a fail instead of trusting the exit code.
const cargoTest = (pkg: string, test: string, extra: string[] = []): StepSpec => ({name: `cargo ${pkg}::${test}`, cmd: 'cargo', args: ['test', '-p', pkg, ...extra, '--test', test, '--', '--include-ignored'], cwd: networkDir, timeoutMs: 1_800_000, minPassedTests: 1})
const scenario = (file: string): StepSpec => ({name: file, cmd: 'bash', args: [`lab/fleet/scenarios/${file}`], cwd: networkDir, timeoutMs: 600_000})

const startedAt = new Date().toISOString()
const t0 = Date.now()
const results: StepResult[] = []
const run = async (phase: string, spec: StepSpec) => {
  const r = await runStep(phase, spec)
  results.push(r)
  return r
}
const pushSkip = (phase: string,name: string,detail: string,optional=false) =>
  results.push({phase,name,status:'skip',ms:0,metrics:[],detail,optional})

/** Run specs concurrently with a worker-pool cap, quietly (so streams don't interleave). */
async function runPool(phase: string, specs: StepSpec[], limit: number): Promise<void> {
  let idx = 0
  const worker = async () => {
    while (idx < specs.length) {
      const spec = specs[idx++]!
      results.push(await runStep(phase, {...spec, quiet: true}))
    }
  }
  await Promise.all(Array.from({length: Math.min(limit, specs.length)}, () => worker()))
}

const haveCargo = await have('cargo')
const haveForge = await have('forge')

// ── Stage 1: bring up the real stack (gate — abort the whole run if unhealthy) ──
if (DO_BRINGUP) {
  results.push(...(await bringUp()))
  const healthy = results.find(r => r.name.startsWith('stack healthy'))
  if (healthy && healthy.status === 'fail') {
    log('\n✗ stack did not come up healthy — aborting before tests. See report.')
    await finish(true)
  }
}

// ── fleet-INDEPENDENT track: Rust anvil (parallel) + cargo crypto perf + crypto stress ──
async function fleetIndependentTrack(): Promise<void> {
  if (DO_CORRECTNESS) {
    if (!DO_RUST) {
      pushSkip('correctness-rust', 'rust anvil protocol tests', 'skipped via KK_VERIFY_RUST=0')
    } else if (haveCargo && haveForge) {
      // Each test spawns its own ephemeral-port anvil, so they're mutually
      // independent — run them in a capped worker pool. cargo's build lock
      // serialises the (cached, fast) per-binary builds; the anvil RUNS overlap.
      await runPool('correctness-rust', [
        cargoTest('keykeeper-node', 'anvil_node_e2e'),
        cargoTest('keykeeper-accountant', 'anvil_settle'),
        cargoTest('keykeeper-accountant', 'anvil_threshold_capstone'),
        cargoTest('keykeeper-accountant', 'anvil_accountant_slashing'),
        cargoTest('tasra-cli', 'anvil_operator_cli'),
        // alloy-client is not a default feature: without it this suite compiles to ZERO
        // tests and exits 0 - it had been vacuously green here since it was added.
        cargoTest('keykeeper-eth', 'anvil_alloy_client', ['--features', 'alloy-client']),
        {name: 'cargo keykeeper-platform-signer (anvil)', cmd: 'cargo', args: ['test', '-p', 'keykeeper-platform-signer'], cwd: networkDir, timeoutMs: 1_800_000},
      ], RUST_PAR)
    } else {
      pushSkip('correctness-rust', 'rust anvil protocol tests', `missing toolchain (cargo=${haveCargo} forge=${haveForge})`)
    }
  }

  if (DO_PERF && haveCargo) {
    // cargo crypto profiles — pure local crypto, independent of the fleet AND of
    // each other; run them as a small pool too.
    await runPool('perf', [
      // Was `-- --ignored` (only-ignored mode) since the day it was added - and
      // perf_smoke has NO #[ignore]d tests, so the step ran ZERO tests and passed
      // vacuously until minPassedTests caught it. The plain helper runs the suite.
      cargoTest('keykeeper-frost', 'perf_smoke'),
      {...cargoTest('keykeeper-bls', 'finish_profile'), name: 'cargo bls finish_profile', args: ['test', '-p', 'keykeeper-bls', '--test', 'finish_profile', '--', '--ignored']},
    ], 2)
  }
  if (DO_PERF) {
    // stress:crypto is in-process crypto throughput (no fleet HTTP). (stress:keyops
    // DOES hit the fleet — it lives in the fleet-dependent track.)
    await run('perf', {...npm('stress:crypto'), timeoutMs: 900_000})
    if (DO_BENCH && haveCargo) {
      await run('perf', {name: 'make bench (criterion)', cmd: 'make', args: ['bench'], cwd: networkDir, timeoutMs: 3_600_000, optional: true})
    }
  }
}

// ── fleet-DEPENDENT track: bootstrap → SDK suites → fleet load → destructive (serial) ──
async function fleetDependentTrack(): Promise<void> {
  // Stage 2: real economic onboarding.
  if (DO_BOOTSTRAP) {
    await run('bootstrap', {name: 'real economic onboarding (account→faucet→TSRA→slot→operate)', cmd: 'npm', args: ['run', '--silent', 'verify:bootstrap'], cwd: sdkRoot, env: FLEET, timeoutMs: 600_000})
  }

  // Stage 3b: SDK live-fleet suites (black box over HTTP) + explorer reconcile.
  // NB: we run `test:prod` (the SIGNED JWT-VC path), NOT `test:e2e` — the prod
  // verifier profile disables the unsigned `/v1/verify` that `test:e2e` uses.
  if (DO_CORRECTNESS) {
    const sdkSuites = ['test', 'test:prod', 'test:reconcile']
    if (on(process.env.KK_VERIFY_DEV_E2E)) sdkSuites.splice(1, 0, 'test:e2e')
    for (const sc of sdkSuites) await run('correctness-sdk', npm(sc))
  }

  // Stage 4: fleet performance/load (serial — all share the fleet + chain).
  if (DO_PERF) {
    await run('perf', {...npm('stress:keyops'), timeoutMs: 900_000})
    // On-chain slot creation via the serial production CLI is slow (~15s DKG each).
    await run('perf', {...npm('stress:slots:onchain'), env: {...FLEET, KK_STRESS_SLOTS: process.env.KK_STRESS_SLOTS ?? '6'}, timeoutMs: 1_800_000})
    // Cap concurrency to a load the 5-node fleet comfortably clears.
    await run('perf', {...npm('stress:slots:onchain:parallel'), env: {...FLEET, KK_STRESS_SLOTS: process.env.KK_STRESS_PARALLEL_SLOTS ?? '12'}, timeoutMs: 1_200_000})
  }

  // Stage 4.5: fleet-recovery settle. The perf/load stage above leaves the
  // fleet + threshold accountant set with a deep backlog (pending DKGs,
  // settlements, and the anchor/adjudication loops still catching up). On a
  // resource-constrained host the accountant set then can't complete a threshold
  // SLASH within the destructive scenarios' window — observed: scenario 14
  // crawling to 374s and 15's slash never landing in 240s, while the SAME slash
  // lands in ~6s on a fresh, unloaded fleet.
  //
  // A FIXED sleep is a blind guess — 180s was enough on some hosts and NOT on
  // others (15 still flaked with the accountant set mid-drain). So settle
  // ADAPTIVELY: wait a floor (the minimum drain), then keep waiting WHILE the
  // host is still churning the backlog, up to a bounded ceiling. See settleFleet.
  if (DO_PERF && DO_DESTRUCTIVE) await settleFleet()

  // Stage 5: destructive (LAST — degrades the fleet).
  if (DO_DESTRUCTIVE) {
    await run('destructive', {name: 'node-slash-lifecycle (slash + unbond)', cmd: 'npx', args: ['tsx', 'test/slashing/node-slash-lifecycle.ts'], cwd: sdkRoot, env: {...FLEET, KK_DESTRUCTIVE: '1'}, timeoutMs: 600_000})
    // Fault evidence is generated outside the production services. The full
    // network certification owns the larger HTTP adversary matrix in layer 4.
    for (const f of ['12-verifier-slash.sh','15-verifier-selective-slash.sh','11-slashing.sh']) {
      await run('destructive',scenario(f))
    }
    await run('destructive',npm('test:slashing'))
    await run('destructive',scenario('08b-nuke-and-recover.sh'))
  }
}

// Finish CPU-heavy independent checks before measuring the live fleet.
await fleetIndependentTrack()
await fleetDependentTrack()

await finish(false)

// ── perf → destructive fleet-recovery settle ────────────────────────────────
// Wait for the perf-stage backlog to DRAIN before the threshold-slash scenarios,
// so a fresh slash lands fast instead of timing out against a starved accountant
// set. Adaptive, not a fixed sleep: a floor (unconditional minimum drain — the
// backlog is queued work-items, not just CPU), then poll host load1 until it
// falls back to the fleet's idle baseline (the accountant containers pin CPU
// while draining, so load1 dropping is the signal the backlog is gone — the same
// signal fastcert's settle_host uses), capped at a bounded ceiling so a
// permanently-loaded host can never wedge the run.
//   KK_VERIFY_COOLDOWN_SECS      floor / minimum settle (default 180)
//   KK_VERIFY_COOLDOWN_MAX_SECS  ceiling / maximum settle (default 480)
//   KK_VERIFY_SETTLE_LOAD_FRAC   proceed once load1 < ncpu·frac (default 0.75)
async function settleFleet(): Promise<void> {
  const floorSecs = Number(process.env.KK_VERIFY_COOLDOWN_SECS ?? 180)
  if (!Number.isFinite(floorSecs) || floorSecs <= 0) return
  const maxSecs = Number(process.env.KK_VERIFY_COOLDOWN_MAX_SECS ?? 480)
  const rawFrac = Number(process.env.KK_VERIFY_SETTLE_LOAD_FRAC ?? 0.75)
  const ncpu = Math.max(1, os.cpus().length)
  const thresh = ncpu * (Number.isFinite(rawFrac) && rawFrac > 0 ? rawFrac : 0.75)
  const ceil = Math.max(floorSecs, Number.isFinite(maxSecs) ? maxSecs : floorSecs)
  const sleep = (s: number) => new Promise(r => setTimeout(r, s * 1000))
  const start = Date.now()
  const since = () => Math.round((Date.now() - start) / 1000)

  banner('fleet-recovery settle (perf → destructive)')
  log(`  draining the perf-load backlog before the threshold-slash scenarios (floor ${floorSecs}s, then until host load1 < ${thresh.toFixed(1)} across ${ncpu} cores, cap ${ceil}s)`)
  await sleep(floorSecs)

  // os.loadavg() reports [0,0,0] where the platform doesn't support it (e.g.
  // Windows) — there the floor is all we can do.
  if ((os.loadavg()[0] ?? 0) <= 0) { log(`  · load average unavailable on this platform; took the ${floorSecs}s floor`); return }
  for (;;) {
    const l = os.loadavg()[0] ?? 0
    if (l < thresh) { log(`  ✓ host recovered (load1 ${l.toFixed(1)} < ${thresh.toFixed(1)}) after ${since()}s`); return }
    if (since() >= ceil) { log(`  · settle cap ${ceil}s reached (load1 ${l.toFixed(1)} still ≥ ${thresh.toFixed(1)}); proceeding`); return }
    log(`  · still draining (load1 ${l.toFixed(1)} ≥ ${thresh.toFixed(1)}, ${since()}s elapsed), waiting…`)
    await sleep(15)
  }
}

// ── finalize: write report, optional teardown, exit code ─────────────────────
async function finish(abort: boolean): Promise<never> {
  const meta = {
    startedAt,
    finishedAt: new Date().toISOString(),
    totalMs: Date.now() - t0,
    config: {
      bringup: String(DO_BRINGUP),
      perf: String(DO_PERF),
      destructive: String(DO_DESTRUCTIVE),
      bench: String(DO_BENCH),
      chainId:process.env.KK_CHAIN_ID ?? '',
      chainRpc:process.env.KK_CHAIN_RPC_HOST ?? '',
      rustPar: String(RUST_PAR),
      networkDir,
      sdkRoot,
    },
  }
  const {anyRequiredFail, mdPath, jsonPath} = writeReport(results, meta)
  banner('verify complete')
  log(`report:  ${mdPath}`)
  log(`json:    ${jsonPath}`)
  const pass = results.filter(r => r.status === 'pass').length
  const fail = results.filter(r => r.status === 'fail').length
  const skip = results.filter(r => r.status === 'skip').length
  log(`${anyRequiredFail ? '❌ FAIL' : '✅ PASS'} — ${pass} passed, ${fail} failed, ${skip} skipped`)

  // Tear down only after a complete run; on abort or KK_KEEP, leave it up for inspection.
  if (KEEP) log('(KK_KEEP=1 — leaving the stack up)')
  else if (abort) log('(aborted — leaving the partial stack up for inspection)')
  else await tearDown().catch(() => undefined)

  process.exit(anyRequiredFail || abort ? 1 : 0)
}
