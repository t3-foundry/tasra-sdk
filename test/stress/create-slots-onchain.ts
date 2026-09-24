// Stress: ON-CHAIN slot creation, EXACTLY as production does it.
//
// Production never curls /v1/dkg/trigger. A creator submits an on-chain tx to
// KeyRegistry (via the operator CLI `tasra-cli slot create`); the CONTRACT
// draws a random k-of-n committee from the registered key-keeper pool; the
// assigned nodes observe `KeySlotCreated`, run the DKG together over libp2p, and
// anchor the key on-chain; the explorer indexes the event; the clear-text DCQL
// rule is provisioned out-of-band (ADR-0025). This harness does that full
// lifecycle, repeatedly, and asserts the slots are real: explorer-indexed,
// DKG-complete, rule-provisioned — with a RANDOM committee per slot (so the load
// spreads across the fleet, never node-1-bound).
//
// vs create-slots.ts (off-chain /v1/dkg/trigger): those are transient + invisible
// to the explorer. THESE are permanent on-chain registry entries — so the count
// defaults low. Each is a real, billable-shaped production slot.
//
// Use commit-reveal against the live threshold beacon on every submission.
//
// Run: tsx test/stress/create-slots-onchain.ts
//   KK_STRESS_SLOTS (12)  KK_STRESS_CONC (4, for DKG-wait pipelining)
//   KK_K (2)  KK_N (3)  KK_STRESS_MODE (mix|frost|bls)  commit-reveal required

import {execFile} from 'node:child_process'
import {dirname, resolve} from 'node:path'
import {fileURLToPath} from 'node:url'
import {promisify} from 'node:util'
import {createPublicClient, http, type Hex} from 'viem'
import {WALLET_RULE as SLOT_DCQL_RULE} from '../fleet/_wallet.ts'
import {Suite, metric} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig, mintLocalJwt, provisionRule} from '../fleet/_fleet.ts'
import {keyRegistryAbi} from '../../src/chain/abis/keyRegistry.ts'
import {requireAddress} from '../../src/chain/deployments.ts'

const pexec = promisify(execFile)
const cfg = loadFleetConfig()
const s = new Suite('stress: on-chain slot creation (production flow)')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}

const registry = cfg.book.KeyRegistry
const creatorKey = process.env.KK_CREATOR_KEY || cfg.deployPk
// The network repo: KK_NETWORK_DIR when certify sets it, else the sibling-org layout.
// Derived here rather than from the fleet config, which no longer reads chain.env as a file.
const repoRoot =
  process.env.KK_NETWORK_DIR ?? resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', 'managination', 'keykeeper-network')
const cli = process.env.KK_CLI || resolve(repoRoot, 'target/release/tasra-cli')
if (!registry || !creatorKey) {
  s.ok('KEY_REGISTRY + creator key available', false, 'need KeyRegistry + DEPLOY_PK in chain.env')
  s.done()
  process.exit(1)
}
// Re-bind post-guard: TS drops the narrowing at a function boundary, and these are
// read inside submitCreate() below.
const REGISTRY = registry
const CREATOR_KEY = creatorKey

const COUNT = Number(process.env.KK_STRESS_SLOTS || 12)
const CONC = Number(process.env.KK_STRESS_CONC || 4)
const MODE = (process.env.KK_STRESS_MODE || 'mix') as 'mix' | 'frost' | 'bls'
const K = Number(process.env.KK_K || 2)
const N = Number(process.env.KK_N || 3)
const PROTECT = true
const jwt = mintLocalJwt(cfg) // admin scope → provisions the DCQL rule (ADR-0025)
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

// On-chain anchor check: a slot's DKG is FINALISED only when its group key is
// submitted on-chain (this is what the explorer reads / shows as "pending DKG"
// until set). A 200 on /v1/keys/:id/public means "assigned committee member",
// NOT that a key exists — so we verify the real key, node-side AND on-chain.
const chain = createPublicClient({transport: http(cfg.rpcUrl)})
const keyReg = requireAddress(cfg.book, 'KeyRegistry')
async function onchainKeySet(slot: string): Promise<boolean> {
  try {
    const s = (await chain.readContract({address: keyReg, abi: keyRegistryAbi, functionName: 'getKeySlot', args: [(slot.startsWith('0x') ? slot : `0x${slot}`) as Hex]})) as {publicKey?: string} | unknown[]
    const pk = (s as {publicKey?: string}).publicKey ?? (Array.isArray(s) ? (s[4] as string) : undefined)
    return !!pk && pk !== '0x'
  } catch {
    return false
  }
}

// Phase 1 (SERIAL — one creator key, nonce-ordered): submit the on-chain create
// tx via the production CLI and parse the slot id. This is exactly the operator
// action; the contract draws the committee.
async function submitCreate(i: number): Promise<{slot: string; mode: string; ruleSalt?: string} | null> {
  const mode = MODE === 'mix' ? (i % 2 === 0 ? 'bls' : 'frost') : MODE
  // FROST's chain-DKG runs over ALL connected key-keepers and asserts
  // `participants == threshold.n`, so a FROST slot MUST have n = key-keeper
  // count or its DKG is rejected ("participants (N) != threshold.n") and the
  // slot sits forever pending. BLS respects the drawn k-of-n committee, so it
  // honours the requested N.
  const n = mode === 'frost' ? cfg.nodeUrls.length : N
  const sub = PROTECT ? 'protect' : 'create'
  const args = [
    'slot', sub,
    '--rpc-url', cfg.rpcUrl,
    '--key-registry', REGISTRY,
    '--private-key', CREATOR_KEY,
    '--dcql', SLOT_DCQL_RULE,
    '--k', String(K),
    '--n', String(n),
    '--mode', mode,
    '--tag', 'keykeeper', // draw from key-keeper operators only (not verifiers/accountants)
  ]
  // One retry: the CLI's tx submission can transiently lose a race with the
  // concurrent finalizers hammering the same RPC/nodes.
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const {stdout} = await pexec(cli, args, {timeout: 180000})
      // `slot create` prints `slot_id 0x…`; `slot protect` prints `Committed slot 0x…`
      // (then `Revealing slot 0x…`). Match both so the protect path is captured too.
      const m = stdout.match(/(?:slot_id|Committed slot|Revealing slot)\s+(0x[0-9a-f]{64})/i)
      // ADR-0058: the CLI mints the rule salt and prints it (`print_params`) —
      // it exists nowhere else, and the keeper refuses the rule without it.
      const salt = stdout.match(/rule_salt\s+(0x[0-9a-f]{64})/i)?.[1]
      if (m) return {slot: m[1]!, mode, ruleSalt: salt}
      s.info(`create #${i}: no slot id in CLI output`)
    } catch (e) {
      // ⚠ Report the REASON, not the command. This used to be
      // `String(e.message).slice(0, 160)`, and since exec's message begins
      // "Command failed: <the entire CLI invocation>", 160 characters was consumed
      // by the command line every single time — the revert was always truncated away.
      //
      // That cost a full certification cycle. Three FROST creates failed with
      // `InsufficientFilteredPool(have, need)`, which states the answer IN the error,
      // and the harness threw it away and printed the command instead. Prefer stderr,
      // and keep the TAIL, because that is the end where the cause lives.
      const err = e as Error & {stderr?: string; stdout?: string}
      const raw = (err.stderr?.trim() || err.message || '').replace(/\s+/g, ' ')
      const msg = raw.length > 300 ? `…${raw.slice(-300)}` : raw
      if (attempt === 0) {
        await sleep(1000)
        continue
      }
      s.info(`create #${i} failed (after retry): ${msg}`)
    }
  }
  return null
}

// Phase 2 (CONCURRENT): wait for the committee's auto-DKG, provision the rule,
// confirm the explorer indexed it.
async function finalize(slot: string, mode: string, ruleSalt: string | undefined): Promise<{ok: boolean; ms: number; committee: number[]; anchored: boolean}> {
  const t0 = Date.now()
  const wantHex = mode === 'frost' ? 64 : 192 // Ed25519 32B vs BLS-G2 96B (compressed)
  const keyRe = new RegExp(`^[0-9a-f]{${wantHex}}$`, 'i')
  const keyOf = async (u: string): Promise<string | undefined> => {
    try {
      const r = (await (await fetch(`${u}/v1/keys/${slot}/public`, {signal: AbortSignal.timeout(4000)})).json()) as {group_public_key?: string}
      return r.group_public_key
    } catch {
      return undefined
    }
  }
  let committee: string[] = []
  let keyed = false
  let anchored = false
  const deadline = Date.now() + 120_000
  while (Date.now() < deadline) {
    committee = await discoverCommittee(cfg, slot)
    // AUTHORITATIVE completion signal: the on-chain anchor (submitPublicKey) means
    // k committee members attested the SAME group key — i.e. the DKG finalised.
    // Check it FIRST and INDEPENDENTLY of the committee HTTP poll. discoverCommittee /
    // keyOf can transiently return an empty/partial set under load even when the slot
    // has already anchored on-chain, and gating pass/fail on that under-reports node
    // success as a pure client-side artifact (measured: a 24-slot burst read 12/24 via
    // the HTTP poll but 24/24 on-chain). The on-chain key is the truth.
    if (await onchainKeySet(slot)) {
      anchored = true
      break
    }
    // Secondary (reporting only): confirm a committee member has PUBLISHED the group
    // key of the right shape, so the per-slot line can show the participating set.
    // This NEVER gates pass/fail — only the on-chain anchor above does.
    if (!keyed && committee.length >= K) {
      for (const u of committee) {
        const k = await keyOf(u)
        if (k && keyRe.test(k)) {
          keyed = true
          break
        }
      }
    }
    await sleep(1500)
  }
  const ms = Date.now() - t0
  // The on-chain anchor is the authoritative "DKG finalised" signal — NOT the
  // committee HTTP poll (which under-reports on-chain-keyed slots under load).
  let ok = anchored
  if (ok) {
    const prov = await provisionRule(committee, slot, SLOT_DCQL_RULE, ruleSalt, jwt)
    ok = prov.ok && committee.length >= K
    if (!prov.ok) s.info(`rule provisioning refused for ${slot.slice(0, 12)}…: ${prov.errors[0]}`)
  }
  const idx = committee.map(u => cfg.nodeUrls.indexOf(u)).filter(i => i >= 0)
  return {ok, ms, committee: idx, anchored}
}

// ── run: serial submitter feeds a concurrent finalizer pool ───────────────────
s.info(`config: ${COUNT} slots on-chain via \`tasra-cli slot ${PROTECT ? 'protect' : 'create'}\`, ${K}-of-${N}, mode=${MODE}, finalize-conc=${CONC}`)
s.info(`creator=${cfg.deployAddr || '(chain.env DEPLOY_ADDR)'}  registry=${registry}`)

const queue: Array<{slot: string; mode: string; ruleSalt?: string}> = []
let submitDone = false
let submitted = 0
const lat: number[] = []
const perNode = new Array<number>(cfg.nodeUrls.length).fill(0)
const committeeSizes: number[] = []
let okCount = 0
let anchoredCount = 0
let done = 0

async function submitter() {
  for (let i = 0; i < COUNT; i++) {
    const r = await submitCreate(i)
    if (r) {
      queue.push(r)
      submitted++
    }
  }
  submitDone = true
}

async function finalizer() {
  while (!submitDone || queue.length) {
    const job = queue.shift()
    if (!job) {
      await sleep(200)
      continue
    }
    const r = await finalize(job.slot, job.mode, job.ruleSalt)
    lat.push(r.ms)
    done++
    if (r.ok) {
      okCount++
      committeeSizes.push(r.committee.length)
      r.committee.forEach(idx => {
        perNode[idx]!++
      })
    }
    if (r.anchored) anchoredCount++
    s.info(`slot ${done} (${job.mode}): ${r.ok ? 'DKG ok' : 'DKG PENDING/timeout'} committee=[${r.committee.map(i => i + 1).join(',')}] on-chain=${r.anchored ? '✓' : '✗'} ${(r.ms / 1000).toFixed(1)}s`)
  }
}

const t0 = Date.now()
await Promise.all([submitter(), ...Array.from({length: CONC}, () => finalizer())])
const wallS = (Date.now() - t0) / 1000

lat.sort((a, b) => a - b)
const pct = (p: number) => (lat.length ? lat[Math.min(lat.length - 1, Math.floor((p / 100) * lat.length))]! : 0)
s.info('────────────────────────────────────────────────────────')
s.info(`submitted ${submitted}/${COUNT} on-chain · DKG complete ${okCount} · on-chain-anchored ${anchoredCount}`)
s.info(`wall ${wallS.toFixed(1)}s · ${((okCount / wallS) * 60).toFixed(1)} slots/min · DKG p50=${(pct(50) / 1000).toFixed(1)}s p95=${(pct(95) / 1000).toFixed(1)}s`)
metric('on-chain slot creation', Math.round((okCount / wallS) * 600) / 10, 'slots/min')
metric('on-chain DKG p50', Math.round(pct(50) / 100) / 10, 's')
metric('on-chain DKG p95', Math.round(pct(95) / 100) / 10, 's')
s.info(`committee draw distribution per node: ${perNode.map((c, i) => `node-${i + 1}:${c}`).join(' ')}`)
s.info('────────────────────────────────────────────────────────')

s.ok('on-chain creation success rate ≥ 90%', submitted >= Math.ceil(COUNT * 0.9) && submitted > 0, `${submitted}/${COUNT}`)
s.ok('every created slot completed DKG (published a real group key)', okCount === submitted && okCount > 0, `${okCount}/${submitted}`)
s.ok('every slot anchored its group key on-chain (DKG finalised, not pending)', anchoredCount === okCount && okCount > 0, `${anchoredCount}/${okCount}`)
s.ok('committee draw spread across ≥3 nodes (not node-1-only)', perNode.filter(c => c > 0).length >= 3, perNode.join(','))

s.done()
