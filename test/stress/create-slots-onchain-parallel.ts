// Stress: PARALLEL on-chain slot creation across MULTIPLE creator keys.
//
// create-slots-onchain.ts submits with ONE creator key, nonce-ordered + serial,
// so wall time is dominated by tx submission, not DKG. The fix production would
// use: spread submission across N creator keys — each key is its own nonce lane,
// so M keys give ~M tx in flight. This harness benchmarks that.
//
// Same on-chain path as production (KeyRegistry.createKeySlotFiltered → contract
// draws a k-of-n committee → nodes auto-DKG → explorer indexes), but driven via
// the SDK write client (viem, in-process) instead of the CLI, so M keys can each
// hold a tx in flight. Set KK_CREATORS=1 to reproduce the serial baseline on this
// exact code path (isolates parallelism from the CLI-vs-SDK difference).
//
// Submission runs in CREATORS parallel lanes (each key serial in its own lane —
// one tx in flight per nonce sequence); a shared finalizer pool waits for each
// slot's DKG + on-chain anchor concurrently. Reports submit-only throughput (the
// thing we parallelised) AND end-to-end throughput.
//
// REALISTIC MULTI-USER MODE: set KK_CREATORS == KK_STRESS_SLOTS so every slot is
// created by its OWN fresh wallet (one tx, nonce 0, nothing to queue behind) —
// the true production shape where each slot is a different user. Per-wallet nonce
// serialisation vanishes; the only ceilings left are chain tx ingestion and the
// fleet's DKG ceremony capacity. Funding is parallelised (one funder, sequential
// nonces) so large user counts set up cheaply.
//
// Run: tsx test/stress/create-slots-onchain-parallel.ts
//   KK_CREATORS (4)  KK_STRESS_SLOTS (24)  KK_STRESS_CONC (8 finalizers)
//   KK_K (2)  KK_N (3)  KK_STRESS_MODE (bls|frost|mix)

import {createPublicClient, http, parseEther, type Hex} from 'viem'
import {WALLET_RULE as SLOT_DCQL_RULE} from '../fleet/_wallet.ts'
import {Suite, metric} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig, mintLocalJwt, provisionRule} from '../fleet/_fleet.ts'
import {createTasraWriteClient, generateClientKey, type TasraWriteClient} from '../../src/chain/write.ts'
import {keyRegistryAbi} from '../../src/chain/abis/keyRegistry.ts'
import {requireAddress} from '../../src/chain/deployments.ts'

const cfg = loadFleetConfig()
const s = new Suite('stress: parallel on-chain slot creation (multi-key)')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}
if (!cfg.deployPk || !cfg.book.KeyRegistry) {
  s.ok('deployer key + KeyRegistry available', false, 'need DEPLOY_PK + KeyRegistry in chain.env')
  s.done()
  process.exit(1)
}

const COUNT = Number(process.env.KK_STRESS_SLOTS || 24)
const CREATORS = Number(process.env.KK_CREATORS || 4)
const CONC = Number(process.env.KK_STRESS_CONC || 8)
const MODE = (process.env.KK_STRESS_MODE || 'bls') as 'mix' | 'frost' | 'bls'
const K = Number(process.env.KK_K || 2)
const N = Number(process.env.KK_N || 3)
const jwt = mintLocalJwt(cfg) // admin scope → provisions the DCQL rule (ADR-0025)
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

// On-chain anchor check (same signal create-slots-onchain.ts uses): a slot's DKG
// is FINALISED only when its group key is submitted on-chain.
const chain = createPublicClient({transport: http(cfg.rpcUrl)})
const keyReg = requireAddress(cfg.book, 'KeyRegistry')
async function onchainKeySet(slot: string): Promise<boolean> {
  try {
    const r = (await chain.readContract({address: keyReg, abi: keyRegistryAbi, functionName: 'getKeySlot', args: [(slot.startsWith('0x') ? slot : `0x${slot}`) as Hex]})) as {publicKey?: string} | unknown[]
    const pk = (r as {publicKey?: string}).publicKey ?? (Array.isArray(r) ? (r[4] as string) : undefined)
    return !!pk && pk !== '0x'
  } catch {
    return false
  }
}

// Wait for the committee's auto-DKG, provision the rule, confirm on-chain anchor.
// `ruleSalt` is the ADR-0058 salt the creating client minted — a keeper refuses the
// rule without it, leaving every slot this test makes unusable by later suites.
async function finalize(slot: string, mode: string, ruleSalt: string): Promise<{ok: boolean; ms: number; committee: number[]; anchored: boolean}> {
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
    // AUTHORITATIVE completion signal: the on-chain anchor (submitPublicKey) — check
    // it FIRST and INDEPENDENTLY of the committee HTTP poll, which can transiently
    // return an empty/partial set under load even when the slot already anchored,
    // under-reporting node success as a client-side artifact. The on-chain key is truth.
    if (await onchainKeySet(slot)) {
      anchored = true
      break
    }
    // Secondary (reporting only): note a committee member has published the key of
    // the right shape. NEVER gates pass/fail — only the on-chain anchor above does.
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
  let ok = anchored
  if (anchored) {
    const prov = await provisionRule(committee, slot, SLOT_DCQL_RULE, ruleSalt, jwt)
    ok = prov.ok && committee.length >= K
    if (!prov.ok) s.info(`rule provisioning refused for ${slot.slice(0, 12)}…: ${prov.errors[0]}`)
  }
  const idx = committee.map(u => cfg.nodeUrls.indexOf(u)).filter(i => i >= 0)
  // The on-chain anchor is authoritative — NOT the committee HTTP poll.
  return {ok, ms, committee: idx, anchored}
}

// ── provision CREATORS funded creator keys ────────────────────────────────────
// Each gets gas only — createKeySlot is permissionless + fee-less (ADR-0027), so
// no TSRA needed to create. Funded in PARALLEL from one deployer wallet (explicit
// sequential nonces, receipts awaited together) so large user counts (the
// realistic one-wallet-per-slot mode) set up in a few blocks, not CREATORS×blocks.
s.info(`funding ${CREATORS} creator keys from deployer (gas only; slot create is fee-less)…`)
const funder = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: cfg.deployPk as Hex, chainId: cfg.chainId})
const creators: TasraWriteClient[] = Array.from({length: CREATORS}, () =>
  createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: generateClientKey(), chainId: cfg.chainId}),
)
const baseNonce = await funder.pub.getTransactionCount({address: funder.address})
await Promise.all(
  creators.map((c, i) =>
    funder.wallet
      .sendTransaction({to: c.address, value: parseEther('0.2'), nonce: baseNonce + i})
      .then(h => funder.pub.waitForTransactionReceipt({hash: h})),
  ),
)
s.ok(`${CREATORS} creator keys funded with gas`, (await Promise.all(creators.map(c => c.ethBalance()))).every(b => b > 0n))

// ── submission: CREATORS parallel nonce lanes feed a shared finalizer pool ─────
const queue: Array<{slot: string; mode: string; ruleSalt: string}> = []
const submitLat: number[] = []
const perKeySubmitted = new Array<number>(CREATORS).fill(0)
let submitted = 0
let nextSubmit = 0
let submitDone = false
let submitWall = 0

async function lane(keyIdx: number) {
  const c = creators[keyIdx]!
  while (true) {
    const i = nextSubmit++
    if (i >= COUNT) break
    const mode = MODE === 'mix' ? (i % 2 === 0 ? 'bls' : 'frost') : MODE
    // FROST chain-DKG runs over ALL key-keepers and asserts participants==n, so a
    // FROST slot MUST have n = node count; BLS honours the drawn k-of-n committee.
    const n = mode === 'frost' ? cfg.nodeUrls.length : N
    const t0 = Date.now()
    try {
      const {slotId, ruleSalt} = await c.createSlotCommitReveal({dcqlRule: SLOT_DCQL_RULE, k: K, n, mode, tags: ['keykeeper']})
      submitLat.push(Date.now() - t0)
      queue.push({slot: slotId, mode, ruleSalt})
      submitted++
      perKeySubmitted[keyIdx]!++
    } catch (e) {
      s.info(`submit #${i} (key-${keyIdx + 1}) failed: ${String((e as Error).message).replace(/\s+/g, ' ').slice(0, 120)}`)
    }
  }
}

// ── finalizer pool: wait DKG + anchor concurrently ────────────────────────────
const lat: number[] = []
const perNode = new Array<number>(cfg.nodeUrls.length).fill(0)
let done = 0
let okCount = 0
let anchoredCount = 0

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
      r.committee.forEach(idx => {
        perNode[idx]!++
      })
    }
    if (r.anchored) anchoredCount++
    s.info(`slot ${done}/${submitted} (${job.mode}): ${r.ok ? 'DKG ok' : 'DKG PENDING/timeout'} committee=[${r.committee.map(i => i + 1).join(',')}] on-chain=${r.anchored ? '✓' : '✗'} ${(r.ms / 1000).toFixed(1)}s`)
  }
}

// ── run ───────────────────────────────────────────────────────────────────────
s.info(`config: ${COUNT} slots via SDK createSlot · ${CREATORS} creator keys (parallel nonce lanes) · ${K}-of-${N} · mode=${MODE} · finalize-conc=${CONC}`)
const t0 = Date.now()
const submitP = Promise.all(Array.from({length: CREATORS}, (_, k) => lane(k))).then(() => {
  submitWall = (Date.now() - t0) / 1000
  submitDone = true
})
await Promise.all([submitP, ...Array.from({length: CONC}, () => finalizer())])
const wallS = (Date.now() - t0) / 1000

const avg = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0)
lat.sort((a, b) => a - b)
const pct = (p: number) => (lat.length ? lat[Math.min(lat.length - 1, Math.floor((p / 100) * lat.length))]! : 0)

s.info('────────────────────────────────────────────────────────')
s.info(`submitted ${submitted}/${COUNT} on-chain · DKG complete ${okCount} · on-chain-anchored ${anchoredCount}`)
s.info(`SUBMIT-ONLY: ${submitWall.toFixed(1)}s → ${((submitted / submitWall) * 60).toFixed(1)} slots/min  (per-tx avg ${(avg(submitLat) / 1000).toFixed(1)}s, ${CREATORS} lanes)`)
s.info(`END-TO-END:  ${wallS.toFixed(1)}s → ${((okCount / wallS) * 60).toFixed(1)} slots/min  · DKG p50=${(pct(50) / 1000).toFixed(1)}s p95=${(pct(95) / 1000).toFixed(1)}s`)
metric('parallel submit-only', Math.round((submitted / submitWall) * 600) / 10, 'slots/min', {creators: CREATORS})
metric('parallel end-to-end', Math.round((okCount / wallS) * 600) / 10, 'slots/min')
metric('parallel DKG p95', Math.round(pct(95) / 100) / 10, 's')
s.info(`submitted per key: ${perKeySubmitted.map((c, i) => `key-${i + 1}:${c}`).join(' ')}`)
s.info(`committee draw distribution per node: ${perNode.map((c, i) => `node-${i + 1}:${c}`).join(' ')}`)
s.info('────────────────────────────────────────────────────────')

s.ok('all slots submitted on-chain', submitted === COUNT, `${submitted}/${COUNT}`)
// This is a STRESS test: under max concurrency a small tail of slots can miss the
// per-slot DKG deadline (the fleet's ceremony capacity, not a correctness bug).
// Assert a high completion SLA, not perfection — but keep anchor-correctness 100%
// for every slot that DID complete (a completed-but-wrong/unanchored key is a real
// failure). Single-slot + serial correctness is proven elsewhere (bootstrap,
// anvil_node_e2e, create-slots-onchain).
s.ok('≥90% of parallel slots completed DKG under load', okCount >= Math.ceil(submitted * 0.9) && okCount > 0, `${okCount}/${submitted}`)
s.ok('every COMPLETED slot anchored its group key on-chain (DKG finalised, not pending)', anchoredCount === okCount && okCount > 0, `${anchoredCount}/${okCount}`)
s.ok('committee draw spread across ≥3 nodes (not node-1-only)', perNode.filter(c => c > 0).length >= 3, perNode.join(','))

s.done()
