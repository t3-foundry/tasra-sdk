// Stress: sign/decrypt throughput vs COMMITTEE SIZE. Creates a matrix of slots
// on-chain (createKeySlotFiltered → contract draws the committee → nodes
// auto-DKG), then load-tests each slot and reports ops/s + latency per k-of-n.
//
//   - FROST (sign): chain-DKG runs over ALL key-keepers and asserts
//     participants == n, so n is pinned to the node count; k varies.
//   - BLS (decrypt): honours the drawn k-of-n committee; both k and n vary.
//
// Slots are created SEQUENTIALLY on purpose: simultaneous DKG bursts collapse
// the DKG layer (see create-slots.ts); this harness measures key USE, not
// creation throughput.
//
// With TASRA_STATS_FILTER set, a background sampler polls `docker stats` for the
// matching containers and reports per-phase CPU/mem (avg + hottest node). Off by
// default, since container naming is a property of the target deployment.
//
// Run: tsx test/stress/keyops-committees.ts
//   KK_STRESS_DURATION (8) seconds per slot   KK_STRESS_CONC (4) concurrency
//   TASRA_STATS_FILTER (unset) — container-name substring to sample
//   KK_STRESS_SPREAD (0) — 1 distributes each request: round-robin the
//     coordinator across ALL committee members and draw a random k-subset as the
//     signing/decrypting set, so both coordination and signer work spread over the
//     fleet instead of pinning committee[0]. 0 = single-coordinator baseline.
//   KK_CREATE_BURST (0) — create this many slots CONCURRENTLY first (one fresh
//     wallet per slot → no nonce lanes; alternating bls 3-of-5 / frost 3-of-N)
//     and report submit + time-to-ready percentiles for the burst.
//   KK_MATRIX (1) — 0 skips the sign/decrypt matrix (burst-only run).

import {randomBytes} from 'node:crypto'
import {execFile} from 'node:child_process'
import {keccak256, parseEther, toHex, type Hex} from 'viem'
import {Suite, metric} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig, mintLocalJwt, provisionRule, SLOT_DCQL_RULE} from '../fleet/_fleet.ts'
import {frostVerify} from '../fleet/_crypto.ts'
import {encryptEnvelope} from '../../src/crypto/envelope.ts'
import {hexToBytes} from '../../src/crypto/hex.ts'
import {createTasraWriteClient, generateClientKey} from '../../src/chain/write.ts'
import {keyRegistryAbi} from '../../src/chain/abis/keyRegistry.ts'
import {requireAddress} from '../../src/chain/deployments.ts'

const cfg = loadFleetConfig()
const s = new Suite('stress: key-use throughput vs committee size')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}
if (!cfg.deployPk || !cfg.book.KeyRegistry) {
  s.ok('deployer key + KeyRegistry available', false, 'need DEPLOY_PK + KeyRegistry in chain.env')
  s.done()
  process.exit(1)
}

const DURATION = Number(process.env.KK_STRESS_DURATION || 8) * 1000
const CONC = Number(process.env.KK_STRESS_CONC || 4)
const SPREAD = process.env.KK_STRESS_SPREAD === '1'

// Random k-subset of `ids` (partial Fisher-Yates), ascending. Under SPREAD each
// request draws a fresh subset so per-signer load evens out across the fleet.
function pickSet(ids: number[], k: number): number[] {
  const a = [...ids]
  for (let i = 0; i < k; i++) {
    const j = i + Math.floor(Math.random() * (a.length - i))
    ;[a[i], a[j]] = [a[j]!, a[i]!]
  }
  return a.slice(0, k).sort((x, y) => x - y)
}
const NODES = cfg.nodeUrls.length
const jwt = mintLocalJwt(cfg)
const H = {'Content-Type': 'application/json', Authorization: `Bearer ${jwt}`}
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

// Committee sets scale with the fleet: quartile spread of k for FROST, and for
// BLS a pair of small fixed baselines plus ~0.7·n thresholds at growing n. On a
// 5-node fleet this reproduces the original matrix shape; at 20 nodes it spans
// 2-of-3 up to 20-of-20.
const uniq = <T>(xs: T[], key: (x: T) => string) => [...new Map(xs.map(x => [key(x), x])).values()]
const r = (x: number) => Math.max(2, Math.round(x))
// FROST: n pinned to the fleet size (chain-DKG asserts participants == n).
const FROST_SET = uniq(
  [2, r(NODES / 4), r(NODES / 2), r((3 * NODES) / 4), NODES].map(k => ({mode: 'frost' as const, k, n: NODES})),
  c => `${c.k}`,
).sort((a, b) => a.k - b.k)
// BLS: the contract draws a real k-of-n subset committee.
const BLS_SET = uniq(
  [
    {k: 2, n: Math.min(3, NODES)},
    {k: 3, n: Math.min(5, NODES)},
    {k: r(0.7 * (NODES / 2)), n: r(NODES / 2)},
    {k: r(0.7 * 0.75 * NODES), n: r(0.75 * NODES)},
    {k: r(0.7 * NODES), n: NODES},
    {k: NODES, n: NODES},
  ]
    .filter(c => c.k <= c.n && c.n <= NODES)
    .map(c => ({mode: 'bls' as const, ...c})),
  c => `${c.k}/${c.n}`,
).sort((a, b) => a.n - b.n || a.k - b.k)

const client = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: cfg.deployPk as Hex, chainId: cfg.chainId})

// ── fleet resource sampling (docker stats) ───────────────────────────────────
// One `docker stats --no-stream` round trip takes ~2s (it spans two cgroup
// ticks), so an 8s bench phase yields ~3-4 samples per node — enough for
// avg/peak, not a time series. CPU% is per-container and can exceed 100% on
// multi-core hosts. Samples are tagged with the phase that was active when the
// round trip STARTED so slow calls don't bleed into the next phase.
interface StatSample {
  phase: string
  name: string
  cpu: number
  memMb: number
}
const statSamples: StatSample[] = []
let statsPhase = 'setup'
// Opt-in, and with no default: the container naming is a property of how the target
// deployment was brought up, which this suite deliberately knows nothing about.
// Set TASRA_STATS_FILTER to a substring of the container names to sample.
const STATS_FILTER = process.env.TASRA_STATS_FILTER ?? ''
let statsOn = STATS_FILTER !== ''
let statsStop = false

function dockerStatsOnce(tagPhase: string): Promise<StatSample[]> {
  return new Promise(resolve => {
    execFile('docker', ['stats', '--no-stream', '--format', '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'], {timeout: 15000}, (err, out) => {
      if (err) return resolve([])
      const rows: StatSample[] = []
      for (const line of out.trim().split('\n')) {
        const [name, cpuRaw, memRaw] = line.split('\t')
        if (!name || !name.includes(STATS_FILTER) || !cpuRaw || !memRaw) continue
        const cpu = Number.parseFloat(cpuRaw) // "142.35%"
        const m = /([\d.]+)\s*([KMG])iB/i.exec(memRaw.split('/')[0] ?? '')
        const memMb = m ? Number.parseFloat(m[1]!) * (m[2]!.toUpperCase() === 'G' ? 1024 : m[2]!.toUpperCase() === 'K' ? 1 / 1024 : 1) : 0
        rows.push({phase: tagPhase, name, cpu, memMb})
      }
      resolve(rows)
    })
  })
}

const statsDone = (async () => {
  if (!statsOn) {
    s.info('resource sampling off — set TASRA_STATS_FILTER to a container-name substring to enable')
    return
  }
  const probe = await dockerStatsOnce('setup')
  if (!probe.length) {
    statsOn = false
    s.info(`resource sampling disabled (docker unreachable or no container matches "${STATS_FILTER}")`)
    return
  }
  statSamples.push(...probe)
  while (!statsStop) statSamples.push(...(await dockerStatsOnce(statsPhase)))
})()

function resourceLine(phase: string): string | null {
  const ss = statSamples.filter(x => x.phase === phase)
  if (!ss.length) return null
  const cpuAvg = ss.reduce((a, x) => a + x.cpu, 0) / ss.length
  const memAvg = ss.reduce((a, x) => a + x.memMb, 0) / ss.length
  const cpuPeak = ss.reduce((a, x) => (x.cpu > a.cpu ? x : a))
  const memPeak = ss.reduce((a, x) => (x.memMb > a.memMb ? x : a))
  return `cpu avg ${cpuAvg.toFixed(0).padStart(4)}% · peak ${cpuPeak.cpu.toFixed(0)}% (${cpuPeak.name})   mem avg ${memAvg.toFixed(0)}MB · peak ${memPeak.memMb.toFixed(0)}MB (${memPeak.name})`
}

// Create one slot on-chain, wait for the committee's auto-DKG to anchor a group
// key, provision the DCQL rule so our local JWT gates through.
async function createSlot(mode: 'frost' | 'bls', k: number, n: number): Promise<{slot: string; committee: string[]; mpk: string} | null> {
  const t0 = Date.now()
  let slot: string
  let ruleSalt: string
  try {
    const created = await client.createSlot({dcqlRule: SLOT_DCQL_RULE, k, n, mode, tags: ['keykeeper']})
    slot = created.slotId
    ruleSalt = created.ruleSalt
  } catch (e) {
    s.info(`${mode} ${k}-of-${n}: create tx failed — ${String((e as Error).message).replace(/\s+/g, ' ').slice(0, 100)}`)
    return null
  }
  const wantHex = mode === 'frost' ? 64 : 192
  const keyRe = new RegExp(`^[0-9a-f]{${wantHex}}$`, 'i')
  let committee: string[] = []
  let mpk = ''
  // DKG over larger committees needs more headroom (O(n²) message exchange).
  const deadline = Date.now() + 120_000 + n * 10_000
  while (Date.now() < deadline && !mpk) {
    committee = await discoverCommittee(cfg, slot)
    for (const u of committee) {
      try {
        const r = (await (await fetch(`${u}/v1/keys/${slot}/public`, {signal: AbortSignal.timeout(4000)})).json()) as {group_public_key?: string}
        if (r.group_public_key && keyRe.test(r.group_public_key)) {
          mpk = r.group_public_key
          break
        }
      } catch {
        /* retry */
      }
    }
    if (!mpk) await sleep(1500)
  }
  if (!mpk) {
    s.ok(`${mode} ${k}-of-${n}: DKG anchored a group key`, false, `timeout after ${((Date.now() - t0) / 1000).toFixed(0)}s`)
    return null
  }
  const prov = await provisionRule(committee, slot, SLOT_DCQL_RULE, ruleSalt, jwt)
  if (!prov.ok) {
    // Every op measured below authorizes against this rule, so a refusal here
    // would report as node latency/failures rather than as broken setup.
    s.ok(`${mode} ${k}-of-${n}: rule + salt provisioned`, false, prov.errors.join('; '))
    return null
  }
  s.ok(`${mode} ${k}-of-${n}: slot ready (committee=${committee.length}) in ${((Date.now() - t0) / 1000).toFixed(1)}s`, true)
  return {slot, committee, mpk}
}

// Run `fn` on `conc` workers for `durationMs`; collect throughput + latency pctls.
async function loadTest(durationMs: number, conc: number, fn: () => Promise<boolean>) {
  const lat: number[] = []
  let ok = 0
  let fail = 0
  const end = Date.now() + durationMs
  async function worker() {
    while (Date.now() < end) {
      const t = Date.now()
      let good = false
      try {
        good = await fn()
      } catch {
        // failed op; `good` stays false
      }
      lat.push(Date.now() - t)
      if (good) ok++
      else fail++
    }
  }
  const t0 = Date.now()
  await Promise.all(Array.from({length: conc}, () => worker()))
  const wall = (Date.now() - t0) / 1000
  lat.sort((a, b) => a - b)
  const pct = (p: number) => (lat.length ? lat[Math.min(lat.length - 1, Math.floor((p / 100) * lat.length))]! : 0)
  return {ok, fail, thr: ok / wall, p50: pct(50), p95: pct(95), p99: pct(99)}
}

interface Row {
  label: string
  thr: number
  ok: number
  fail: number
  p50: number
  p95: number
  p99: number
}
const signRows: Row[] = []
const decRows: Row[] = []

s.info(`config: ${CONC} concurrent, ${DURATION / 1000}s per slot, ${NODES}-node fleet, coordination=${SPREAD ? 'SPREAD (round-robin coordinator + random signer sets)' : 'single-coordinator'}`)

// ── optional CONCURRENT slot-creation burst ───────────────────────────────────
// One fresh wallet per slot (the realistic every-slot-its-own-user shape — no
// nonce lanes), all createKeySlotFiltered txs fired together, then every slot
// polled to key-served. Reports submit + ready percentiles and the burst's
// resource footprint.
const BURST = Number(process.env.KK_CREATE_BURST || 0)
const RUN_MATRIX = process.env.KK_MATRIX !== '0'
const burstPhase = `create burst×${BURST}`
if (BURST > 0) {
  s.info(`burst: funding ${BURST} creator wallets (gas only)…`)
  const wallets = Array.from({length: BURST}, () => createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: generateClientKey(), chainId: cfg.chainId}))
  const baseNonce = await client.pub.getTransactionCount({address: client.address})
  await Promise.all(
    wallets.map((w, i) =>
      client.wallet.sendTransaction({to: w.address, value: parseEther('0.1'), nonce: baseNonce + i}).then(h => client.pub.waitForTransactionReceipt({hash: h})),
    ),
  )
  statsPhase = burstPhase
  // Fire the raw createKeySlotFiltered txs WITHOUT waiting for receipts, and
  // poll readiness immediately — the true DKG ceremony time is
  // (key served) − (block inclusion, from the receipt's block timestamp).
  // Waiting on receipts first (viem polls ~4s) hides sub-4s ceremonies.
  // Readiness polling rotates one node per tick per slot (committee membership
  // is unknown until a member answers 200) to bound harness request volume.
  const keyReg = requireAddress(cfg.book, 'KeyRegistry')
  // Opaque on purpose: a burst slot is only polled to key-served and never has a
  // rule provisioned, so nothing re-derives this and no salt is needed.
  const ruleCommitmentHash = keccak256(toHex(SLOT_DCQL_RULE))
  const burstTags = [keccak256(toHex('keykeeper'))]
  const t0 = Date.now()
  const results = await Promise.all(
    wallets.map(async (w, i) => {
      const mode: 'frost' | 'bls' = i % 2 === 0 ? 'bls' : 'frost'
      const n = mode === 'frost' ? NODES : Math.min(5, NODES)
      const k = Math.min(3, n)
      const slotId = `0x${randomBytes(32).toString('hex')}` as Hex
      const salt = `0x${randomBytes(32).toString('hex')}` as Hex
      try {
        const tx = await w.wallet.writeContract({
          address: keyReg,
          abi: keyRegistryAbi,
          functionName: 'createKeySlotFiltered',
          // …, mode, auth (AuthType.Unspecified = 0), salt, requiredTags
          args: [slotId, ruleCommitmentHash, k, n, mode === 'frost' ? 0 : 1, 0, salt, burstTags],
        })
        // Block-inclusion timestamp resolves in the background while we poll.
        let inclMs = 0
        const incl = w.pub
          .waitForTransactionReceipt({hash: tx})
          .then(async r => {
            const b = await w.pub.getBlock({blockNumber: r.blockNumber})
            inclMs = Number(b.timestamp) * 1000
          })
          .catch(() => undefined)
        const keyRe = new RegExp(`^[0-9a-f]{${mode === 'frost' ? 64 : 192}}$`, 'i')
        const deadline = Date.now() + 180_000
        let probe = i % cfg.nodeUrls.length
        let readyAt = 0
        while (Date.now() < deadline && !readyAt) {
          const u = cfg.nodeUrls[probe++ % cfg.nodeUrls.length]!
          try {
            const r = await fetch(`${u}/v1/keys/${slotId}/public`, {signal: AbortSignal.timeout(2000)})
            if (r.status === 200) {
              const j = (await r.json()) as {group_public_key?: string}
              if (j.group_public_key && keyRe.test(j.group_public_key)) readyAt = Date.now()
            }
          } catch {
            /* keep polling */
          }
          if (!readyAt) await sleep(250)
        }
        await incl
        if (!readyAt) return {ok: false, mode, dkgMs: -1}
        // Clamp: block timestamps have 1s resolution and can nominally trail
        // the poll clock; a ceremony can't take negative time.
        const dkgMs = inclMs ? Math.max(0, readyAt - inclMs) : -1
        return {ok: true, mode, dkgMs}
      } catch {
        return {ok: false, mode, dkgMs: -1}
      }
    }),
  )
  statsPhase = 'idle'
  const wall = (Date.now() - t0) / 1000
  const good = results.filter(r => r.ok)
  const pctOf = (xs: number[], p: number) => {
    const s2 = [...xs].sort((a, b) => a - b)
    return s2.length ? s2[Math.min(s2.length - 1, Math.floor((p / 100) * s2.length))]! : 0
  }
  const dkgOf = (m: 'frost' | 'bls') => good.filter(r => r.mode === m && r.dkgMs >= 0).map(r => r.dkgMs)
  const fmt2 = (xs: number[]) => (xs.length ? `p50=${(pctOf(xs, 50) / 1000).toFixed(1)}s p95=${(pctOf(xs, 95) / 1000).toFixed(1)}s max=${(Math.max(...xs) / 1000).toFixed(1)}s` : 'n/a')
  s.info(
    `BURST ${BURST} concurrent creates: ${good.length}/${BURST} ready, wall ${wall.toFixed(1)}s (${((good.length / wall) * 60).toFixed(0)} slots/min)\n` +
      `    DKG ceremony (ready − block-inclusion, ±1s): bls[${dkgOf('bls').length}] ${fmt2(dkgOf('bls'))} · frost[${dkgOf('frost').length}] ${fmt2(dkgOf('frost'))}`,
  )
  metric(`burst ${BURST} end-to-end`, Math.round((good.length / wall) * 60), 'slots/min')
  metric(`burst ${BURST} bls DKG p95`, Math.round(pctOf(dkgOf('bls'), 95) / 100) / 10, 's')
  metric(`burst ${BURST} frost DKG p95`, Math.round(pctOf(dkgOf('frost'), 95) / 100) / 10, 's')
  s.ok(`burst: ≥95% of ${BURST} concurrent slots became ready`, good.length / BURST >= 0.95, `${good.length}/${BURST}`)
}

// ── FROST signing across k ────────────────────────────────────────────────────
for (const c of RUN_MATRIX ? FROST_SET : []) {
  const made = await createSlot(c.mode, c.k, c.n)
  if (!made) continue
  const target = made.committee[0]!
  // Verified probe: one cryptographically checked signature before measuring.
  const m = randomBytes(32).toString('hex')
  const sg = (await (await fetch(`${target}/v1/sign`, {method: 'POST', headers: H, body: JSON.stringify({key_slot_id: made.slot, message_hex: m})})).json()) as {signature_r?: string; signature_z?: string; group_public_key?: string}
  const probeOk = !!sg.signature_r && frostVerify(hexToBytes(`0x${sg.signature_r}`), hexToBytes(`0x${sg.signature_z}`), hexToBytes(`0x${sg.group_public_key}`), hexToBytes(`0x${m}`))
  s.ok(`sign ${c.k}-of-${c.n}: probe signature verifies`, probeOk)
  if (!probeOk) continue
  statsPhase = `sign ${c.k}-of-${c.n}`
  // SPREAD: rotate the coordinator over every committee member and draw a fresh
  // random signing set per request. The demo fleet's keeper operator ids are
  // 1..n (the default 1..k set the probe uses relies on the same fact).
  const signTargets = SPREAD ? made.committee : [target]
  const signIds = Array.from({length: c.n}, (_, i) => i + 1)
  let signRr = 0
  const st = await loadTest(DURATION, CONC, async () => {
    const t = signTargets[signRr++ % signTargets.length]!
    const body = JSON.stringify({
      key_slot_id: made.slot,
      message_hex: randomBytes(32).toString('hex'),
      ...(SPREAD ? {signing_set: pickSet(signIds, c.k)} : {}),
    })
    const r = await fetch(`${t}/v1/sign`, {method: 'POST', headers: H, body, signal: AbortSignal.timeout(30000)})
    return r.ok
  })
  statsPhase = 'idle'
  const label = `${c.k}-of-${c.n}`
  signRows.push({label, ...st})
  s.info(`SIGN ${label}: ${st.thr.toFixed(1)} ops/s  ok=${st.ok} fail=${st.fail}  p50=${st.p50}ms p95=${st.p95}ms p99=${st.p99}ms`)
  metric(`FROST sign ${label} throughput`, Math.round(st.thr * 10) / 10, 'ops/s')
}

// ── BLS decrypt across k-of-n ─────────────────────────────────────────────────
for (const c of RUN_MATRIX ? BLS_SET : []) {
  const made = await createSlot(c.mode, c.k, c.n)
  if (!made) continue
  // committee map: shard identifier (per node) → libp2p peer id
  const blsPeers: Array<{id: number; peer_id: string}> = []
  for (const url of made.committee) {
    try {
      const info = (await (await fetch(`${url}/v1/info`)).json()) as {peer_id: string}
      const sr = await fetch(`${url}/v1/shards/key`, {method: 'POST', headers: H, body: JSON.stringify({key_slot_id: made.slot})})
      if (!sr.ok) continue
      const {identifier} = (await sr.json()) as {identifier: number}
      blsPeers.push({id: identifier, peer_id: info.peer_id})
    } catch {
      /* skip */
    }
  }
  blsPeers.sort((a, b) => a.id - b.id)
  if (blsPeers.length < c.k) {
    s.ok(`decrypt ${c.k}-of-${c.n}: resolved committee peers`, false, `${blsPeers.length} < k`)
    continue
  }
  const identity = 'stress-keyops-committees'
  const env = encryptEnvelope(hexToBytes(made.slot), hexToBytes(`0x${made.mpk}`), new TextEncoder().encode(identity), new TextEncoder().encode('stress plaintext'), 0n)
  const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64')
  const body = JSON.stringify({
    key_slot_id: made.slot,
    ciphertext: {u: b64(env.ciphertext.u), nonce: b64(env.ciphertext.nonce), aead_ct: b64(env.ciphertext.aeadCt)},
    identity,
    decrypting_set: blsPeers.slice(0, c.k).map(p => p.id),
    bls_peers: blsPeers,
  })
  const target = made.committee[0]!
  // Verified probe: one exact-plaintext recovery before measuring.
  const dr = (await (await fetch(`${target}/v1/decrypt`, {method: 'POST', headers: H, body})).json()) as {plaintext?: string}
  const probeOk = Buffer.from(dr.plaintext ?? '', 'base64').toString() === 'stress plaintext'
  s.ok(`decrypt ${c.k}-of-${c.n}: probe recovers plaintext`, probeOk)
  if (!probeOk) continue
  statsPhase = `decrypt ${c.k}-of-${c.n}`
  // SPREAD: rotate the serving node over the committee and draw a fresh random
  // decrypting set per request (bls_peers/ciphertext stay constant).
  const decTargets = SPREAD ? made.committee : [target]
  const decIds = blsPeers.map(p => p.id)
  const baseReq = {
    key_slot_id: made.slot,
    ciphertext: {u: b64(env.ciphertext.u), nonce: b64(env.ciphertext.nonce), aead_ct: b64(env.ciphertext.aeadCt)},
    identity,
    bls_peers: blsPeers,
  }
  let decRr = 0
  const st = await loadTest(DURATION, CONC, async () => {
    const t = decTargets[decRr++ % decTargets.length]!
    const reqBody = SPREAD ? JSON.stringify({...baseReq, decrypting_set: pickSet(decIds, c.k)}) : body
    const r = await fetch(`${t}/v1/decrypt`, {method: 'POST', headers: H, body: reqBody, signal: AbortSignal.timeout(30000)})
    return r.ok
  })
  statsPhase = 'idle'
  const label = `${c.k}-of-${c.n}`
  decRows.push({label, ...st})
  s.info(`DECRYPT ${label}: ${st.thr.toFixed(1)} ops/s  ok=${st.ok} fail=${st.fail}  p50=${st.p50}ms p95=${st.p95}ms p99=${st.p99}ms`)
  metric(`BLS decrypt ${label} throughput`, Math.round(st.thr * 10) / 10, 'ops/s')
}

// ── summary ───────────────────────────────────────────────────────────────────
const fmt = (r: Row) => `${r.label.padEnd(8)} ${r.thr.toFixed(1).padStart(7)} ops/s   p50=${String(r.p50).padStart(4)}ms  p95=${String(r.p95).padStart(4)}ms  p99=${String(r.p99).padStart(4)}ms  ok=${r.ok} fail=${r.fail}`
s.info('── FROST sign vs committee ──')
for (const r of signRows) s.info(fmt(r))
s.info('── BLS decrypt vs committee ──')
for (const r of decRows) s.info(fmt(r))

// Stop the sampler before summarizing so no half-finished round trip lands
// mid-report; a final `docker stats` call takes ~2s to drain.
statsStop = true
await statsDone
if (statSamples.length) {
  s.info('── node resources per phase (docker stats: cpu %/container, mem MiB) ──')
  const phases = [...(BURST > 0 ? [burstPhase] : []), ...signRows.map(r => `sign ${r.label}`), ...decRows.map(r => `decrypt ${r.label}`)]
  for (const ph of phases) {
    const line = resourceLine(ph)
    if (line) s.info(`${ph.padEnd(17)} ${line}`)
  }
  const bench = statSamples.filter(x => x.phase !== 'setup' && x.phase !== 'idle')
  if (bench.length) {
    const cpuPeak = bench.reduce((a, x) => (x.cpu > a.cpu ? x : a))
    const memPeak = bench.reduce((a, x) => (x.memMb > a.memMb ? x : a))
    s.info(`overall under load: cpu peak ${cpuPeak.cpu.toFixed(0)}% (${cpuPeak.name}, ${cpuPeak.phase}) · mem peak ${memPeak.memMb.toFixed(0)}MB (${memPeak.name}, ${memPeak.phase})`)
    metric('fleet cpu peak under load', Math.round(cpuPeak.cpu), '%')
    metric('fleet mem peak under load', Math.round(memPeak.memMb), 'MB')
  }
}

s.ok('all benchmarked slots kept ≥95% success', [...signRows, ...decRows].every(r => r.ok / (r.ok + r.fail) >= 0.95))

s.done()
