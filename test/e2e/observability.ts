// E2E: OBSERVABILITY surface on the prod fleet — health, readiness, info, metrics.
//
// Read-only: asserts every node/verifier is live, the Prometheus /metrics endpoint
// exposes the keykeeper_* families, the node has indexed slot creations and knows the
// registered operator set, and the verifiers report PRODUCTION mode (unsigned verify
// OFF, a trust anchor set).
//
// Run: tsx test/e2e/observability.ts

import {Suite} from '../fleet/_assert.ts'
import {gate, loadFleetConfig} from '../fleet/_fleet.ts'

const cfg = loadFleetConfig()
const s = new Suite('e2e: observability (health/readyz/info/metrics)')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}

const get = async (url: string) => {
  try {
    const r = await fetch(url, {signal: AbortSignal.timeout(5000)})
    return {status: r.status, body: await r.text()}
  } catch (e) {
    return {status: 0, body: String(e)}
  }
}

// ── nodes ─────────────────────────────────────────────────────────────────────
for (const [i, u] of cfg.nodeUrls.entries()) {
  s.ok(`node ${i + 1} /health is 200`, (await get(`${u}/health`)).status === 200)
  s.ok(`node ${i + 1} /readyz is 200`, (await get(`${u}/readyz`)).status === 200)
  const m = await get(`${u}/metrics`)
  // Probe metrics that are ALWAYS registered at startup (a counter + a gauge),
  // not event-gated families. keykeeper_chain_events_total is a labeled counter
  // that only renders once a chain event is processed LIVE, so it's absent on a
  // healthy-but-quiescent resumed node — a false negative for a "are metrics
  // exposed" smoke check. dkg_attempts_total (counter) and db_pool_size (gauge)
  // render from process start regardless of activity.
  s.ok(`node ${i + 1} /metrics exposes keykeeper_* families`, m.status === 200 && m.body.includes('keykeeper_dkg_attempts_total') && m.body.includes('keykeeper_db_pool_size'))
}

const infoRes = await get(`${cfg.nodeUrls[0]}/v1/info`)
const info = JSON.parse(infoRes.body) as {version: string; peer_id: string}
s.ok('node /v1/info carries version + libp2p peer_id', !!info.version && /^12D3Koo/.test(info.peer_id), `v${info.version} ${info.peer_id?.slice(0, 12)}`)

const m1 = (await get(`${cfg.nodeUrls[0]}/metrics`)).body
const created = Number(m1.match(/keykeeper_chain_events_total\{kind="KeySlotCreated"\}\s+(\d+)/)?.[1] ?? 0)
s.ok('node indexed KeySlotCreated chain events', created > 0, `KeySlotCreated=${created}`)

// "Node knows the registered operator set" — asserted via the source-agnostic
// keykeeper_operator_directory_size gauge, NOT the NodeRegistered EVENT counter.
// A resumed node subscribes from its persisted chain cursor (≈ head), so it never
// replays past NodeRegistered events — it learns the active set via the startup
// on-chain backfill (active_operators) instead. Its directory is full while its
// NodeRegistered event counter is legitimately 0, so the gauge (populated by BOTH
// the backfill and live events) is the honest signal. The raw event count is kept
// in the detail string for diagnostics only.
const registeredEvents = Number(m1.match(/keykeeper_chain_events_total\{kind="NodeRegistered"\}\s+(\d+)/)?.[1] ?? 0)
const dirSize = Number(m1.match(/keykeeper_operator_directory_size\s+(\d+)/)?.[1] ?? 0)
s.ok('node knows the registered operator set (directory populated)', dirSize > 0, `directory=${dirSize}, NodeRegistered events seen live=${registeredEvents}`)

// ── verifiers (production-mode assertions) ────────────────────────────────────
for (const [i, u] of cfg.verifierUrls.entries()) {
  s.ok(`verifier ${i + 1} /health is 200`, (await get(`${u}/health`)).status === 200)
  s.ok(`verifier ${i + 1} /metrics is 200`, (await get(`${u}/metrics`)).status === 200)
}
const vinfoRes = await get(`${cfg.verifierUrls[0]}/v1/info`)
const vinfo = JSON.parse(vinfoRes.body) as {unsigned_verify_enabled: boolean; vc_anchor_count: number}
// On a DEMO-FAULTS fleet (KK_VERIFY_DEMO_FAULTS=1) up.sh deliberately opens the
// unsigned /v1/verify path — the byzantine verifier scenarios (12/15) drive it by
// design, so asserting production posture would contradict the fleet we asked for.
// Assert the posture the requested fleet SHOULD have, in both directions.
if (process.env.KK_VERIFY_DEMO_FAULTS === '1') {
  s.ok('unsigned /v1/verify OPEN (demo-faults fleet — byzantine scenarios drive it)', vinfo.unsigned_verify_enabled === true)
} else {
  s.ok('verifier runs in PRODUCTION mode (unsigned /v1/verify OFF)', vinfo.unsigned_verify_enabled === false)
}
s.ok('verifier has a VC trust anchor configured', vinfo.vc_anchor_count >= 1, `anchors=${vinfo.vc_anchor_count}`)

// ── capability matrix: tECDSA EOA signing is built into the default node ──────
// tecdsa is an on-by-default cargo feature (addendum, 2026-06-28), so the
// /v1/sign/eoa-digest route is MOUNTED. It sits on the authenticated router, so an
// unauthenticated empty POST is rejected pre-handler (401/400-class) — anything but
// 404 proves the feature compiled in and the route exists. (404 would mean the node
// was built --no-default-features, i.e. tECDSA omitted.)
const tecdsa = await fetch(`${cfg.nodeUrls[0]}/v1/sign/eoa-digest`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}', signal: AbortSignal.timeout(4000)}).then(r => r.status).catch(() => 0)
s.ok('tECDSA /v1/sign/eoa-digest is built into this node (route mounted, not 404)', tecdsa !== 404 && tecdsa !== 0, `HTTP ${tecdsa}`)

s.done()
