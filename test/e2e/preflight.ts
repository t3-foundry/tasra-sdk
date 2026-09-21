// E2E preflight: the fleet is up, every daemon answers, and the demo slot has
// finished DKG. Run this first — the other e2e suites assume it passed.
//
// Run: tsx test/e2e/preflight.ts

import {Suite} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig} from '../fleet/_fleet.ts'
import {nodeApi, verifierApi} from '../../src/chain/offchain.ts'

const cfg = loadFleetConfig()
const s = new Suite('e2e: preflight')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}

s.ok('TASRA_SLOT_ID is a slot id', /^0x[0-9a-f]{64}$/.test(cfg.slotId), cfg.slotId || '(empty)')
s.info(`chain ${cfg.chainId} via ${cfg.rpcUrl}`)

// ── nodes ────────────────────────────────────────────────────────────────
for (const url of cfg.nodeUrls) {
  try {
    const ready = await nodeApi.readyz(url)
    s.ok(`node ${url} /readyz`, (ready.status ?? '').toLowerCase() !== 'fail')
    const info = await nodeApi.info(url)
    s.ok(
      `node ${url} /v1/info (id=${info.node_identifier}, peers=${info.connected_peers ?? '?'})`,
      typeof info.node_identifier === 'number',
    )
  } catch (e) {
    s.ok(`node ${url} reachable`, false, String(e))
  }
}

// ── verifiers ──────────────────────────────────────────────────────────────
for (const url of cfg.verifierUrls) {
  try {
    const info = await verifierApi.info(url)
    s.ok(`verifier ${url} /v1/info (ttl=${info.jwt_ttl_secs ?? '?'}s)`, !!info.version)
  } catch (e) {
    s.ok(`verifier ${url} reachable`, false, String(e))
  }
}

// ── chain ──────────────────────────────────────────────────────────────────
try {
  const res = await fetch(cfg.rpcUrl, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', method: 'eth_chainId', params: [], id: 1}),
    signal: AbortSignal.timeout(4000),
  })
  const body = (await res.json()) as {result?: string}
  const id = body.result ? parseInt(body.result, 16) : NaN
  s.eq(`besu RPC chainId`, id, cfg.chainId)
} catch (e) {
  s.ok('besu RPC reachable', false, String(e))
}

// ── demo slot DKG complete + committee resolved ──────────────────────────────
if (cfg.slotId) {
  const committee = await discoverCommittee(cfg, cfg.slotId)
  s.ok(`demo slot committee resolved (${committee.length} node(s))`, committee.length >= 2)
  s.info(`committee: ${committee.map(u => u.replace(/^https?:\/\//, '')).join(', ') || '(none)'}`)
  const member = committee[0]
  if (member) {
    const pub = await nodeApi.keySlotPublic(member, cfg.slotId)
    s.ok('demo slot has a group public key (DKG complete)', !!pub.group_public_key)
  }
}

s.done()
