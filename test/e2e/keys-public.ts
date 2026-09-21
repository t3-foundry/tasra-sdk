// E2E: the slot's public key is consistent across the whole committee.
//
// Every committee node must publish the SAME group public key, k, n, epoch and
// mode for the slot (they ran one DKG); non-committee nodes must 404. This is
// the "the fleet agrees with itself" check that the reconcile suites build on.
//
// Run: tsx test/e2e/keys-public.ts

import {Suite} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig} from '../fleet/_fleet.ts'

interface PublicReply {
  key_slot_id: string
  threshold_k: number
  threshold_n: number
  epoch: number
  group_public_key: string
  mode: string
}

const cfg = loadFleetConfig()
const s = new Suite('e2e: slot public key consistency')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}
if (!cfg.slotId) {
  s.ok('demo slot id present', false)
  s.done()
  process.exit(1)
}

const committee = await discoverCommittee(cfg, cfg.slotId)
s.ok('committee has at least k=2 nodes', committee.length >= 2, `found ${committee.length}`)

const replies: PublicReply[] = []
for (const url of committee) {
  const res = await fetch(`${url}/v1/keys/${cfg.slotId}/public`, {signal: AbortSignal.timeout(4000)})
  s.ok(`node ${url.replace(/^https?:\/\//, '')} serves /public (200)`, res.ok, `HTTP ${res.status}`)
  if (res.ok) replies.push((await res.json()) as PublicReply)
}

if (replies.length >= 1) {
  const first = replies[0]!
  s.ok('group public key is 96 bytes (192 hex chars)', /^[0-9a-f]{192}$/i.test(first.group_public_key))
  s.eq('slot id echoed by node matches', `0x${first.key_slot_id.toLowerCase()}`, cfg.slotId)
  s.ok('threshold is well-formed (1 ≤ k ≤ n)', first.threshold_k >= 1 && first.threshold_k <= first.threshold_n)
  s.info(`k=${first.threshold_k} n=${first.threshold_n} epoch=${first.epoch} mode=${first.mode}`)

  // All committee members must agree field-for-field.
  for (const r of replies.slice(1)) {
    s.eq('committee agrees on group_public_key', r.group_public_key, first.group_public_key)
    s.eq('committee agrees on threshold_k', r.threshold_k, first.threshold_k)
    s.eq('committee agrees on threshold_n', r.threshold_n, first.threshold_n)
    s.eq('committee agrees on epoch', r.epoch, first.epoch)
    s.eq('committee agrees on mode', r.mode, first.mode)
  }

  s.eq('committee size matches threshold_n', committee.length, first.threshold_n)
}

// A node outside the committee must NOT serve the slot.
const outsiders = cfg.nodeUrls.filter(u => !committee.includes(u))
if (outsiders.length) {
  const res = await fetch(`${outsiders[0]}/v1/keys/${cfg.slotId}/public`, {signal: AbortSignal.timeout(4000)})
  s.ok(`non-committee node ${outsiders[0]!.replace(/^https?:\/\//, '')} 404s the slot`, res.status === 404, `HTTP ${res.status}`)
}

s.done()
