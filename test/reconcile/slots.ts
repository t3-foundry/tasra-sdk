// Reconcile: the demo slot, three ways. The explorer's view must match BOTH
// the nodes' published key (operational reality) AND the on-chain KeyRegistry
// (canonical truth).
//
// Run: tsx test/reconcile/slots.ts

import {Suite} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig} from '../fleet/_fleet.ts'
import {chainClient, explorer, reconcileGate} from './_explorer.ts'

interface ExplorerSlot {
  slotId: string
  creator: string
  /** The EXPLORER's JSON field. It adopted the contract's name in the same change,
   *  so both sides now say `ruleCommitment` - the SALTED commitment, never `keccak256(rule)`. */
  ruleCommitment: string
  k: number
  n: number
  mode: string
  publicKey: string
  epoch: number
  exists: boolean
  cancelled: boolean
}
interface OnchainSlot {
  creator: string
  /** The SALTED commitment — `KeySlot.ruleCommitment` on-chain. */
  ruleCommitment: string
  threshold: {k: number; n: number}
  mode: number
  publicKey: string
  epoch: bigint
  exists: boolean
  cancelled: boolean
}

const cfg = loadFleetConfig()
const s = new Suite('reconcile: explorer /slots ↔ nodes ↔ chain')

if (!(await gate(s, cfg)) || !(await reconcileGate(s, cfg))) {
  s.done()
  process.exit(0)
}
if (!cfg.slotId) {
  s.ok('demo slot id present', false)
  s.done()
  process.exit(1)
}

const ex = await explorer<ExplorerSlot>(cfg, `/slots/${cfg.slotId}`)
s.eq('explorer slotId matches', ex.slotId.toLowerCase(), cfg.slotId)
s.ok('explorer marks slot existing + not cancelled', ex.exists && !ex.cancelled)

// ── explorer vs nodes (operational reality) ──────────────────────────────────
const committee = await discoverCommittee(cfg, cfg.slotId)
const member = committee[0]
if (member) {
  const pub = (await (
    await fetch(`${member}/v1/keys/${cfg.slotId}/public`, {signal: AbortSignal.timeout(4000)})
  ).json()) as {group_public_key: string; threshold_k: number; threshold_n: number; epoch: number}
  s.eq('explorer publicKey == node group_public_key', ex.publicKey.toLowerCase(), `0x${pub.group_public_key.toLowerCase()}`)
  s.eq('explorer k == node threshold_k', ex.k, pub.threshold_k)
  s.eq('explorer n == node threshold_n', ex.n, pub.threshold_n)
  s.eq('explorer epoch == node epoch', ex.epoch, pub.epoch)
}

// ── explorer vs chain (canonical truth) ──────────────────────────────────────
const ch = chainClient(cfg)
const oc = (await ch.readers.keyRegistry.getKeySlot(cfg.slotId)) as OnchainSlot
s.eq('explorer publicKey == chain publicKey', ex.publicKey.toLowerCase(), oc.publicKey.toLowerCase())
s.eq('explorer k == chain threshold.k', ex.k, oc.threshold.k)
s.eq('explorer n == chain threshold.n', ex.n, oc.threshold.n)
s.eq('explorer epoch == chain epoch', BigInt(ex.epoch), oc.epoch)
s.eq('explorer creator == chain creator', ex.creator.toLowerCase(), oc.creator.toLowerCase())
s.eq('explorer ruleCommitment == chain ruleCommitment', ex.ruleCommitment.toLowerCase(), oc.ruleCommitment.toLowerCase())

s.done()
