// Reconcile: explorer /verifiers and /accountants vs the on-chain registry.
// Each operator the explorer puts in a role-set must be a registered operator
// whose active flag + stake match the chain.
//
// Run: tsx test/reconcile/sets.ts

import {Suite} from '../fleet/_assert.ts'
import {gate, loadFleetConfig} from '../fleet/_fleet.ts'
import {chainClient, explorer, reconcileGate, short} from './_explorer.ts'

interface RoleSet {
  role: string
  operators: Array<{address: string; stake: string; active: boolean}>
}
interface OnchainNode {
  operator: string
  stake: bigint
  active: boolean
}

const cfg = loadFleetConfig()
const s = new Suite('reconcile: explorer role-sets ↔ chain')

if (!(await gate(s, cfg)) || !(await reconcileGate(s, cfg))) {
  s.done()
  process.exit(0)
}

const ch = chainClient(cfg)

for (const path of ['/verifiers', '/accountants'] as const) {
  let set: RoleSet
  try {
    set = await explorer<RoleSet>(cfg, path)
  } catch (e) {
    s.ok(`explorer ${path} reachable`, false, String(e))
    continue
  }
  s.ok(`explorer ${path} lists operators (${set.operators.length})`, set.operators.length > 0)
  for (const op of set.operators) {
    const oc = (await ch.readers.nodeRegistry.nodeOf(op.address as `0x${string}`)) as OnchainNode
    const tag = `${set.role}:${short(op.address)}`
    s.ok(`${tag} is a registered operator`, oc.operator.toLowerCase() === op.address.toLowerCase())
    s.eq(`${tag} active matches chain`, op.active, oc.active)
    s.eq(`${tag} stake matches chain`, BigInt(op.stake), oc.stake)
  }
}

s.done()
