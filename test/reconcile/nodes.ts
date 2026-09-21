// Reconcile: explorer /nodes vs the on-chain NodeRegistry (source of truth).
// Every node the explorer lists must be a registered operator whose active
// flag, stake and pubkey match the chain.
//
// Run: tsx test/reconcile/nodes.ts

import {Suite} from '../fleet/_assert.ts'
import {gate, loadFleetConfig} from '../fleet/_fleet.ts'
import {chainClient, explorer, reconcileGate, short} from './_explorer.ts'

interface ExplorerNode {
  address: string
  pubkey: string
  stake: string
  rewardBalance: string
  active: boolean
}
interface OnchainNode {
  operator: string
  pubkey: string
  stake: bigint
  rewardBalance: bigint
  active: boolean
}

const cfg = loadFleetConfig()
const s = new Suite('reconcile: explorer /nodes ↔ chain')

if (!(await gate(s, cfg)) || !(await reconcileGate(s, cfg))) {
  s.done()
  process.exit(0)
}

const ex = await explorer<{count: number; nodes: ExplorerNode[]}>(cfg, '/nodes')
s.ok('explorer count matches array length', ex.count === ex.nodes.length, `${ex.count} vs ${ex.nodes.length}`)
s.ok('explorer lists at least one node', ex.nodes.length > 0)

const ch = chainClient(cfg)

// ⚠ This comparison is a TOCTOU: the explorer row was indexed at some block, and the
// chain is then read at HEAD. Any operator whose stake is MOVING can differ between
// the two reads while both are perfectly correct.
//
// It went unnoticed for as long as it has existed because the demo fleet's only
// continuously-slashed operator (the KK_DEMO_FAULT_FALSESLASH victim) used to grind
// down to a bond of zero and STOP: `_slash` returns early with nothing left to take,
// emitting no event, so the row sat frozen and always agreed. Keeping that operator
// solvent — which the fleet now does, so the committee pool stays whole — turns it
// back into a target that changes every epoch, and the race became visible.
//
// Re-reading BOTH sides on a mismatch distinguishes the two cases without weakening
// the assertion: a value that merely moved between reads agrees on the second look,
// while an explorer that is genuinely stale or wrong disagrees every time. Pinning
// the chain read to the explorer's indexed block would be stricter still, but the
// explorer does not expose that height today.
async function eqSettled<T>(
  label: string,
  fromExplorer: (row: ExplorerNode) => T,
  fromChain: (oc: OnchainNode) => T,
  addr: string,
  row: ExplorerNode,
  oc: OnchainNode,
): Promise<void> {
  if (fromExplorer(row) === fromChain(oc)) {
    s.eq(label, fromExplorer(row), fromChain(oc))
    return
  }
  // The correct assertion for an INDEXER is convergence, not instantaneous equality.
  // An immediate re-read is far too tight a window: the demo fleet's false-slash victim
  // moves every ~4 seconds (measured 2000 → 1800 → 1600 → 1400 in twelve), and the
  // explorer trails the chain by roughly one slash, so at any given instant the two
  // legitimately differ while the explorer is perfectly correct.
  //
  // Retrying until they agree keeps the assertion meaningful in the way that matters:
  // an explorer that is merely BEHIND catches up within a poll or two, while one that is
  // stale-forever or projecting a value the chain never had never converges and still
  // fails. Only the mismatch path pays the cost.
  let re = row
  let oc2 = oc
  for (let attempt = 0; attempt < 6; attempt++) {
    await new Promise(r => setTimeout(r, 2000))
    const fresh = await explorer<{nodes: ExplorerNode[]}>(cfg, '/nodes')
    const found = fresh.nodes.find(x => x.address.toLowerCase() === addr.toLowerCase())
    if (!found) {
      s.ok(label, false, 'operator vanished from the explorer between reads')
      return
    }
    re = found
    oc2 = (await ch.readers.nodeRegistry.nodeOf(addr as `0x${string}`)) as OnchainNode
    if (fromExplorer(re) === fromChain(oc2)) break
  }
  s.eq(label, fromExplorer(re), fromChain(oc2))
}

for (const n of ex.nodes) {
  const oc = (await ch.readers.nodeRegistry.nodeOf(n.address as `0x${string}`)) as OnchainNode
  const tag = short(n.address)
  s.ok(`${tag} is a registered operator`, oc.operator.toLowerCase() === n.address.toLowerCase())
  // `pubkey` is immutable after registration, so it needs no settle step — and a
  // mismatch there is always a real defect rather than a race.
  s.eq(`${tag} pubkey matches chain`, n.pubkey.toLowerCase(), oc.pubkey.toLowerCase())
  await eqSettled(`${tag} active matches chain`, r => r.active, o => o.active, n.address, n, oc)
  await eqSettled(`${tag} stake matches chain`, r => BigInt(r.stake), o => o.stake, n.address, n, oc)
  await eqSettled(
    `${tag} rewardBalance matches chain`,
    r => BigInt(r.rewardBalance), o => o.rewardBalance, n.address, n, oc,
  )
}

s.done()
