// Reconcile: explorer /overview internal consistency + indexer freshness.
//   - chainId + head track the chain (the indexer is caught up),
//   - the beacon epoch matches the chain,
//   - and we PIN the meaning of counts.nodes: it is the TOTAL operator count
//     (nodes + verifiers + accountants), NOT the node-tagged count that
//     /nodes returns. Both are asserted against the chain so the difference is
//     documented, not a surprise.
//
// Run: tsx test/reconcile/overview.ts

import {Suite} from '../fleet/_assert.ts'
import {gate, loadFleetConfig} from '../fleet/_fleet.ts'
import {chainClient, explorer, reconcileGate} from './_explorer.ts'

interface Overview {
  chainId: number
  head: number
  indexedEvents: number
  counts: {nodes: number; activeNodes: number; slots: number; slashes: number; events: number}
  beacon: {epoch: number; lastUpdate: number}
}

const cfg = loadFleetConfig()
const s = new Suite('reconcile: explorer /overview ↔ chain (freshness)')

if (!(await gate(s, cfg)) || !(await reconcileGate(s, cfg))) {
  s.done()
  process.exit(0)
}

const ch = chainClient(cfg)
const ov = await explorer<Overview>(cfg, '/overview')

s.eq('explorer chainId == chain', ov.chainId, cfg.chainId)

const head = Number(await ch.getBlockNumber())
// The indexer tails the chain: it should be at/just-behind the chain head. If it
// reports a head WELL ABOVE the chain, its DB is stale from a PREVIOUS chain
// instance (the chain was wiped/re-provisioned under a persisted explorer
// volume) — restart the explorer to re-index. That's a real "explorer ≠ reality"
// condition, so it fails loud with the cause.
if (ov.head > head + 5) {
  s.ok(
    'indexer head not ahead of chain (stale explorer DB vs a reset chain?)',
    false,
    `explorer head ${ov.head} ≫ chain head ${head} — the chain looks re-provisioned under a persisted explorer DB; restart/re-index the explorer`,
  )
} else {
  s.near('indexer is caught up with the chain (lag ≤ 50 blocks)', ov.head, head, 50)
}
s.ok('indexer has indexed events', ov.indexedEvents > 0)
s.ok('overview sees the demo slot', ov.counts.slots >= 1)

// counts.nodes is the FULL operator count, not the node-tagged subset.
const operatorCount = Number(await ch.readers.nodeRegistry.operatorCount())
s.eq('overview counts.nodes == chain operatorCount (ALL operators)', ov.counts.nodes, operatorCount)
const nodesList = await explorer<{count: number}>(cfg, '/nodes')
s.ok(
  'note: /nodes (node-tagged) ≤ overview counts.nodes (all operators)',
  nodesList.count <= ov.counts.nodes,
  `/nodes=${nodesList.count}, overview.counts.nodes=${ov.counts.nodes}`,
)
s.info(`/nodes lists ${nodesList.count} node-tagged operators of ${operatorCount} total on-chain`)

// beacon epoch consistency. The explorer indexes asynchronously (a 4 s poll behind a 10 s
// beacon) and the two reads are never one snapshot, so a single-shot compare read |66 - 68| on
// an otherwise green fleet. Compare until the two sides
// agree within the tolerance, ceiling 45 s — the same rule the network own reconcile check
// reconcile follows.
try {
  const deadline = Date.now() + 45_000
  let explorerEpoch = ov.beacon.epoch
  let chainEpoch = Number(await ch.readers.beacon.epoch())
  while (Math.abs(explorerEpoch - chainEpoch) > 1 && Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 3000))
    explorerEpoch = (await explorer<Overview>(cfg, '/overview')).beacon.epoch
    chainEpoch = Number(await ch.readers.beacon.epoch())
  }
  s.near('explorer beacon epoch == chain beacon epoch', explorerEpoch, chainEpoch, 1)
} catch (e) {
  s.skip('beacon epoch', `no ThresholdRandomBeacon readable (${String(e).slice(0, 60)})`)
}

s.done()
