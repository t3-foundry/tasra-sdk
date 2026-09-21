// Slashing (read-only): the explorer's /slashing feed must reflect real
// on-chain transactions. For a sample of records we confirm the referenced tx
// exists on-chain, succeeded, and sits in the block the explorer claims.
//
// Run: tsx test/slashing/history.ts

import {Suite} from '../fleet/_assert.ts'
import {gate, loadFleetConfig} from '../fleet/_fleet.ts'
import {chainClient, explorer, reconcileGate} from '../reconcile/_explorer.ts'

interface SlashItem {
  id: number
  kind: string
  contract: string
  operator: string | null
  bps: number | null
  block: number
  txHash: `0x${string}`
}

const cfg = loadFleetConfig()
const s = new Suite('slashing: explorer /slashing ↔ chain (read-only)')

if (!(await gate(s, cfg)) || !(await reconcileGate(s, cfg))) {
  s.done()
  process.exit(0)
}

let feed = await explorer<{count: number; items: SlashItem[]}>(cfg, '/slashing')
if (process.env.TASRA_CHECKS_REQUIRED === '1') {
  const deadline=Date.now()+60000
  while (feed.items.length===0 && Date.now()<deadline) {
    await new Promise(resolve=>setTimeout(resolve,2000))
    feed=await explorer<{count:number;items:SlashItem[]}>(cfg,'/slashing')
  }
}
s.ok('explorer count matches array length', feed.count === undefined || feed.count >= feed.items.length)
s.info(`explorer reports ${feed.items.length} slashing record(s)`)

if (feed.items.length === 0) {
  s.skip('tx reconciliation', 'no slashing records on this fleet yet')
  s.done()
  process.exit(0)
}

const ch = chainClient(cfg)
const head = Number(await ch.getBlockNumber())

// Sample up to 8 records so the suite stays fast on a long history.
const sample = feed.items.slice(0, 8)
for (const it of sample) {
  const tag = `#${it.id} ${it.kind}`
  s.ok(`${tag} block ≤ chain head`, it.block <= head, `block ${it.block}, head ${head}`)
  try {
    const rcpt = await ch.client.getTransactionReceipt({hash: it.txHash})
    s.eq(`${tag} tx exists + succeeded`, rcpt.status, 'success')
    s.eq(`${tag} tx block matches explorer`, Number(rcpt.blockNumber), it.block)
  } catch (e) {
    s.ok(`${tag} tx is on-chain`, false, String(e).slice(0, 80))
  }
}

s.done()
