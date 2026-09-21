// Reconcile: explorer /tasra/* token economics vs on-chain reads.
//   token supply/symbol/decimals, treasury balance, settlement escrow.
//
// Run: tsx test/reconcile/tasra.ts

import {Suite} from '../fleet/_assert.ts'
import {gate, loadFleetConfig} from '../fleet/_fleet.ts'
import {chainClient, explorer, reconcileGate} from './_explorer.ts'

const cfg = loadFleetConfig()
const s = new Suite('reconcile: explorer /tasra ↔ chain')

if (!(await gate(s, cfg)) || !(await reconcileGate(s, cfg))) {
  s.done()
  process.exit(0)
}

const ch = chainClient(cfg)

// ── token ────────────────────────────────────────────────────────────────
{
  const t = await explorer<{supply: string; symbol: string; decimals: number}>(cfg, '/tasra/token')
  s.eq('explorer supply == chain totalSupply', BigInt(t.supply), (await ch.readers.token.totalSupply()) as bigint)
  s.eq('explorer symbol == chain symbol', t.symbol, (await ch.readers.token.symbol()) as string)
  s.eq('explorer decimals == chain decimals', t.decimals, Number(await ch.readers.token.decimals()))
}

// ── treasury ─────────────────────────────────────────────────────────────
{
  const tr = await explorer<{balance: string}>(cfg, '/tasra/treasury')
  const treasuryAddr = cfg.book.Treasury
  if (treasuryAddr) {
    const onchain = (await ch.readers.token.balanceOf(treasuryAddr)) as bigint
    s.eq('explorer treasury balance == chain TSRA.balanceOf(treasury)', BigInt(tr.balance), onchain)
  } else {
    s.skip('treasury balance', 'no Treasury address in chain.env')
  }
}

// ── settlement ───────────────────────────────────────────────────────────
{
  const st = await explorer<{totalHeld: string}>(cfg, '/tasra/settlement')
  s.eq('explorer settlement totalHeld == chain totalHeld', BigInt(st.totalHeld), (await ch.readers.settlement.totalHeld()) as bigint)
}

s.done()
