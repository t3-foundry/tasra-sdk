// Shared helpers for the reconciliation suites: a typed GET against the
// explorer API (the thing under test) and a chain client (the source of truth).
//
// "Does the explorer reflect reality?" — every reconcile suite answers that by
// reading the same fact from the explorer and from the chain/nodes and asserting
// they agree.

import {createTasraChainClient} from '../../src/chain/client.ts'
import type {Suite} from '../fleet/_assert.ts'
import type {FleetConfig} from '../fleet/_fleet.ts'

export async function explorer<T>(cfg: FleetConfig, path: string): Promise<T> {
  const res = await fetch(`${cfg.explorerApi}${path}`, {signal: AbortSignal.timeout(8000)})
  if (!res.ok) throw new Error(`explorer GET ${path} → HTTP ${res.status}`)
  return (await res.json()) as T
}

export function chainClient(cfg: FleetConfig) {
  return createTasraChainClient({
    rpcUrl: cfg.rpcUrl,
    addresses: cfg.book,
    chainId: cfg.chainId,
  })
}

export function short(addr: string): string {
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`
}

/**
 * Gate: both the explorer API and the chain RPC must answer, and the address
 * book must be populated (reconcile compares against on-chain reads). Skips
 * cleanly otherwise — unless KK_FLEET_REQUIRED=1.
 */
export async function reconcileGate(s: Suite, cfg: FleetConfig): Promise<boolean> {
  let exOk = false
  try {
    await explorer(cfg, '/overview')
    exOk = true
  } catch {
    /* down */
  }
  let chOk = false
  try {
    await chainClient(cfg).getBlockNumber()
    chOk = true
  } catch {
    /* down */
  }
  const bookOk = !!cfg.book.NodeRegistry && !!cfg.book.TasraToken
  if (exOk && chOk && bookOk) return true
  const detail =
    `explorer ${cfg.explorerApi}=${exOk ? 'up' : 'DOWN'}, ` +
    `chain ${cfg.rpcUrl}=${chOk ? 'up' : 'DOWN'}, ` +
    `addresses=${bookOk ? 'ok' : 'MISSING'}`
  if (process.env.KK_FLEET_REQUIRED) {
    s.ok(`reconcile deps reachable (${detail})`, false)
    return false
  }
  s.skip('suite', `reconcile deps not reachable — ${detail}`)
  return false
}
