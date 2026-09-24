// The RPC the explorer CONTAINER dials, derived from the fleet's chain declaration
// (`credentials/chain.env`) when the environment does not say. Pure, so it is unit-tested.
import {existsSync, readFileSync} from 'node:fs'

/** CHAIN_RPC + CHAIN_ID as the host sees them, from a `KEY=value` / `export KEY=value` file. */
export function fleetChain(chainEnvPath: string): {rpc?: string; chainId?: string} {
  if (!existsSync(chainEnvPath)) return {}
  return parseFleetChain(readFileSync(chainEnvPath, 'utf8'))
}

export function parseFleetChain(text: string): {rpc?: string; chainId?: string} {
  const kv: Record<string, string> = {}
  for (const line of text.split('\n')) {
    const m = /^(?:export\s+)?([A-Z0-9_]+)=(.*)$/.exec(line.trim())
    if (!m) continue
    const [, key, value] = m
    if (key !== undefined && value !== undefined) kv[key] = value.replace(/^["']|["']$/g, '')
  }
  return {rpc: kv.CHAIN_RPC, chainId: kv.CHAIN_ID ?? kv.KK_CHAIN_ID}
}

/**
 * Precedence: KK_EXPLORER_RPC_URL (the Avalanche declaration exports it), else the fleet's
 * CHAIN_RPC mapped from the host's view to the container's (localhost:8545 is the besu
 * container; any other localhost is the Docker host gateway), else the besu default.
 * Hardcoding besu:8545 pointed the explorer at a dead host on every Avalanche fleet whose
 * environment lacked the override (Rust harness run 2, 2026-09-18).
 */
export function explorerRpcUrl(env: Record<string, string | undefined>, fleetRpc?: string): string {
  if (env.KK_EXPLORER_RPC_URL) return env.KK_EXPLORER_RPC_URL
  if (fleetRpc) {
    try {
      const u = new URL(fleetRpc)
      if (['localhost', '127.0.0.1', '0.0.0.0'].includes(u.hostname)) {
        if (u.port === '8545') return 'http://besu:8545'
        u.hostname = 'host.docker.internal'
        return u.toString().replace(/\/$/, '')
      }
      return fleetRpc
    } catch {
      /* fall through to the default */
    }
  }
  return 'http://besu:8545'
}
