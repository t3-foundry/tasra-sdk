// Faucet client — funds a fresh sovereign client account with gas (ETH) + TSRA
// so it can create and operate a slot. The faucet is an HTTP service on the
// network (dev/testnet); the client just asks it to top up an address.
//
// Interface-driven: products inject a Faucet implementation; a test or another
// environment can supply a different funding source behind the same shape.

export interface FaucetGrant {
  address: string
  /** Native gas funded, wei (decimal string). */
  ethWei?: string
  /** TSRA funded, base units (decimal string). */
  tsra?: string
  /** Funding tx hashes, if the faucet reports them. */
  txHashes?: string[]
}

export interface Faucet {
  /** Top up `address` with gas + TSRA. */
  fund(address: string): Promise<FaucetGrant>
}

/**
 * HTTP faucet client: POST {faucetUrl}/faucet {address} → FaucetGrant.
 * Matches the network faucet service.
 */
export function httpFaucet(faucetUrl: string): Faucet {
  const base = faucetUrl.replace(/\/$/, '')
  return {
    async fund(address: string): Promise<FaucetGrant> {
      const res = await fetch(`${base}/faucet`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({address}),
      })
      if (!res.ok) {
        let detail = ''
        try {
          detail = (await res.text()).slice(0, 200)
        } catch {
          /* ignore */
        }
        throw new Error(`faucet: HTTP ${res.status}${detail ? `: ${detail}` : ''}`)
      }
      return (await res.json()) as FaucetGrant
    },
  }
}
