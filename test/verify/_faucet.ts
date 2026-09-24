// Real, no-mock funding source for the verify harness.
//
// A fresh sovereign account needs gas (ETH) to sign anything. On a public
// dev/testnet a faucet SERVICE hands that out; the network-only fleet doesn't
// run one, so we fall back to the demo DEPLOYER key (from chain.env) doing the
// real on-chain transfer. Either way the funding is a real signed transaction —
// no mock, no shortcut. This backs the intent of src/slots/faucet.ts (`httpFaucet`)
// for environments where the HTTP service isn't present.
//
// EURC is NOT handed out here: the demo MockEurc is open-mint (anyone can
// `mint`), so the client mints its own EURC and buys TSRA on the bonding curve
// (the production acquisition path). This helper only guarantees gas.

import {parseEther, type Hex} from 'viem'
import {httpFaucet} from '../../src/slots/faucet.ts'
import {createTasraWriteClient} from '../../src/chain/write.ts'
import type {FleetConfig} from '../fleet/_fleet.ts'

export interface FundResult {
  via: 'faucet-service' | 'deployer'
  ethWei: bigint
}

/**
 * Ensure `address` holds at least `minEthWei` of gas. Prefers a live faucet
 * service at cfg.faucetUrl; otherwise the deployer sends ETH directly.
 */
export async function ensureGas(
  cfg: FleetConfig,
  address: Hex,
  minEthWei: bigint = parseEther('1'),
): Promise<FundResult> {
  // 1. real faucet service, if one is reachable
  try {
    const probe = await fetch(`${cfg.faucetUrl}/health`, {signal: AbortSignal.timeout(2000)})
    if (probe.ok) {
      await httpFaucet(cfg.faucetUrl).fund(address)
      return {via: 'faucet-service', ethWei: minEthWei}
    }
  } catch {
    /* no faucet service — fall through to the deployer */
  }

  // 2. deployer stand-in (still a real on-chain transfer)
  if (!cfg.deployPk) throw new Error('no faucet service and no DEPLOY_PK in chain.env — cannot fund')
  const funder = createTasraWriteClient({
    rpcUrl: cfg.rpcUrl,
    addresses: cfg.book,
    privateKey: cfg.deployPk as Hex,
    chainId: cfg.chainId,
  })
  await funder.sendEth(address, minEthWei)
  return {via: 'deployer', ethWei: minEthWei}
}
