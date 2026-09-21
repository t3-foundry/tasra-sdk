import type {Address, Hex} from 'viem'
import type {TasraChainClient} from './client.js'
import {keyRegistryAbi} from './abis/keyRegistry.js'
import {thresholdRandomBeaconAbi} from './abis/thresholdRandomBeacon.js'

/** A creation may keep its slot/rule inputs, but needs a durably saved new commit salt. */
export class SlotCommitmentExpiredError extends Error {
  constructor(readonly chainId: number, readonly keyRegistry: Address, readonly slotId: Hex,
    readonly commitment: Hex, readonly creator: Address, readonly salt: Hex) {
    super('Slot commitment expired; reconcile outstanding relay requests before replacing its commit salt')
    this.name = 'SlotCommitmentExpiredError'
  }
}

/** Read-only recovery gate. The caller must also reconcile every outstanding signed request. */
export async function assertExpiredSlotCommitment(chain: TasraChainClient, error: SlotCommitmentExpiredError): Promise<void> {
  const registry = chain.addresses.KeyRegistry
  if (registry?.toLowerCase() !== error.keyRegistry.toLowerCase() || await chain.client.getChainId() !== error.chainId) {
    throw new Error('Commitment recovery belongs to a different deployment')
  }
  const blockNumber = await chain.client.getBlockNumber({cacheTime: 0})
  const [slot, commit, beacon] = await Promise.all([
    chain.client.readContract({address: registry, abi: keyRegistryAbi, functionName: 'getKeySlot', args: [error.slotId], blockNumber}),
    chain.client.readContract({address: registry, abi: keyRegistryAbi, functionName: 'slotCommits', args: [error.commitment], blockNumber}),
    chain.client.readContract({address: registry, abi: keyRegistryAbi, functionName: 'randomBeacon', blockNumber}),
  ])
  const epoch = await chain.client.readContract({address: beacon, abi: thresholdRandomBeaconAbi, functionName: 'epoch', blockNumber})
  if (slot.exists || commit[3] || commit[2].toLowerCase() !== error.creator.toLowerCase() || commit[0] === 0n || epoch <= commit[1]) {
    throw new Error('Commitment recovery requires an expired unused commitment and an absent slot')
  }
}
