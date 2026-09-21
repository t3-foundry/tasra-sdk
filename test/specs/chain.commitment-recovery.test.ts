import {beforeEach, expect, it, vi} from 'vitest'
import {SlotCommitmentExpiredError, assertExpiredSlotCommitment} from '../../src/chain/commitmentRecovery.js'
import type {TasraChainClient} from '../../src/chain/client.js'
const registry = `0x${'11'.repeat(20)}` as const, owner = `0x${'22'.repeat(20)}` as const
const failure = new SlotCommitmentExpiredError(31337, registry, `0x${'33'.repeat(32)}`, `0x${'44'.repeat(32)}`, owner, `0x${'55'.repeat(32)}`)
const state = {exists: false, used: false, owner, epoch: 9n, expiry: 8n}
const read = vi.fn(async ({functionName}: {functionName: string}) => {
  if (functionName === 'getKeySlot') return {exists: state.exists}
  if (functionName === 'slotCommits') return [5n, state.expiry, state.owner, state.used]
  if (functionName === 'randomBeacon') return registry
  if (functionName === 'epoch') return state.epoch
  throw new Error('unexpected read')
})
const chain = {addresses: {KeyRegistry: registry}, client: {getChainId: async () => 31337, getBlockNumber: async () => 123n, readContract: read}} as unknown as TasraChainClient
beforeEach(() => {Object.assign(state, {exists: false, used: false, owner, epoch: 9n, expiry: 8n}); read.mockClear()})
it('pins the absent slot, unused commitment and expiry reads to one block', async () => {
  await assertExpiredSlotCommitment(chain, failure)
  expect(read).toHaveBeenCalledTimes(4)
  for (const [request] of read.mock.calls) expect(request).toMatchObject({blockNumber: 123n})
})
it.each([{exists: true}, {used: true}, {epoch: 8n}, {owner: registry}])('refuses recovery when the original commitment is not safely replaceable (case %#)', async change => {
  Object.assign(state, change)
  await expect(assertExpiredSlotCommitment(chain, failure)).rejects.toThrow('expired unused')
})
it('refuses a different deployment or unavailable RPC', async () => {
  await expect(assertExpiredSlotCommitment({...chain, addresses: {KeyRegistry: owner}}, failure)).rejects.toThrow('different deployment')
  expect(read).not.toHaveBeenCalled()
  read.mockRejectedValueOnce(new Error('RPC unavailable'))
  await expect(assertExpiredSlotCommitment(chain, failure)).rejects.toThrow('RPC unavailable')
})
