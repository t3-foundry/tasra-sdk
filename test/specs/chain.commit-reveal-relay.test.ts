import {afterEach, beforeEach, expect, it, vi} from 'vitest'
import {createWalletClient, defineChain, http, decodeFunctionData, type Hex} from 'viem'
import {privateKeyToAccount} from 'viem/accounts'
import {createTasraWriteClient} from '../../src/chain/write.js'
import {keyRegistryAbi} from '../../src/chain/abis/keyRegistry.js'
const mocks = vi.hoisted(() => ({submit: vi.fn(), read: vi.fn(), receipt: vi.fn()}))
vi.mock('viem', async original => ({...await original<typeof import('viem')>(), createPublicClient: () => ({readContract: mocks.read, waitForTransactionReceipt: mocks.receipt})}))
vi.mock('../../src/chain/registeredRelay.js', async original => ({...await original<typeof import('../../src/chain/registeredRelay.js')>(), createRegisteredRelaySubmitter: () => ({submit: mocks.submit})}))
const address = `0x${'11'.repeat(20)}` as const, hash = (v: string) => `0x${v.repeat(32)}` as Hex
const chain = defineChain({id: 31337, name: 'fixture', nativeCurrency: {name: 'ETH', symbol: 'ETH', decimals: 18}, rpcUrls: {default: {http: ['http://localhost:1']}}})
function fixture(withBeacon = true) {
  const wallet = createWalletClient({account: privateKeyToAccount(hash('01')), chain, transport: http()})
  const direct = vi.spyOn(wallet, 'writeContract').mockRejectedValue(new Error('Unexpected direct transaction'))
  const nudge = vi.spyOn(wallet, 'sendTransaction').mockRejectedValue(new Error('Unexpected direct gas payment'))
  const writer = createTasraWriteClient({rpcUrl: 'http://localhost:1', wallet, addresses: {KeyRegistry: address, ...(withBeacon ? {ThresholdRandomBeacon: address} : {}), ServiceRegistry: address}, relay: {forwarder: address, approvals: [{chainId: 31337, registry: address, serviceId: hash('02'), owner: address, serviceType: 0, revision: 1n, manifestHash: hash('03')}], transport: {request: vi.fn(), relayRequest: vi.fn()}}})
  const args = {slotId: hash('04'), salt: hash('05'), ruleSalt: hash('06'), dcqlRule: 'verify:demo', k: 2, n: 3, mode: 'bls' as const}
  return {writer, args, direct, nudge}
}
beforeEach(() => {
  vi.clearAllMocks()
  mocks.read.mockImplementation(async ({functionName}: {functionName: string}) => {
    if (functionName === 'computeCommitment') return hash('07')
    if (functionName === 'slotCommits') return [2n, 5n, address, false]
    if (functionName === 'epoch') return 2n
    if (functionName === 'randomBeacon') return address
    throw new Error(`Unexpected read ${functionName}`)
  })
  mocks.receipt.mockResolvedValue({status: 'success'})
  mocks.submit.mockImplementation(async (_to, _data, label) => ({id: hash('08'), txHash: label === 'commitKeySlot' ? hash('09') : hash('10')}))
})
afterEach(() => {vi.useRealTimers(); vi.restoreAllMocks()})
it('resolves an omitted beacon from the pinned registry before submitting', async () => {
  const h = fixture(false)
  await h.writer.createSlotCommitReveal(h.args)
  expect(mocks.read.mock.calls[0]?.[0]).toMatchObject({address, functionName: 'randomBeacon'})
  expect(mocks.submit).toHaveBeenCalledTimes(2)
  mocks.submit.mockClear()
  mocks.read.mockRejectedValueOnce(new Error('registry unavailable'))
  await expect(h.writer.createSlotCommitReveal(h.args)).rejects.toThrow('registry unavailable')
  expect(mocks.submit).not.toHaveBeenCalled()
})
it.each([false, true])('routes commit and reveal through the registered submitter (with policy: %s)', async withPolicy => {
  const h = fixture()
  const result = await h.writer.createSlotCommitReveal({...h.args, ...(withPolicy ? {rulePolicy: {admin: address, guardian: `0x${'22'.repeat(20)}` as const, timelockSecs: 120}} : {})})
  expect(result).toMatchObject({slotId: h.args.slotId, ruleSalt: h.args.ruleSalt, commitTx: hash('09'), revealTx: hash('10'), targetEpoch: 2})
  const calls = mocks.submit.mock.calls.map(([, data]) => decodeFunctionData({abi: keyRegistryAbi, data}))
  expect(calls.map(c => c.functionName)).toEqual(['commitKeySlot', withPolicy ? 'revealKeySlotWithPolicy' : 'revealKeySlot'])
  expect(calls[1]!.args).toContain(h.args.slotId)
  expect(calls[1]!.args).toContain(h.args.salt)
  expect(h.direct).not.toHaveBeenCalled()
  expect(h.nudge).not.toHaveBeenCalled()
})
it('propagates an uncertain reveal without a second submit or direct fallback', async () => {
  const h = fixture()
  mocks.submit.mockRejectedValueOnce(new Error('commit unavailable'))
  await expect(h.writer.createSlotCommitReveal(h.args)).rejects.toThrow('commit unavailable')
  expect(mocks.submit).toHaveBeenCalledTimes(1)
  mocks.submit.mockClear()
  mocks.submit.mockResolvedValueOnce({id: hash('08'), txHash: hash('09')}).mockRejectedValueOnce(new Error('unknown relay outcome'))
  await expect(h.writer.createSlotCommitReveal(h.args)).rejects.toThrow('unknown relay outcome')
  expect(mocks.submit).toHaveBeenCalledTimes(2)
  expect(h.direct).not.toHaveBeenCalled()
})
it('does not make direct gas-paying nudges while waiting for the beacon', async () => {
  vi.useFakeTimers()
  const h = fixture()
  mocks.read.mockImplementation(async ({functionName}: {functionName: string}) => functionName === 'computeCommitment' ? hash('07') : functionName === 'slotCommits' ? [2n, 5n, address, false] : 1n)
  const assertion = expect(h.writer.createSlotCommitReveal({...h.args, maxWaitMs: 5000})).rejects.toThrow('beacon did not reach')
  await vi.advanceTimersByTimeAsync(6001)
  await assertion
  expect(mocks.submit).toHaveBeenCalledTimes(1)
  expect(h.direct).not.toHaveBeenCalled()
  expect(h.nudge).not.toHaveBeenCalled()
})

it('reports an unused expired commitment before attempting another reveal', async () => {
  const h = fixture()
  mocks.read.mockImplementation(async ({functionName}: {functionName: string}) => functionName === 'computeCommitment' ? hash('07') : functionName === 'slotCommits' ? [2n, 5n, address, false] : 6n)
  await expect(h.writer.createSlotCommitReveal(h.args)).rejects.toThrow('commitment expired')
  expect(mocks.submit).toHaveBeenCalledTimes(1)
  expect(h.direct).not.toHaveBeenCalled()
})
