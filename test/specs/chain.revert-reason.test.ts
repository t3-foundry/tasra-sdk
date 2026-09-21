// A custom error must survive the relay path.
//
// viem decodes a revert only when it knows the ABI. The relay path estimates the inner call with no
// ABI, so the selector arrives buried in the error chain and viem's message is "Execution reverted
// for an unknown reason." A sandbox agent hit exactly that: `createSlot` on a genesis requiring
// commit-reveal gave no clue what was wrong or what to do instead.
import {expect, it, vi} from 'vitest'
import {createWalletClient, defineChain, encodeErrorResult, http, type Abi, type Hex} from 'viem'
import {privateKeyToAccount} from 'viem/accounts'
import {describeRevert, revertError} from '../../src/chain/revertReason.js'
import {CONTRACT_ABIS} from '../../src/chain/abis/index.js'
import {createTasraWriteClient} from '../../src/chain/write.js'

const COMMIT_REVEAL_REQUIRED = '0x10e88a27' // CommitRevealRequired(), as an Avalanche C-chain node returns it
const address = `0x${'11'.repeat(20)}` as const
const hash = (v: string) => `0x${v.repeat(32)}` as Hex

/** The shape viem builds: the selector sits two `cause` levels below the thrown error. */
function estimationError(data: string): Error {
  const rpc = Object.assign(new Error('Execution reverted for an unknown reason.'), {data})
  const inner = Object.assign(new Error('Execution reverted for an unknown reason.'), {cause: rpc})
  return Object.assign(new Error('Execution reverted for an unknown reason.'), {cause: inner})
}

it('names a custom error carried anywhere in the cause chain', () => {
  expect(describeRevert(estimationError(COMMIT_REVEAL_REQUIRED))).toBe('CommitRevealRequired()')
})

it('renders the arguments of an error that carries them', () => {
  const errors = Object.values(CONTRACT_ABIS).flat() as Abi
  const withInputs = errors.find(
    i => i.type === 'error' && i.inputs.length === 1 && i.inputs[0]?.type === 'uint256',
  )
  expect(withInputs, 'an error with one uint256 argument').toBeDefined()
  const name = (withInputs as {name: string}).name
  const data = encodeErrorResult({abi: [withInputs] as Abi, errorName: name, args: [7n]})
  expect(describeRevert(estimationError(data))).toBe(`${name}(7)`)
})

it('returns undefined rather than throwing for data it cannot decode', () => {
  expect(describeRevert(estimationError('0xdeadbeef'))).toBeUndefined()
  expect(describeRevert(new Error('no data here'))).toBeUndefined()
  expect(describeRevert(undefined)).toBeUndefined()
})

it('falls back to the original message and keeps the cause', () => {
  const raw = new Error('Relay deadline exceeded')
  const wrapped = revertError(raw, 'relay: the inner call reverts at estimation')
  expect(wrapped.message).toBe('relay: the inner call reverts at estimation: Relay deadline exceeded')
  expect(wrapped.cause).toBe(raw)
})

it('createSlot says which call to use when the deployment requires commit-reveal', async () => {
  const chain = defineChain({
    id: 31337, name: 'fixture', nativeCurrency: {name: 'ETH', symbol: 'ETH', decimals: 18},
    rpcUrls: {default: {http: ['http://localhost:1']}},
  })
  const wallet = createWalletClient({account: privateKeyToAccount(hash('01')), chain, transport: http()})
  vi.spyOn(wallet, 'writeContract').mockRejectedValue(estimationError(COMMIT_REVEAL_REQUIRED))
  const writer = createTasraWriteClient({
    rpcUrl: 'http://localhost:1', wallet, chainId: 31337, addresses: {KeyRegistry: address},
  })
  await expect(writer.createSlot({dcqlRule: 'verify:demo', k: 2, n: 3, mode: 'bls'}))
    .rejects.toThrow('createSlotCommitReveal')
})
