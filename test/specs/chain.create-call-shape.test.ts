// Pins the ENCODED argument order of every KeyRegistry creation call the write
// client makes.
//
// ── why this file exists ─────────────────────────────────────────────────────
// `sendCall` in src/chain/write.ts is declared `args: readonly unknown[]`, and the
// call object is cast through `as unknown as Parameters<typeof encodeFunctionData>[0]`.
// That cast is load-bearing for the relay path, but it means THE COMPILER IS NOT A
// CHECK HERE: an argument dropped, duplicated, or put in the wrong position type-checks
// perfectly and fails only as an ABI encode error at runtime — or, worse, encodes
// cleanly into a DIFFERENT valid call, because `mode`, `auth`, `k` and `n` are all
// small unsigned integers and `slotId`, `ruleCommitment` and `salt` are all bytes32.
// Swapping `mode` and `auth` produces a slot with the wrong key type and no error
// anywhere; swapping `ruleCommitment` and `salt` produces a slot whose rule can never
// be provisioned, which surfaces much later as "dcql_rule does not match the slot's
// on-chain commitment" and reads like a typo in a rule that is fine.
//
// `auth` (`KeyRegistry.AuthType`, added 2026-09-19 alongside the dcqlHash →
// ruleCommitment rename) is the NEWEST member and sits in the middle of the tuple —
// immediately after `mode` and before `salt` — so it is the first thing a future edit
// will misplace, and the easiest to forget when a seventh entry point is added. It is
// also deliberately absent from `computeCommitment`, so the same index means `auth` in
// a creation call and `salt` in the commitment read. This file asserts both, together,
// because that asymmetry is the trap.
//
// ── what it guards, concretely ───────────────────────────────────────────────
// Three of the entry points below (`createKeySlotFiltered`, `…Exportable`,
// `…WithPolicy`) had NO committed coverage of their encoded shape before this file;
// only the two reveal paths were covered, incidentally, by chain.commit-reveal-relay.
// Decoding with `decodeFunctionData` against the vendored ABI is what makes this a real
// check: it re-derives the shape from the ABI rather than restating the literal.
//
// ⚠ `KeyRegistry.createKeySlot` (the unfiltered variant) is deliberately NOT covered:
// the SDK has no call site for it. If one is ever added, add a case here with it.

import {beforeEach, expect, it, vi} from 'vitest'
import {createWalletClient, defineChain, decodeFunctionData, http, keccak256, toHex, type Hex} from 'viem'
import {privateKeyToAccount} from 'viem/accounts'
import {createTasraWriteClient, ruleCommitment, type CreateSlotArgs} from '../../src/chain/write.js'
import {keyRegistryAbi} from '../../src/chain/abis/keyRegistry.js'

const mocks = vi.hoisted(() => ({submit: vi.fn(), read: vi.fn(), receipt: vi.fn()}))
vi.mock('viem', async original => ({...await original<typeof import('viem')>(), createPublicClient: () => ({readContract: mocks.read, waitForTransactionReceipt: mocks.receipt})}))
vi.mock('../../src/chain/registeredRelay.js', async original => ({...await original<typeof import('../../src/chain/registeredRelay.js')>(), createRegisteredRelaySubmitter: () => ({submit: mocks.submit})}))

const address = `0x${'11'.repeat(20)}` as const
const hash = (v: string) => `0x${v.repeat(32)}` as Hex
const chain = defineChain({id: 31337, name: 'fixture', nativeCurrency: {name: 'ETH', symbol: 'ETH', decimals: 18}, rpcUrls: {default: {http: ['http://localhost:1']}}})

/** The one policy shape used throughout: a real guardian, so MIN_RULE_TIMELOCK is not consulted. */
const POLICY = {admin: address, guardian: `0x${'22'.repeat(20)}` as const, timelockSecs: 120}

/**
 * The write client with BOTH direct paths poisoned, so every call must go through the
 * relay submitter — which is what gives us the encoded calldata to decode.
 */
function fixture() {
  const wallet = createWalletClient({account: privateKeyToAccount(hash('01')), chain, transport: http()})
  vi.spyOn(wallet, 'writeContract').mockRejectedValue(new Error('Unexpected direct transaction'))
  vi.spyOn(wallet, 'sendTransaction').mockRejectedValue(new Error('Unexpected direct gas payment'))
  const writer = createTasraWriteClient({
    rpcUrl: 'http://localhost:1',
    wallet,
    addresses: {KeyRegistry: address, ThresholdRandomBeacon: address, ServiceRegistry: address},
    relay: {
      forwarder: address,
      approvals: [{chainId: 31337, registry: address, serviceId: hash('02'), owner: address, serviceType: 0, revision: 1n, manifestHash: hash('03')}],
      transport: {request: vi.fn(), relayRequest: vi.fn()},
    },
  })
  // ⚠ These numbers are chosen so NO TWO of them collide, which is what makes a
  // transposition detectable. `mode: 'tecdsa-p256'` is ordinal 4, k is 5, n is 7, and
  // the AuthType ordinals are 0/1/2 — every position holds a distinct value.
  //
  // This is not fussiness. The obvious fixture (`mode: 'bls'`, k 2, n 3) is SILENTLY
  // BLIND to the exact bug this file exists to catch: 'bls' is ordinal 1 and 'oid4vp'
  // is ordinal 1, so swapping `mode` and `auth` leaves both assertions passing; k 2
  // collides with 'oauth' 2 the same way. Verified by mutation: with the colliding
  // fixture a mode/auth swap failed only 3 of 6 affected cases, with these values it
  // fails all of them.
  const args = {slotId: hash('04'), salt: hash('05'), ruleSalt: hash('06'), dcqlRule: 'verify:demo', k: 5, n: 7, mode: 'tecdsa-p256' as const}
  return {writer, args}
}

beforeEach(() => {
  vi.restoreAllMocks()
  vi.clearAllMocks()
  mocks.read.mockImplementation(async ({functionName}: {functionName: string}) => {
    if (functionName === 'computeCommitment') return hash('07')
    if (functionName === 'slotCommits') return [2n, 5n, address, false]
    if (functionName === 'epoch') return 2n
    if (functionName === 'randomBeacon') return address
    if (functionName === 'MIN_RULE_TIMELOCK') return 120
    throw new Error(`Unexpected read ${functionName}`)
  })
  mocks.receipt.mockResolvedValue({status: 'success'})
  mocks.submit.mockImplementation(async () => ({id: hash('08'), txHash: hash('09')}))
})

/** Every relayed call, decoded back through the vendored ABI. */
const relayed = () => mocks.submit.mock.calls.map(([, data]) => decodeFunctionData({abi: keyRegistryAbi, data}))

/**
 * The shared prefix of all five creation entry points:
 *   0 slotId · 1 ruleCommitment · 2 k · 3 n · 4 mode · 5 auth · 6 salt · 7 requiredTags
 * `mode` is the `KeyRegistry.Mode` ordinal ('tecdsa-p256' = 4); `auth` the `AuthType` ordinal.
 */
function expectCreationPrefix(callArgs: readonly unknown[], expected: {salt: Hex; slotId: Hex; ruleSalt: Hex; dcqlRule: string; k: number; n: number; auth: number}) {
  expect(callArgs[0]).toBe(expected.slotId)
  // The SALTED commitment goes on chain, never the raw rule hash.
  expect(callArgs[1]).toBe(ruleCommitment(expected.ruleSalt, expected.dcqlRule))
  expect(callArgs[1]).not.toBe(keccak256(toHex(expected.dcqlRule)))
  expect(callArgs[2]).toBe(expected.k)
  expect(callArgs[3]).toBe(expected.n)
  expect(callArgs[4]).toBe(4) // mode: 'tecdsa-p256'
  expect(callArgs[5]).toBe(expected.auth)
  expect(callArgs[6]).toBe(expected.salt)
  expect(callArgs[7]).toEqual([keccak256(toHex('keykeeper'))])
}

it.each<[string, Partial<CreateSlotArgs>, string, number]>([
  ['an omitted authType defaults to Unspecified', {}, 'createKeySlotFiltered', 0],
  ['an explicit unspecified', {authType: 'unspecified'}, 'createKeySlotFiltered', 0],
  ['oid4vp', {authType: 'oid4vp'}, 'createKeySlotFiltered', 1],
  ['oauth', {authType: 'oauth'}, 'createKeySlotFiltered', 2],
  ['an exportable slot', {exportable: true, authType: 'oid4vp'}, 'createKeySlotFilteredExportable', 1],
  ['a slot with a rule policy', {rulePolicy: POLICY, authType: 'oauth'}, 'createKeySlotFilteredWithPolicy', 2],
])('createSlot encodes %s at the pinned argument positions', async (_label, extra, functionName, auth) => {
  const h = fixture()
  await h.writer.createSlot({...h.args, ...extra})
  const calls = relayed()
  expect(calls).toHaveLength(1)
  expect(calls[0]!.functionName).toBe(functionName)
  expectCreationPrefix(calls[0]!.args!, {...h.args, auth})
})

it('createKeySlotFilteredWithPolicy carries the policy tuple after the tags', async () => {
  const h = fixture()
  await h.writer.createSlot({...h.args, rulePolicy: POLICY})
  const [call] = relayed()
  expect(call!.args).toHaveLength(9)
  expect(call!.args![8]).toEqual({admin: POLICY.admin, guardian: POLICY.guardian, timelock: POLICY.timelockSecs})
})

it.each<[string, Partial<CreateSlotArgs>, string, number]>([
  ['revealKeySlot', {}, 'revealKeySlot', 8],
  ['revealKeySlotWithPolicy', {rulePolicy: POLICY}, 'revealKeySlotWithPolicy', 9],
])('createSlotCommitReveal encodes %s at the pinned argument positions', async (_label, extra, functionName, arity) => {
  const h = fixture()
  await h.writer.createSlotCommitReveal({...h.args, ...extra, authType: 'oid4vp'})
  const calls = relayed()
  expect(calls.map(c => c.functionName)).toEqual(['commitKeySlot', functionName])
  expect(calls[1]!.args).toHaveLength(arity)
  expectCreationPrefix(calls[1]!.args!, {...h.args, auth: 1})
})

it('computeCommitment takes 8 args and does NOT carry auth — index 5 is the salt there', async () => {
  const h = fixture()
  await h.writer.createSlotCommitReveal({...h.args, authType: 'oauth'})
  const read = mocks.read.mock.calls.map(([c]) => c).find(c => c.functionName === 'computeCommitment')
  expect(read).toBeDefined()
  // slotId · ruleCommitment · k · n · mode · salt · requiredTags · creator
  expect(read.args).toHaveLength(8)
  expect(read.args[4]).toBe(4) // mode: 'tecdsa-p256'
  // ⚠ THE ASYMMETRY: index 5 is `auth` in a creation call but `salt` here. Adding auth
  // to the commitment would silently invalidate every outstanding commit.
  expect(read.args[5]).toBe(h.args.salt)
  expect(read.args[5]).not.toBe(2) // not the AuthType ordinal we just passed
  expect(read.args[7]).toBe(privateKeyToAccount(hash('01')).address)
})

it('refuses an unknown authType before anything is signed', async () => {
  const h = fixture()
  await expect(h.writer.createSlot({...h.args, authType: 'saml' as never})).rejects.toThrow('unknown authType')
  expect(mocks.submit).not.toHaveBeenCalled()
})
