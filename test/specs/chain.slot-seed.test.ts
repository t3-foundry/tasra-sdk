// ADR-0075: the per-commitment draw seed.
//
// What these pin is the CLIENT-SIDE half of the security argument. The chain enforces that the
// signature is a real k-of-n threshold signature; nothing here can or should re-check that. What
// this side owes is that a caller never spends gas on an answer that could not possibly work, and
// that a deployment without the fast path still creates slots.
import {afterEach, beforeEach, expect, it, vi} from 'vitest'
import {createWalletClient, defineChain, http, keccak256, toHex, type Hex} from 'viem'
import {privateKeyToAccount} from 'viem/accounts'
import {createTasraWriteClient} from '../../src/chain/write.js'
import {requestSlotSeed} from '../../src/chain/slotSeed.js'
import {resolveAccountantUrls, ACCOUNTANT_TAG} from '../../src/chain/discovery.js'
import type {TasraChainClient} from '../../src/chain/client.js'

const mocks = vi.hoisted(() => ({submit: vi.fn(), read: vi.fn(), receipt: vi.fn()}))
vi.mock('viem', async original => ({...await original<typeof import('viem')>(), createPublicClient: () => ({readContract: mocks.read, waitForTransactionReceipt: mocks.receipt})}))
vi.mock('../../src/chain/registeredRelay.js', async original => ({...await original<typeof import('../../src/chain/registeredRelay.js')>(), createRegisteredRelaySubmitter: () => ({submit: mocks.submit})}))

const address = `0x${'11'.repeat(20)}` as const
const hash = (v: string) => `0x${v.repeat(32)}` as Hex
const COMMITMENT = hash('07')
const DIGEST = hash('aa')
const SIG = `0x${'5c'.repeat(64)}` as Hex
const chain = defineChain({id: 31337, name: 'fixture', nativeCurrency: {name: 'ETH', symbol: 'ETH', decimals: 18}, rpcUrls: {default: {http: ['http://localhost:1']}}})

/** A chain client that only answers `commitSeedDigest` — all `requestSlotSeed` needs when the
 *  accountant URLs are supplied, so discovery never runs. */
function seedChain(digest: Hex = DIGEST): TasraChainClient {
  return {client: {readContract: async () => digest}} as unknown as TasraChainClient
}

/** Stand in for the accountant fleet: `replies` is consulted per base URL. */
function fleet(replies: Record<string, {status: number; body?: unknown} | 'throw'>) {
  return vi.fn(async (input: string | URL | Request) => {
    const url = String(input)
    const base = url.replace(/\/v1\/slot-seed$/, '')
    const r = replies[base]
    if (!r) throw new Error(`no stub for ${url}`)
    if (r === 'throw') throw new Error('connection refused')
    return {ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.body} as Response
  })
}

afterEach(() => {vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals()})

it('returns the seed an accountant served when it matches the registry digest', async () => {
  vi.stubGlobal('fetch', fleet({'http://a': {status: 200, body: {commitment: COMMITMENT, digest: DIGEST, signature: SIG}}}))
  await expect(requestSlotSeed(seedChain(), address, COMMITMENT, {urls: ['http://a']}))
    .resolves.toMatchObject({digest: DIGEST, signature: SIG})
})

// ⚠ A digest that is not this registry's means the accountant is bound to a DIFFERENT registry or
//   chain. Its signature can never satisfy the reveal, and accepting it would surface as a
//   `BadSeedSignature` revert — a message about validity, for what is actually a wiring fault.
it('refuses a seed whose digest is not the one the registry computes', async () => {
  vi.stubGlobal('fetch', fleet({'http://a': {status: 200, body: {commitment: COMMITMENT, digest: hash('bb'), signature: SIG}}}))
  await expect(requestSlotSeed(seedChain(DIGEST), address, COMMITMENT, {urls: ['http://a']})).resolves.toBeNull()
})

it.each([
  ['a short signature', `0x${'5c'.repeat(32)}`],
  ['an over-long signature', `0x${'5c'.repeat(96)}`],
  // The point at infinity: it satisfies the pairing trivially, so the contract rejects it. Doing
  // so here as well means a misbehaving accountant cannot make a caller pay to find out.
  ['the point at infinity', `0x${'00'.repeat(64)}`],
  ['a non-hex signature', `0x${'zz'.repeat(64)}`],
  ['a malformed digest', undefined],
])('refuses %s', async (_label, signature) => {
  const body = signature === undefined
    ? {commitment: COMMITMENT, digest: '0xnope', signature: SIG}
    : {commitment: COMMITMENT, digest: DIGEST, signature}
  vi.stubGlobal('fetch', fleet({'http://a': {status: 200, body}}))
  await expect(requestSlotSeed(seedChain(), address, COMMITMENT, {urls: ['http://a']})).resolves.toBeNull()
})

// Any one accountant can lead the round, so an unreachable or not-yet-ready one is not a failure
// of the set.
it('moves on to the next accountant past a refusal, an outage and a 503', async () => {
  const f = fleet({
    'http://a': {status: 404},                     // has not seen the commit yet
    'http://b': 'throw',                           // unreachable
    'http://c': {status: 503},                     // threshold set not up
    'http://d': {status: 200, body: {commitment: COMMITMENT, digest: DIGEST, signature: SIG}},
  })
  vi.stubGlobal('fetch', f)
  await expect(requestSlotSeed(seedChain(), address, COMMITMENT, {urls: ['http://a', 'http://b', 'http://c', 'http://d']}))
    .resolves.toMatchObject({signature: SIG})
  expect(f).toHaveBeenCalledTimes(4)
})

it('returns null when no accountant is registered, without reading the registry', async () => {
  const read = vi.fn()
  const c = {client: {readContract: read}} as unknown as TasraChainClient
  await expect(requestSlotSeed(c, address, COMMITMENT, {urls: []})).resolves.toBeNull()
  expect(read).not.toHaveBeenCalled()
})

// --- the write path ---------------------------------------------------------------------------

function writer(relay: boolean) {
  const wallet = createWalletClient({account: privateKeyToAccount(hash('01')), chain, transport: http()})
  vi.spyOn(wallet, 'sendTransaction').mockRejectedValue(new Error('Unexpected direct gas payment'))
  const direct = vi.spyOn(wallet, 'writeContract').mockResolvedValue(hash('10'))
  const w = createTasraWriteClient({
    rpcUrl: 'http://localhost:1', wallet,
    addresses: {KeyRegistry: address, ThresholdRandomBeacon: address, ServiceRegistry: address},
    ...(relay ? {relay: {forwarder: address, approvals: [{chainId: 31337, registry: address, serviceId: hash('02'), owner: address, serviceType: 0, revision: 1n, manifestHash: hash('03')}], transport: {request: vi.fn(), relayRequest: vi.fn()}}} : {}),
  })
  return {w, direct, args: {slotId: hash('04'), salt: hash('05'), ruleSalt: hash('06'), dcqlRule: 'verify:demo', k: 2, n: 3, mode: 'bls' as const}}
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.read.mockImplementation(async ({functionName}: {functionName: string}) => {
    if (functionName === 'computeCommitment') return COMMITMENT
    // ⚠ targetEpoch 9 against a beacon at 2: the epoch path CANNOT complete in these tests, so a
    //   passing seeded case is proof the seed was used and not merely that creation succeeded.
    if (functionName === 'slotCommits') return [9n, 20n, address, false]
    if (functionName === 'epoch') return 2n
    if (functionName === 'randomBeacon') return address
    if (functionName === 'commitSeedDigest') return DIGEST
    throw new Error(`Unexpected read ${functionName}`)
  })
  mocks.receipt.mockResolvedValue({status: 'success'})
  mocks.submit.mockImplementation(async (_to: unknown, _data: unknown, label: string) => ({id: hash('08'), txHash: label === 'commitKeySlot' ? hash('09') : hash('10')}))
})

it('reveals with the seed instead of waiting for the target epoch', async () => {
  vi.stubGlobal('fetch', fleet({'http://a': {status: 200, body: {commitment: COMMITMENT, digest: DIGEST, signature: SIG}}}))
  const h = writer(false)
  const seen: (string | null)[] = []
  const out = await h.w.createSlotCommitReveal({...h.args, accountantUrls: ['http://a'], onSeed: s => seen.push(s?.signature ?? null)})
  expect(out.seeded).toBe(true)
  expect(seen).toEqual([SIG])
  const reveal = h.direct.mock.calls.find(c => (c[0] as {functionName: string}).functionName.startsWith('revealKeySlot'))
  expect(reveal?.[0]).toMatchObject({functionName: 'revealKeySlotWithSeed'})
  expect((reveal?.[0] as {args: readonly unknown[]}).args.at(-1)).toBe(SIG)
})

it('pins the rule policy in the seeded reveal, in the same transaction', async () => {
  vi.stubGlobal('fetch', fleet({'http://a': {status: 200, body: {commitment: COMMITMENT, digest: DIGEST, signature: SIG}}}))
  const h = writer(false)
  await h.w.createSlotCommitReveal({...h.args, accountantUrls: ['http://a'], rulePolicy: {admin: address, guardian: `0x${'22'.repeat(20)}` as const, timelockSecs: 120}})
  const reveal = h.direct.mock.calls.find(c => (c[0] as {functionName: string}).functionName.startsWith('revealKeySlot'))
  expect(reveal?.[0]).toMatchObject({functionName: 'revealKeySlotWithSeedAndPolicy'})
})

// ⚠ THE FAST PATH MUST ONLY EVER COST TIME. With no accountant reachable the creation still has
//   to run ADR-0030's epoch wait — which here cannot finish, so a timeout naming the target epoch
//   is the proof that the fallback was entered rather than the whole call failing on the seed.
it('falls back to the epoch wait when no accountant serves a seed', async () => {
  vi.stubGlobal('fetch', fleet({'http://a': 'throw'}))
  const h = writer(false)
  await expect(h.w.createSlotCommitReveal({...h.args, accountantUrls: ['http://a'], maxWaitMs: 1}))
    .rejects.toThrow('beacon did not reach target epoch 9')
})

it('skips the seed request entirely when slotSeed is false', async () => {
  const f = fleet({})
  vi.stubGlobal('fetch', f)
  const h = writer(false)
  await expect(h.w.createSlotCommitReveal({...h.args, slotSeed: false, maxWaitMs: 1}))
    .rejects.toThrow('beacon did not reach target epoch 9')
  expect(f).not.toHaveBeenCalled()
})

// ⚠⚠ Under a relay a failed seeded reveal must NOT fall through. The relay submitter owns the
//    retries of the one request it signed; a second signed request against the same forwarder
//    nonce is the defect that wedges every later write by this signer.
it('rethrows a failed seeded reveal under a relay rather than falling back', async () => {
  vi.stubGlobal('fetch', fleet({'http://a': {status: 200, body: {commitment: COMMITMENT, digest: DIGEST, signature: SIG}}}))
  mocks.submit.mockImplementation(async (_to: unknown, _data: unknown, label: string) => {
    if (label === 'commitKeySlot') return {id: hash('08'), txHash: hash('09')}
    throw new Error('relay: reveal reverted')
  })
  const h = writer(true)
  await expect(h.w.createSlotCommitReveal({...h.args, accountantUrls: ['http://a'], maxWaitMs: 1}))
    .rejects.toThrow('relay: reveal reverted')
})

it('commits exactly once whichever path completes the reveal', async () => {
  vi.stubGlobal('fetch', fleet({'http://a': {status: 200, body: {commitment: COMMITMENT, digest: DIGEST, signature: SIG}}}))
  const h = writer(false)
  await h.w.createSlotCommitReveal({...h.args, accountantUrls: ['http://a']})
  const commits = h.direct.mock.calls.filter(c => (c[0] as {functionName: string}).functionName === 'commitKeySlot')
  expect(commits).toHaveLength(1)
})

// --- accountant discovery ----------------------------------------------------------------------

// ⚠ The paged getter returns TWO outputs, so viem hands back a TUPLE, not an object. Getting that
//   wrong resolves an empty set, which reads as "no accountants are deployed" — a silent fallback
//   to the epoch wait that nothing would report.
it('walks taggedActiveOperatorsPage and keeps only operators with a url', async () => {
  const pages: Array<[Array<{url: string}>, bigint]> = [
    [[{url: 'http://a'}, {url: ''}, {url: 'http://c'}], 5n],
    [[{url: 'http://d'}, {url: 'http://e'}], 5n],
  ]
  const read = vi.fn(async () => pages.shift() ?? [[], 5n])
  const chain = {read} as unknown as TasraChainClient
  await expect(resolveAccountantUrls(chain)).resolves.toEqual(['http://a', 'http://c', 'http://d', 'http://e'])
  // Two pages covered the total; a third call would mean the offset never caught up.
  expect(read).toHaveBeenCalledTimes(2)
  expect(read.mock.calls[0]).toEqual(['NodeRegistry', 'taggedActiveOperatorsPage', [ACCOUNTANT_TAG, 0n, 256n]])
  expect(read.mock.calls[1]).toEqual(['NodeRegistry', 'taggedActiveOperatorsPage', [ACCOUNTANT_TAG, 3n, 256n]])
})

// A registry with no accountants must terminate, not spin: an empty page ends the walk whatever
// `total` claims.
it('stops on an empty page even when total disagrees', async () => {
  const read = vi.fn(async () => [[], 99n])
  await expect(resolveAccountantUrls({read} as unknown as TasraChainClient)).resolves.toEqual([])
  expect(read).toHaveBeenCalledTimes(1)
})

it('the accountant tag is the registered one', () => {
  expect(ACCOUNTANT_TAG).toBe(keccak256(toHex('accountant')))
})
