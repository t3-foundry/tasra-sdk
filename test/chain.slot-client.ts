// Slot-driven endpoint resolution — the chain client's discovery half, offline.
//
// `createTasraSlotClient` had no coverage at all. It is the piece that turns a bare slot
// id into `{nodes, verifier}` by reading the registry, so everything it gets wrong is an
// endpoint a caller then talks to (or fails to). Three things here are load-bearing:
//
//   • the verifier DIRECTORY is network-wide and cached ONCE per client, while keeper
//     discovery is per-slot. A cache that re-reads is a cost bug; one that caches the
//     per-slot half would be a correctness bug.
//   • `resolveVerifierDirectory` assigns `index` by ASCENDING OPERATOR ADDRESS, because
//     that is the order the network builds every tagged set in. If this order drifts, the
//     committee flow's inclusion proofs are built against the wrong leaves and the keeper
//     rejects a token that is otherwise valid — so the ordering is pinned against a
//     registry deliberately returned OUT of order.
//   • both "nothing discovered" errors have to say which side is empty, since a slot with
//     no keeper URL and a network with no verifier need completely different fixes.
//
// The chain client is a plain object here rather than a stubbed RPC: these functions are
// defined against the reader interface, and faking the readers keeps the suite about
// discovery instead of about viem.
//
// Run: tsx test/chain.slot-client.ts — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {createTasraSlotClient} from '../src/chain/slotClient.ts'
import {
  VERIFIER_TAG,
  resolveSlotGroupKey,
  resolveSlotKeeperUrls,
  resolveVerifierDirectory,
} from '../src/chain/discovery.ts'
import type {TasraChainClient} from '../src/chain/client.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean, detail = ''): void {
  if (cond) passed++
  else failures.push(name + (detail ? ` — ${detail}` : ''))
}
function eq(name: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual)
  const b = JSON.stringify(expected)
  ok(name, a === b, `got ${a}, want ${b}`)
}
async function rejectsWith(name: string, re: RegExp, run: () => Promise<unknown>): Promise<void> {
  try {
    await run()
    ok(name, false, 'did not throw')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    ok(name, re.test(message), `message was ${JSON.stringify(message)}`)
  }
}

const slotId = `0x${'ab'.repeat(32)}` as `0x${string}`
const addr = (n: number): `0x${string}` => `0x${n.toString(16).padStart(40, '0')}`

/** One registry entry, as `nodeOf` returns it. */
interface Node {
  operator: `0x${string}`
  dns: string
  url: string
  p2pAddr: string
  pubkey: `0x${string}`
  active: boolean
}
const node = (n: number, url: string): Node => ({
  operator: addr(n),
  dns: '',
  url,
  p2pAddr: '',
  pubkey: `0x${n.toString(16).padStart(64, '0')}`,
  active: true,
})

interface FakeChain {
  assigned: `0x${string}`[]
  activeOps: `0x${string}`[]
  tagged: Set<string>
  nodes: Map<string, Node>
  slot?: {publicKey: `0x${string}`; epoch: bigint | number; mode: number}
  /** Every read the fake served, so caching can be asserted rather than assumed. */
  reads: string[]
}

function fakeChain(f: Omit<FakeChain, 'reads'>): {chain: TasraChainClient; reads: string[]} {
  const reads: string[] = []
  /**
   * Discovery reads the per-operator values through `readMany` so they batch on a chain
   * with Multicall3. The fake implements it over the same data, honouring
   * `allowFailure: false` — which is the flag that keeps an ordered directory's indexes
   * meaningful, so a fake that ignored it would hide exactly the bug that matters.
   */
  const readMany = (
    contract: string,
    functionName: string,
    argsList: readonly unknown[][],
    opts?: {allowFailure?: boolean},
  ): Promise<unknown[]> => {
    const results = argsList.map(args => {
      const op = String(args[0]).toLowerCase()
      if (contract === 'NodeRegistry' && functionName === 'nodeOf') {
        reads.push(`nodeOf(${op.slice(-2)})`)
        return f.nodes.get(op) ?? null
      }
      if (contract === 'NodeRegistry' && functionName === 'hasTag') {
        reads.push(`hasTag(${op.slice(-2)})`)
        return args[1] === VERIFIER_TAG && f.tagged.has(op)
      }
      throw new Error(`fake readMany: unexpected ${contract}.${functionName}`)
    })
    if (opts?.allowFailure === false && results.some(r => r === null)) {
      return Promise.reject(new Error(`fake readMany: ${contract}.${functionName} had an unreadable item`))
    }
    return Promise.resolve(results)
  }
  const chain = {
    readMany,
    multicallAddress: () => Promise.resolve(null),
    readers: {
      keyRegistry: {
        assignedNodes: (id: `0x${string}`) => {
          reads.push(`assignedNodes(${id.slice(0, 6)})`)
          return Promise.resolve(f.assigned)
        },
        getKeySlot: (id: `0x${string}`) => {
          reads.push(`getKeySlot(${id.slice(0, 6)})`)
          return Promise.resolve(f.slot)
        },
      },
      nodeRegistry: {
        activeOperators: () => {
          reads.push('activeOperators')
          return Promise.resolve(f.activeOps)
        },
        hasTag: (op: `0x${string}`, tag: `0x${string}`) => {
          reads.push(`hasTag(${op.slice(-2)})`)
          return Promise.resolve(tag === VERIFIER_TAG && f.tagged.has(op.toLowerCase()))
        },
        nodeOf: (op: `0x${string}`) => {
          reads.push(`nodeOf(${op.slice(-2)})`)
          return Promise.resolve(f.nodes.get(op.toLowerCase()))
        },
      },
    },
  } as unknown as TasraChainClient
  return {chain, reads}
}

// ─── the default deployment: 3 keepers, 3 verifiers registered out of order ────
const keepers = [node(0x11, 'http://keeper-a:8080'), node(0x12, 'http://keeper-b:8080'), node(0x13, 'http://keeper-c:8080')]
// Deliberately NOT ascending, and with a non-verifier in the middle, so the sort and the
// tag filter are both doing work.
const verifiers = [node(0xcc, 'http://verifier-cc'), node(0xaa, 'http://verifier-aa'), node(0xbb, 'http://verifier-bb')]
const plain = node(0x99, 'http://plain-keeper')

const allNodes = new Map([...keepers, ...verifiers, plain].map(n => [n.operator.toLowerCase(), n]))
const base = {
  assigned: keepers.map(k => k.operator),
  activeOps: [...verifiers.map(v => v.operator), plain.operator],
  tagged: new Set(verifiers.map(v => v.operator.toLowerCase())),
  nodes: allNodes,
  slot: {publicKey: `0x${'cd'.repeat(96)}` as `0x${string}`, epoch: 4n, mode: 1},
}

// ─── discovery primitives ─────────────────────────────────────────────────────
{
  const {chain} = fakeChain(base)
  eq(
    'resolveSlotKeeperUrls returns the slot committee in assignedNodes order',
    await resolveSlotKeeperUrls(chain, slotId),
    ['http://keeper-a:8080', 'http://keeper-b:8080', 'http://keeper-c:8080'],
  )

  const dir = await resolveVerifierDirectory(chain)
  // The ordering invariant: ascending operator address, regardless of registry order.
  eq('verifier directory is sorted by ascending operator address', dir.map(v => v.operator), [addr(0xaa), addr(0xbb), addr(0xcc)])
  eq('index is the position in that order, from 0', dir.map(v => v.index), [0, 1, 2])
  eq('each index carries ITS OWN url', dir.map(v => v.url), ['http://verifier-aa', 'http://verifier-bb', 'http://verifier-cc'])
  ok('each index carries its own pubkey', dir[0]?.pubkey === verifiers[1]?.pubkey && dir[2]?.pubkey === verifiers[0]?.pubkey)
  ok('an untagged active operator is excluded', !dir.some(v => v.operator === plain.operator))

  const slot = await resolveSlotGroupKey(chain, slotId)
  eq('slot group key reads publicKey/epoch/mode', [slot.publicKey.length, slot.epoch, slot.mode], [2 + 192, 4, 1])
  ok('epoch is narrowed from bigint to number', typeof slot.epoch === 'number')
}
{
  // A url-less operator is skipped rather than yielding an empty string a caller would
  // then try to fetch.
  const {chain} = fakeChain({
    ...base,
    assigned: [addr(0x11), addr(0x77), addr(0x13)],
    nodes: new Map([...allNodes, [addr(0x77).toLowerCase(), node(0x77, '')]]),
  })
  eq('a keeper with no registered url is skipped', await resolveSlotKeeperUrls(chain, slotId), [
    'http://keeper-a:8080',
    'http://keeper-c:8080',
  ])
}
{
  const {chain} = fakeChain({...base, tagged: new Set()})
  eq('no tagged operator yields an empty directory', (await resolveVerifierDirectory(chain)).length, 0)
}
{
  // ⚠ An UNREADABLE operator must fail the call, not shrink the set. Discovery reads the
  // per-operator values through readMany with `allowFailure: false` for exactly this:
  // `index` is a position, the anchored snapshot's leaves are built in the same order, so
  // one silently dropped operator renumbers every operator after it and the committee
  // flow's inclusion proofs are then built against the wrong leaves. A short directory
  // must be an error, never a plausible-looking different one.
  const missing = addr(0x5a)
  const {chain} = fakeChain({
    ...base,
    activeOps: [...verifiers.map(v => v.operator), missing],
    tagged: new Set([...verifiers.map(v => v.operator.toLowerCase()), missing.toLowerCase()]),
    // `missing` is tagged and active but has no registry entry, so its nodeOf is unreadable.
  })
  await rejectsWith(
    'an unreadable verifier fails the directory rather than renumbering it',
    /unreadable item/,
    () => resolveVerifierDirectory(chain),
  )
}
{
  // Same rule for the slot's keeper committee: a silently shorter node list reads as a
  // smaller slot.
  const {chain} = fakeChain({...base, assigned: [...base.assigned, addr(0x5b)]})
  await rejectsWith(
    'an unreadable keeper fails slot discovery rather than shrinking the committee',
    /unreadable item/,
    () => resolveSlotKeeperUrls(chain, slotId),
  )
}

// ─── the slot client ──────────────────────────────────────────────────────────
{
  const {chain, reads} = fakeChain(base)
  const kk = createTasraSlotClient({chain, identity: 'did:example:alice'})

  const r = await kk.resolveEndpoints(slotId)
  eq('resolveEndpoints returns the slot id it was given', r.slotId, slotId)
  eq('resolveEndpoints returns every keeper url', r.nodes, keepers.map(k => k.url))
  eq('verifierCount is the size of the discovered set', r.verifierCount, 3)
  ok('the chosen verifier comes from the discovered set', verifiers.some(v => v.url === r.verifier))

  // The caching invariant: the verifier set is network-wide, so a second slot must NOT
  // re-read it — but it MUST re-read that slot's own keeper committee.
  const before = reads.filter(x => x === 'activeOperators').length
  const assignedBefore = reads.filter(x => x.startsWith('assignedNodes')).length
  await kk.resolveEndpoints(slotId)
  eq('the verifier directory is read once per client', reads.filter(x => x === 'activeOperators').length, before)
  eq(
    'keeper discovery is NOT cached: it runs per slot',
    reads.filter(x => x.startsWith('assignedNodes')).length,
    assignedBefore + 1,
  )
  ok('verifierDirectory() hands back the cached set', (await kk.verifierDirectory()).length === 3)
  eq('still only one directory read after verifierDirectory()', reads.filter(x => x === 'activeOperators').length, before)
}
{
  // rewriteUrl exists because on-chain URLs are in-cluster names. It must apply to BOTH
  // sides — a rewrite that missed the verifier would leave an unreachable session.
  const {chain} = fakeChain(base)
  const seen: string[] = []
  const kk = createTasraSlotClient({
    chain,
    rewriteUrl: u => {
      seen.push(u)
      return u.replace('http://', 'https://public.example/')
    },
    onResolve: res => seen.push(`resolved:${res.verifierCount}`),
  })
  const r = await kk.resolveEndpoints(slotId)
  ok('rewriteUrl is applied to every keeper url', r.nodes.every(u => u.startsWith('https://public.example/')))
  ok('rewriteUrl is applied to the verifier url', r.verifier.startsWith('https://public.example/'))
  ok('rewriteUrl saw the raw on-chain urls', seen.includes('http://keeper-a:8080'))
  // onResolve fires from openSession, not resolveEndpoints — assert where it actually runs.
  ok('resolveEndpoints alone does not fire onResolve', !seen.some(s => s.startsWith('resolved:')))
}
{
  // A rewrite that maps a url to '' drops it, which is the documented filter. All-empty
  // must therefore read as "no keeper with a url", not as a silent success.
  const {chain} = fakeChain(base)
  const kk = createTasraSlotClient({chain, rewriteUrl: () => ''})
  await rejectsWith(
    'a rewrite that blanks every keeper url fails, naming the slot',
    /slot 0xabababab… has no on-chain assigned keeper node with a URL/,
    () => kk.resolveEndpoints(slotId),
  )
}
{
  // The two empty-set errors must be distinguishable: one is a slot problem, the other a
  // network problem, and they have different fixes.
  const {chain} = fakeChain({...base, assigned: []})
  await rejectsWith(
    'no assigned keeper names the slot',
    /slot 0xabababab… has no on-chain assigned keeper node with a URL/,
    () => createTasraSlotClient({chain}).resolveEndpoints(slotId),
  )
}
{
  const {chain} = fakeChain({...base, tagged: new Set()})
  await rejectsWith(
    'no verifier names the tag it looked for',
    /no verifiers discovered on chain.*keccak256\("verifier"\)-tagged/s,
    () => createTasraSlotClient({chain}).resolveEndpoints(slotId),
  )
}
{
  // The verifier is chosen at random from the set. Over many resolutions every member
  // should appear — a selector stuck on index 0 would send all load to one verifier and
  // still pass every single-shot assertion.
  const {chain} = fakeChain(base)
  const kk = createTasraSlotClient({chain})
  const chosen = new Set<string>()
  for (let i = 0; i < 60; i++) chosen.add((await kk.resolveEndpoints(slotId)).verifier)
  eq('the random choice covers the whole verifier set', chosen.size, 3)
}
{
  // A single-verifier network must still resolve (the modulo/rounding edge).
  const only = verifiers[0]!
  const {chain} = fakeChain({...base, activeOps: [only.operator], tagged: new Set([only.operator.toLowerCase()])})
  const r = await createTasraSlotClient({chain}).resolveEndpoints(slotId)
  eq('a one-verifier network resolves to that verifier', [r.verifier, r.verifierCount], [only.url, 1])
}
// ─── openSession: session bookkeeping over the resolved endpoints ─────────────
// A `{jwt}` session needs no verifier round trip, but it does read the slot's group key
// from a keeper, so the keeper is stubbed. That keeps this about the slot client's
// tracking rather than about session internals (those are test/client.*.ts).
{
  const G2 = bls12_381.G2.ProjectivePoint
  const ORDER = bls12_381.fields.Fr.ORDER
  const msk = ((0x2b7e1516n % ORDER) + ORDER) % ORDER
  const mpkHex = Array.from(G2.BASE.multiply(msk).toRawBytes(true))
    .map(x => x.toString(16).padStart(2, '0'))
    .join('')

  const realFetch = globalThis.fetch
  let keeperUp = true
  globalThis.fetch = (async (url: string) => {
    if (!keeperUp) return {ok: false, status: 503, text: async () => 'keeper down'} as unknown as Response
    if (String(url).includes('/public')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({group_public_key: `0x${mpkHex}`, epoch: 4}),
      } as unknown as Response
    }
    return {ok: false, status: 404, text: async () => 'no route'} as unknown as Response
  }) as typeof globalThis.fetch

  try {
    const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url')
    const now = Math.floor(Date.now() / 1000)
    const jwt = `${b64({alg: 'EdDSA', typ: 'JWT'})}.${b64({sub: 'did:example:alice', exp: now + 3600})}.sig`

    {
      const {chain} = fakeChain(base)
      const resolved: number[] = []
      const kk = createTasraSlotClient({chain, onResolve: r => resolved.push(r.verifierCount)})
      eq('a new client tracks no sessions', kk.sessions().length, 0)
      const s1 = await kk.openSession(slotId, {jwt})
      const s2 = await kk.openSession(slotId, {jwt})
      eq('openSession tracks each session', kk.sessions().length, 2)
      eq('onResolve fires once per openSession', resolved, [3, 3])
      ok('the session carries the holder from the token', s1.holder === 'did:example:alice')
      await kk.closeAll()
      eq('closeAll drops every session', kk.sessions().length, 0)
      let refused = 0
      for (const s of [s1, s2]) {
        try {
          await s.decrypt(new Uint8Array([2, 0, 0]))
        } catch {
          refused++
        }
      }
      eq('closeAll closed both sessions', refused, 2)
    }
    {
      // A failed open must not be tracked as an open session — otherwise closeAll later
      // rejects on a session that never existed.
      keeperUp = false
      const {chain} = fakeChain(base)
      const kk = createTasraSlotClient({chain})
      let threw = false
      try {
        await kk.openSession(slotId, {jwt})
      } catch {
        threw = true
      }
      ok('openSession propagates a keeper failure', threw)
      eq('a failed openSession is not tracked', kk.sessions().length, 0)
      await kk.closeAll()
      eq('closeAll on an empty client is a no-op', kk.sessions().length, 0)
      keeperUp = true
    }
  } finally {
    globalThis.fetch = realFetch
  }
}

if (failures.length > 0) {
  console.error(`✗ chain.slot-client: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ chain.slot-client: ${passed} checks passed`)
