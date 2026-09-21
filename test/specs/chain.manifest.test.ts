import {afterEach, beforeEach, describe, expect, it} from 'vitest'
import {createHash} from 'node:crypto'
import {getCreate2Address, keccak256, toHex, type Hex} from 'viem'
import {NETWORKS} from '../../src/chain/networks.js'
import {
  IMPLEMENTATION_SLOT,
  addressBookFromManifest,
  observeNetworkManifest,
  parseNetworkManifest,
  parsePinnedNetworkManifest,
  type NetworkManifest,
} from '../../src/chain/manifest.js'

const hash = `0x${'ab'.repeat(32)}` as const
const addr = `0x${'12'.repeat(20)}` as const
function manifest(): NetworkManifest {
  return {schemaVersion: 1, network: 'testnet', chainId: 43113, deploymentId: 'fuji-1', revision: 1,
    protocolVersion: '0.1.0', status: 'active', verifiedAt: {blockNumber: '100', blockHash: hash, timestamp: '2026-09-14T00:00:00Z'},
    contracts: ['NodeRegistry', 'KeyRegistry'].map(name => ({name, address: addr, abi: `contracts/abi/0.1.0/${name}.json`,
      runtimeCodeHash: hash, deployment: {transactionHash: hash, blockNumber: '99'}, create2: null, proxy: null})), services: []}
}
describe('public network manifests', () => {
  it('accepts pinned active data and refuses any changed byte', () => {
    const text = JSON.stringify(manifest())
    const digest = createHash('sha256').update(text).digest('hex')
    expect(addressBookFromManifest(parsePinnedNetworkManifest(text, digest)).NodeRegistry).toBe(addr)
    expect(() => parsePinnedNetworkManifest(`${text}\n`, digest)).toThrow('SHA-256')
  })
  it('refuses planned and retired networks for live clients', () => {
    for (const status of ['planned', 'retired'] as const) expect(() => addressBookFromManifest({...manifest(), status})).toThrow(status)
  })
  it('rejects wrong-chain data, missing evidence, duplicates and unsafe links', () => {
    const m = manifest()
    for (const bad of [{...m, chainId: 43114}, {...m, verifiedAt: null}, {...m, contracts: [m.contracts[0], m.contracts[0]]},
      {...m, services: [{kind: 'agent', url: 'https://secret:password@example.com'}]},
      {...m, contracts: m.contracts.map(c => ({...c, abi: 'contracts/abi/../../secret.json'}))}]) {
      expect(() => parseNetworkManifest(bad)).toThrow()
    }
  })
  it('accepts a named upgrade authority and refuses a malformed one', () => {
    // An upgrade authority is optional, but when present it names who can replace the
    // implementation — so a garbage value must not be waved through as "some address".
    const m = manifest()
    const proxy = {implementation: `0x${'cc'.repeat(20)}`, runtimeCodeHash: hash, upgradeAuthority: `0x${'dd'.repeat(20)}`} as const
    m.contracts[0] = {...m.contracts[0]!, proxy}
    expect(parseNetworkManifest(m)).toBe(m)
    for (const bad of ['0xnothex', `0x${'00'.repeat(20)}`, '']) {
      expect(() => parseNetworkManifest({...m, contracts: [{...m.contracts[0]!, proxy: {...proxy, upgradeAuthority: bad}}, m.contracts[1]!]}))
        .toThrow('proxy')
    }
  })
  it('allows http service URLs only on the local network', () => {
    // ⚠ A plaintext service URL on a public network is a downgrade a manifest must not be
    // able to request. `local` is the single exception, for a fleet on a developer machine.
    const plain = [{kind: 'agent', url: 'http://agent.example/v1'}]
    expect(() => parseNetworkManifest({...manifest(), services: plain})).toThrow('public service URL')
    const local = {...manifest(), network: 'local' as const, chainId: NETWORKS.local.chainId, services: plain}
    expect(parseNetworkManifest(local).services).toEqual(plain)
    // …and https is accepted on both.
    expect(parseNetworkManifest({...manifest(), services: [{kind: 'agent', url: 'https://agent.example/v1'}]}).services).toHaveLength(1)
    // A fragment is refused too: it is never meaningful to a service base URL and is a
    // common way to smuggle a second target past a naive prefix check.
    expect(() => parseNetworkManifest({...manifest(), services: [{kind: 'agent', url: 'https://agent.example/v1#evil'}]}))
      .toThrow('public service URL')
  })
  it('checks full CREATE2 hash inputs against the claimed address', () => {
    const m = manifest(), create2 = {factory: addr, salt: hash, initCodeHash: hash}
    m.contracts[0] = {...m.contracts[0]!, create2,
      address: getCreate2Address({from: addr, salt: hash, bytecodeHash: hash})}
    expect(parseNetworkManifest(m)).toBe(m)
    m.contracts[0].create2!.initCodeHash = `0x${'cd'.repeat(32)}`
    expect(() => parseNetworkManifest(m)).toThrow('CREATE2 address')
  })
})

// ─── observing a live deployment against the manifest ────────────────────────
//
// `observeNetworkManifest` is the only part of this module that touches a chain, and it is
// the part that decides whether a deployment IS what the manifest says. Everything here is
// asserted against a stubbed JSON-RPC, because the answers are what the checks turn on.
//
// The property that earns the function its keep is the PROXY one: a UUPS proxy's own
// bytecode is unchanged by an upgrade, so comparing only the address's code hash would call
// a swapped implementation a match. The implementation slot is read, its code hashed, and
// BOTH have to agree with the manifest.
//
// The `verifiedAt` cross-check is the other one: a manifest verified against a block that is
// no longer canonical proves nothing, so the observation refuses rather than reporting a
// match it cannot stand behind.

const NODE_REGISTRY = `0x${'aa'.repeat(20)}` as const
const KEY_REGISTRY = `0x${'bb'.repeat(20)}` as const
const IMPL = `0x${'cc'.repeat(20)}` as const
const OTHER_IMPL = `0x${'dd'.repeat(20)}` as const

/** Runtime bytecode per address, and the hash the manifest should pin for it. */
const CODE: Record<string, Hex> = {
  [NODE_REGISTRY]: '0x60806040523480',
  [KEY_REGISTRY]: '0x60806040523481',
  [IMPL]: '0x60806040523482',
  [OTHER_IMPL]: '0x60806040523483',
}
const codeHash = (a: string): Hex => keccak256(CODE[a.toLowerCase()] ?? CODE[a] ?? '0x')

interface RpcState {
  chainId: number
  /** The finalized block the observation pins every read to. */
  finalized: {number: bigint; hash: Hex}
  /** Historic blocks by number, for the verifiedAt canonical check. */
  blocks: Record<string, Hex>
  /** Runtime code per address; absent = not deployed. */
  code: Record<string, Hex | undefined>
  /** EIP-1967 implementation slot contents per proxy address. */
  slot: Record<string, Hex | undefined>
  /** Every read, so block pinning can be asserted rather than assumed. */
  reads: Array<{method: string; address?: string; blockNumber?: string}>
}
let rpc: RpcState

function freshRpc(over: Partial<RpcState> = {}): RpcState {
  return {
    chainId: 43113,
    finalized: {number: 200n, hash: `0x${'f1'.repeat(32)}`},
    blocks: {'100': hash},
    code: {[NODE_REGISTRY]: CODE[NODE_REGISTRY], [KEY_REGISTRY]: CODE[KEY_REGISTRY], [IMPL]: CODE[IMPL], [OTHER_IMPL]: CODE[OTHER_IMPL]},
    slot: {},
    reads: [],
    ...over,
  }
}

const blockJson = (number: bigint | null, blockHash: Hex | null): Record<string, unknown> => ({
  number: number === null ? null : `0x${number.toString(16)}`,
  hash: blockHash,
  parentHash: `0x${'bb'.repeat(32)}`,
  timestamp: '0x65000000',
  gasLimit: '0x1c9c380',
  gasUsed: '0x5208',
  miner: `0x${'11'.repeat(20)}`,
  extraData: '0x',
  difficulty: '0x0',
  totalDifficulty: '0x0',
  size: '0x220',
  nonce: '0x0000000000000000',
  sha3Uncles: `0x${'00'.repeat(32)}`,
  logsBloom: `0x${'00'.repeat(256)}`,
  transactionsRoot: `0x${'00'.repeat(32)}`,
  stateRoot: `0x${'00'.repeat(32)}`,
  receiptsRoot: `0x${'00'.repeat(32)}`,
  transactions: [],
  uncles: [],
  baseFeePerGas: '0x1',
})

const realFetch = globalThis.fetch

/** A manifest whose pinned hashes match the stubbed chain. */
function liveManifest(): NetworkManifest {
  return {
    schemaVersion: 1, network: 'testnet', chainId: 43113, deploymentId: 'fuji-1', revision: 1,
    protocolVersion: '0.1.0', status: 'active',
    verifiedAt: {blockNumber: '100', blockHash: hash, timestamp: '2026-09-14T00:00:00Z'},
    contracts: [
      {name: 'NodeRegistry', address: NODE_REGISTRY, abi: 'contracts/abi/0.1.0/NodeRegistry.json',
        runtimeCodeHash: codeHash(NODE_REGISTRY), deployment: {transactionHash: hash, blockNumber: '99'}, create2: null, proxy: null},
      {name: 'KeyRegistry', address: KEY_REGISTRY, abi: 'contracts/abi/0.1.0/KeyRegistry.json',
        runtimeCodeHash: codeHash(KEY_REGISTRY), deployment: {transactionHash: hash, blockNumber: '99'}, create2: null, proxy: null},
    ],
    services: [],
  }
}

describe('observing a deployment against its manifest', () => {
  beforeEach(() => {
    rpc = freshRpc()
    globalThis.fetch = (async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as {id: number; method: string; params?: unknown[]}
      const params = body.params ?? []
      let result: unknown
      switch (body.method) {
        case 'eth_chainId':
          result = `0x${rpc.chainId.toString(16)}`
          break
        case 'eth_getBlockByNumber': {
          const tag = String(params[0])
          rpc.reads.push({method: 'eth_getBlockByNumber', blockNumber: tag})
          if (tag === 'finalized') result = blockJson(rpc.finalized.number, rpc.finalized.hash)
          else result = blockJson(BigInt(tag), rpc.blocks[String(BigInt(tag))] ?? `0x${'99'.repeat(32)}`)
          break
        }
        case 'eth_getCode': {
          const a = String(params[0]).toLowerCase()
          rpc.reads.push({method: 'eth_getCode', address: a, blockNumber: String(params[1])})
          result = rpc.code[a] ?? '0x'
          break
        }
        case 'eth_getStorageAt': {
          const a = String(params[0]).toLowerCase()
          rpc.reads.push({method: 'eth_getStorageAt', address: a, blockNumber: String(params[2])})
          result = rpc.slot[a] ?? `0x${'00'.repeat(32)}`
          break
        }
        default:
          throw new Error(`stub: unhandled ${body.method}`)
      }
      const payload = {jsonrpc: '2.0', id: body.id, result}
      return {ok: true, status: 200, json: async () => payload, text: async () => JSON.stringify(payload),
        headers: new Headers({'content-type': 'application/json'})} as unknown as Response
    }) as typeof globalThis.fetch
  })
  afterEach(() => {
    globalThis.fetch = realFetch
  })

  const observe = (m: NetworkManifest = liveManifest()) => observeNetworkManifest(m, 'http://127.0.0.1:1/')

  it('reports a match when every pinned code hash is what the chain holds', async () => {
    const o = await observe()
    expect(o.matches).toBe(true)
    expect(o.chainId).toBe(43113)
    expect(o.blockNumber).toBe('200')
    expect(o.blockHash).toBe(rpc.finalized.hash)
    expect(Number.isFinite(Date.parse(o.observedAt))).toBe(true)
    expect(o.contracts.map(c => c.name)).toEqual(['NodeRegistry', 'KeyRegistry'])
    expect(o.contracts.every(c => c.matches)).toBe(true)
    // Both hashes are reported, so a caller can show the difference rather than just a verdict.
    expect(o.contracts[0]!.observedCodeHash).toBe(codeHash(NODE_REGISTRY))
    expect(o.contracts[0]!.expectedCodeHash).toBe(codeHash(NODE_REGISTRY))
    // A non-proxy contract reports no implementation.
    expect(o.contracts[0]!.implementation).toBeNull()
  })

  it('pins every read to the one finalized block', async () => {
    // ⚠ Otherwise the observation straddles blocks: a contract could be read before an
    // upgrade and its implementation after it, reporting a state that never existed.
    await observe()
    const pinned = rpc.reads.filter(r => r.method === 'eth_getCode' || r.method === 'eth_getStorageAt')
    expect(pinned.length).toBeGreaterThan(0)
    expect([...new Set(pinned.map(r => r.blockNumber))]).toEqual(['0xc8']) // 200
    expect(rpc.reads.some(r => r.blockNumber === 'finalized')).toBe(true)
  })

  it('refuses a chain that is not the manifest\'s', async () => {
    rpc.chainId = 43114
    await expect(observe()).rejects.toThrow('RPC chain does not match manifest')
  })

  it('refuses an unfinalized block', async () => {
    // A chain with no finalized block yet answers with nulls; verifying against it would
    // pin an observation to a block that can still disappear.
    rpc.finalized = {number: null as unknown as bigint, hash: `0x${'f1'.repeat(32)}`}
    await expect(observe()).rejects.toThrow('unfinalized block')
    rpc = freshRpc({finalized: {number: 200n, hash: null as unknown as Hex}})
    await expect(observe()).rejects.toThrow('unfinalized block')
  })

  it('refuses a manifest verified ahead of the finalized chain', async () => {
    // Claiming verification at a block the chain has not finalized is either a forged
    // manifest or a verification against a different chain.
    rpc.finalized = {number: 50n, hash: `0x${'f1'.repeat(32)}`}
    await expect(observe()).rejects.toThrow('ahead of finalized chain')
  })

  it('refuses a manifest whose verification block is no longer canonical', async () => {
    // ⚠ The reorg check. The manifest pins {blockNumber, blockHash}; if the block at that
    // height now has a different hash, the verification happened on an orphaned branch and
    // proves nothing about this chain.
    rpc.blocks = {'100': `0x${'ee'.repeat(32)}`}
    await expect(observe()).rejects.toThrow('not canonical')
  })

  it('skips the verification cross-check when the manifest claims none', async () => {
    // A planned deployment has no verifiedAt, so there is nothing to cross-check — and the
    // absence must not be read as a failure.
    const planned: NetworkManifest = {...liveManifest(), status: 'planned', verifiedAt: null}
    const o = await observe(planned)
    expect(rpc.reads.filter(r => r.method === 'eth_getBlockByNumber' && r.blockNumber !== 'finalized')).toHaveLength(0)
    // …but a non-active deployment can never report an overall match, however well its code
    // lines up. Displaying it is fine; trusting it is not.
    expect(o.contracts.every(c => c.matches)).toBe(true)
    expect(o.matches).toBe(false)
  })

  it('reports a mismatch when deployed code is not what was pinned', async () => {
    rpc.code[KEY_REGISTRY] = '0xdeadbeef'
    const o = await observe()
    expect(o.matches).toBe(false)
    expect(o.contracts[0]!.matches).toBe(true)
    const key = o.contracts[1]!
    expect(key.matches).toBe(false)
    expect(key.observedCodeHash).toBe(keccak256('0xdeadbeef'))
    expect(key.observedCodeHash).not.toBe(key.expectedCodeHash)
  })

  it('reports an address with no code at all as unmatched', async () => {
    // An empty `0x` is what an undeployed (or self-destructed) address answers.
    rpc.code[KEY_REGISTRY] = undefined
    const o = await observe()
    expect(o.contracts[1]!.observedCodeHash).toBeNull()
    expect(o.contracts[1]!.matches).toBe(false)
    expect(o.matches).toBe(false)
  })

  it('verifies a proxy\'s implementation, not just the proxy', async () => {
    const m = liveManifest()
    m.contracts[1] = {...m.contracts[1]!, proxy: {implementation: IMPL, runtimeCodeHash: codeHash(IMPL), upgradeAuthority: null}}
    rpc.slot[KEY_REGISTRY.toLowerCase()] = `0x${'00'.repeat(12)}${IMPL.slice(2)}`
    const o = await observe(m)
    expect(o.matches).toBe(true)
    // The implementation is read from the EIP-1967 slot and reported alongside the proxy.
    expect(o.contracts[1]!.implementation?.toLowerCase()).toBe(IMPL.toLowerCase())
    expect(o.contracts[1]!.implementationCodeHash).toBe(codeHash(IMPL))
    expect(rpc.reads.some(r => r.method === 'eth_getStorageAt' && r.address === KEY_REGISTRY.toLowerCase())).toBe(true)
    // A non-proxy contract must not be probed for an implementation slot.
    expect(rpc.reads.some(r => r.method === 'eth_getStorageAt' && r.address === NODE_REGISTRY.toLowerCase())).toBe(false)
  })

  it('catches a swapped implementation behind an unchanged proxy', async () => {
    // ⚠ THE reason this function exists. A UUPS upgrade leaves the proxy's own bytecode
    // byte-identical, so a check that hashed only the address's code would report a match
    // while the logic behind it had been replaced.
    const m = liveManifest()
    m.contracts[1] = {...m.contracts[1]!, proxy: {implementation: IMPL, runtimeCodeHash: codeHash(IMPL), upgradeAuthority: null}}
    rpc.slot[KEY_REGISTRY.toLowerCase()] = `0x${'00'.repeat(12)}${OTHER_IMPL.slice(2)}`
    const o = await observe(m)
    // The proxy's own code still matches what the manifest pinned…
    expect(o.contracts[1]!.observedCodeHash).toBe(o.contracts[1]!.expectedCodeHash)
    // …and the observation is a mismatch anyway.
    expect(o.contracts[1]!.matches).toBe(false)
    expect(o.contracts[1]!.implementation?.toLowerCase()).toBe(OTHER_IMPL.toLowerCase())
    expect(o.matches).toBe(false)
  })

  it('catches an implementation at the right address with the wrong code', async () => {
    // The address can be correct while the code at it is not — a redeploy to the same
    // address, or a manifest pinned against a different build.
    const m = liveManifest()
    m.contracts[1] = {...m.contracts[1]!, proxy: {implementation: IMPL, runtimeCodeHash: codeHash(IMPL), upgradeAuthority: null}}
    rpc.slot[KEY_REGISTRY.toLowerCase()] = `0x${'00'.repeat(12)}${IMPL.slice(2)}`
    rpc.code[IMPL] = '0xfeedface'
    const o = await observe(m)
    expect(o.contracts[1]!.implementation?.toLowerCase()).toBe(IMPL.toLowerCase())
    expect(o.contracts[1]!.implementationCodeHash).toBe(keccak256('0xfeedface'))
    expect(o.contracts[1]!.matches).toBe(false)
  })

  it('treats an empty implementation slot as unmatched rather than absent', async () => {
    // A zero slot means the proxy is not initialised (or is not the proxy the manifest
    // thinks). Either way it cannot satisfy a manifest that pins an implementation.
    const m = liveManifest()
    m.contracts[1] = {...m.contracts[1]!, proxy: {implementation: IMPL, runtimeCodeHash: codeHash(IMPL), upgradeAuthority: null}}
    const o = await observe(m) // slot left at all-zero
    expect(o.contracts[1]!.implementation).toBeNull()
    expect(o.contracts[1]!.implementationCodeHash).toBeNull()
    expect(o.contracts[1]!.matches).toBe(false)
  })

  it('reports an implementation whose own code is missing', async () => {
    const m = liveManifest()
    m.contracts[1] = {...m.contracts[1]!, proxy: {implementation: IMPL, runtimeCodeHash: codeHash(IMPL), upgradeAuthority: null}}
    rpc.slot[KEY_REGISTRY.toLowerCase()] = `0x${'00'.repeat(12)}${IMPL.slice(2)}`
    rpc.code[IMPL] = undefined
    const o = await observe(m)
    expect(o.contracts[1]!.implementationCodeHash).toBeNull()
    expect(o.contracts[1]!.matches).toBe(false)
  })

  it('never reports a match for an empty contract set', async () => {
    // `every` over an empty array is vacuously true, so the length check is what stops an
    // empty manifest from reporting a verified deployment. That is the classic
    // green-that-cannot-fail, and it is guarded.
    const empty: NetworkManifest = {...liveManifest(), status: 'planned', verifiedAt: null, contracts: []}
    const o = await observe(empty)
    expect(o.contracts).toHaveLength(0)
    expect(o.matches).toBe(false)
  })

  it('pins the EIP-1967 implementation slot to its standard value', () => {
    // A wrong slot reads zero for every proxy, which would turn every proxy observation
    // into a silent mismatch. Derived here rather than copied.
    const derived = `0x${(BigInt(keccak256(toHex('eip1967.proxy.implementation'))) - 1n).toString(16).padStart(64, '0')}`
    expect(IMPLEMENTATION_SLOT).toBe(derived)
  })
})
