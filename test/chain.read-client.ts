// The viem read client — offline, against a stubbed JSON-RPC endpoint.
//
// `createTasraChainClient` was the least covered file in the package. Most of it is
// one-line `readContract` wrappers, but four things in it carry real logic and each
// has a documented invariant that nothing checked:
//
//   • logSources    — the vesting vaults are ONE ABI over up to three TRANCHE address
//                     keys, which are deliberately not contract names. Scanning by
//                     name therefore misses every vault log. The source says so; now
//                     a test fails if that stops being true.
//   • getLogsWindowed — window arithmetic (the last window must clamp to toBlock, not
//                     overshoot it) and per-address ABI attribution, which is what
//                     makes a signature shared by two contracts decode correctly.
//   • getBlockTimestamps — de-duplicates before hitting the RPC.
//   • readMany      — Multicall3 batching, and every way that can go wrong on a chain
//                     that does not have it. A failing item yields `null` in place, so
//                     one unreadable operator does not blank the set — unless
//                     `allowFailure: false`, where position carries meaning.
//
// The stub answers real JSON-RPC and the real viem stack runs on top of it, so the
// encode/decode path is exercised rather than mocked away — including a working
// `aggregate3` at the Multicall3 address, so the batched path is the real viem multicall
// action rather than a stand-in for it.
//
// ⚠ The batching assertions count REQUESTS. They have to: a version of readMany that
// returns correct values while still issuing one call per item passes every value-based
// test there is, and that is precisely the defect this replaced.
//
// Run: tsx test/chain.read-client.ts — exits non-zero on any failure.

import {
  decodeFunctionData,
  encodeAbiParameters,
  encodeEventTopics,
  encodeFunctionResult,
  multicall3Abi,
  toFunctionSelector,
  type Abi,
} from 'viem'
import {createTasraChainClient, MULTICALL3_ADDRESS} from '../src/chain/client.ts'
import {CONTRACT_ABIS, type ContractName} from '../src/chain/abis/index.ts'
import {resolveVerifierDirectory} from '../src/chain/discovery.ts'
import type {AddressBook} from '../src/chain/deployments.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean, detail = ''): void {
  if (cond) passed++
  else failures.push(name + (detail ? ` — ${detail}` : ''))
}
function eq(name: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v))
  const b = JSON.stringify(expected, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v))
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

const addr = (n: number): `0x${string}` => `0x${n.toString(16).padStart(40, '0')}`
const TOKEN = addr(0xaa)
const EURC = addr(0xbb)
const NODES = addr(0xcc)
const VAULT_INVESTOR = addr(0xd1)
const VAULT_TEAM = addr(0xd2)

const addresses: AddressBook = {
  TasraToken: TOKEN,
  MockEurc: EURC,
  NodeRegistry: NODES,
  TasraVestingVault_investor: VAULT_INVESTOR,
  TasraVestingVault_team: VAULT_TEAM,
}
const abiAt = new Map<string, ContractName>([
  [TOKEN, 'TasraToken'],
  [EURC, 'MockEurc'],
  [NODES, 'NodeRegistry'],
  [VAULT_INVESTOR, 'TasraVestingVault'],
  [VAULT_TEAM, 'TasraVestingVault'],
])

// ─── the log fixture ──────────────────────────────────────────────────────────
// One ERC-20 Transfer on each of two contracts that share the signature, plus a
// NodeRegistry event, spread over blocks so the windowing is observable.
interface Fixture {
  address: `0x${string}`
  block: bigint
  topics: readonly `0x${string}`[]
  data: `0x${string}`
}
const transferLog = (at: `0x${string}`, contract: ContractName, block: bigint, value: bigint): Fixture => ({
  address: at,
  block,
  topics: encodeEventTopics({
    abi: CONTRACT_ABIS[contract] as Abi,
    eventName: 'Transfer',
    args: {from: addr(1), to: addr(2)},
  }) as readonly `0x${string}`[],
  data: encodeAbiParameters([{type: 'uint256'}], [value]),
})

const fixtures: Fixture[] = [
  transferLog(TOKEN, 'TasraToken', 0n, 100n),
  transferLog(EURC, 'MockEurc', 1n, 200n),
  transferLog(TOKEN, 'TasraToken', 3n, 300n),
  transferLog(EURC, 'MockEurc', 5n, 400n),
]
// Two logs from the SAME address inside ONE window, so the per-address grouping has to
// accumulate rather than overwrite. With one log per address per window a grouping bug
// that drops all but the last is invisible.
const sameWindowPair: Fixture[] = [
  transferLog(TOKEN, 'TasraToken', 10n, 500n),
  transferLog(TOKEN, 'TasraToken', 11n, 600n),
]
/** An extra log the RPC returns from an address that was never asked for. */
let injectStrayLog = false

// ─── the JSON-RPC stub ────────────────────────────────────────────────────────
/** Canned eth_call results, keyed by `contract.functionName`. */
const callResults: Record<string, unknown> = {
  'TasraToken.symbol': 'TSRA',
  'TasraToken.decimals': 18,
  'TasraToken.totalSupply': 10n ** 24n,
  'TasraToken.balanceOf': 42n,
  'MockEurc.symbol': 'EURC',
  'NodeRegistry.operatorCount': 3n,
  'NodeRegistry.activeCount': 2n,
  'TasraVestingVault.released': 7n,
  'TasraVestingVault.beneficiary': addr(0xbeef),
}
/** Addresses whose eth_call must fail, to drive the readMany contract. */
const failingArg = new Set<string>()
/**
 * When set, the stub answers ANY view call with a type-correct value derived from the
 * ABI, instead of requiring a canned result. That is what lets the reader-wiring table
 * below cover ~45 readers without 45 fixtures.
 */
let genericReads = false

/** A type-correct placeholder for one ABI output, so encodeFunctionResult accepts it. */
function zeroFor(t: {type: string; components?: readonly {type: string}[]}): unknown {
  if (t.type === 'string') return ''
  if (t.type === 'bool') return false
  if (t.type === 'address') return addr(0)
  if (t.type === 'bytes') return '0x'
  if (t.type === 'tuple') return (t.components ?? []).map(zeroFor)
  if (t.type.endsWith('[]')) return []
  const fixedBytes = /^bytes(\d+)$/.exec(t.type)
  if (fixedBytes) return `0x${'00'.repeat(Number(fixedBytes[1]))}`
  if (/^u?int/.test(t.type)) return 0n
  throw new Error(`stub: no placeholder for ABI type ${t.type}`)
}

/**
 * The 4-byte selector of `contract.functionName`, read from the vendored ABI.
 *
 * The ABI ITEM goes to viem rather than a signature string assembled from
 * `inputs.map(i => i.type)`: a struct parameter's type is the literal `"tuple"`, so
 * hand-building the string yields the wrong selector for any function taking one.
 */
function selectorOf(contract: ContractName, functionName: string): string {
  const abi = CONTRACT_ABIS[contract] as Abi
  const item = abi.find(i => i.type === 'function' && i.name === functionName)
  if (!item) throw new Error(`no function ${functionName} on ${contract}`)
  return toFunctionSelector(item as Parameters<typeof toFunctionSelector>[0])
}

// ─── the Multicall3 stand-in ──────────────────────────────────────────────────
/** What the canonical Multicall3 address behaves like in a given test. */
type Multicall3Mode = 'deployed' | 'absent' | 'wrong-contract' | 'probe-error' | 'aggregate-error'
let multicall3Mode: Multicall3Mode = 'absent'
/** Where the stub pretends Multicall3 is deployed (to test an explicit override). */
let multicall3At: `0x${string}` = MULTICALL3_ADDRESS.toLowerCase() as `0x${string}`

const requests: Array<{method: string; params: unknown}> = []
const realFetch = globalThis.fetch

/** Execute one inner call of an aggregate3 through the same path a direct call takes. */
function innerCall(target: `0x${string}`, callData: `0x${string}`): {success: boolean; returnData: `0x${string}`} {
  try {
    return {success: true, returnData: rpcResult('eth_call', [{to: target, data: callData}]) as `0x${string}`}
  } catch {
    return {success: false, returnData: '0x'}
  }
}

function rpcResult(method: string, params: unknown[]): unknown {
  if (method === 'eth_getCode') {
    const at = String((params as [string])[0]).toLowerCase()
    if (at !== multicall3At) return '0x'
    // An RPC that will not answer the probe at all.
    if (multicall3Mode === 'probe-error') throw new Error('stub: getCode unsupported')
    // `absent` is the bare-chain case: no contract at the canonical address.
    return multicall3Mode === 'absent' ? '0x' : '0x60806040'
  }
  if (method === 'eth_blockNumber') return '0x64'
  if (method === 'eth_chainId') return '0x539'
  if (method === 'eth_getBlockByNumber') {
    const n = BigInt(String(params[0]))
    // Timestamp derived from the block number so the assertion can be exact.
    return {number: `0x${n.toString(16)}`, timestamp: `0x${(1_700_000_000n + n).toString(16)}`}
  }
  if (method === 'eth_getLogs') {
    const f = params[0] as {address: `0x${string}`[]; fromBlock: `0x${string}`; toBlock: `0x${string}`}
    const want = new Set(f.address.map(a => a.toLowerCase()))
    const from = BigInt(f.fromBlock)
    const to = BigInt(f.toBlock)
    const pool = injectStrayLog
      ? [...fixtures, ...sameWindowPair, {...transferLog(TOKEN, 'TasraToken', 0n, 999n), address: addr(0xdead)}]
      : [...fixtures, ...sameWindowPair]
    return pool
      .filter(l => (want.has(l.address.toLowerCase()) || l.address === addr(0xdead)) && l.block >= from && l.block <= to)
      .map((l, i) => ({
        address: l.address,
        topics: l.topics,
        data: l.data,
        blockNumber: `0x${l.block.toString(16)}`,
        blockHash: `0x${'11'.repeat(32)}`,
        transactionHash: `0x${'22'.repeat(32)}`,
        transactionIndex: '0x0',
        logIndex: `0x${i.toString(16)}`,
        removed: false,
      }))
  }
  if (method === 'eth_call') {
    const {to, data} = params[0] as {to: `0x${string}`; data: `0x${string}`}
    if (to.toLowerCase() === multicall3At) {
      // The aggregate call itself is rejected — an out-of-gas eth_call, or an RPC that
      // refuses the payload. viem THROWS here, unlike the wrong-contract case below.
      if (multicall3Mode === 'aggregate-error') throw new Error('stub: aggregate rejected (out of gas)')
      // Something at the address that is NOT Multicall3: the aggregate returns data viem
      // cannot decode, which is the failure the fallback exists for.
      if (multicall3Mode === 'wrong-contract') return '0x'
      const [calls] = decodeFunctionData({abi: multicall3Abi, data}).args as [
        readonly {target: `0x${string}`; allowFailure: boolean; callData: `0x${string}`}[],
      ]
      return encodeFunctionResult({
        abi: multicall3Abi,
        functionName: 'aggregate3',
        result: calls.map(c => innerCall(c.target, c.callData)),
      })
    }
    const contract = abiAt.get(to.toLowerCase() as `0x${string}`) ?? abiAt.get(to)
    if (!contract) throw new Error(`stub: no ABI for ${to}`)
    const abi = CONTRACT_ABIS[contract] as Abi
    const {functionName, args} = decodeFunctionData({abi, data})
    if (args?.some(a => typeof a === 'string' && failingArg.has(a.toLowerCase()))) {
      // An undeployed/reverting read: empty return data, which viem surfaces as a decode failure.
      return '0x'
    }
    const key = `${contract}.${functionName}`
    if (key in callResults) {
      return encodeFunctionResult({abi, functionName, result: callResults[key] as never})
    }
    if (!genericReads) throw new Error(`stub: no canned result for ${key}`)
    const outputs = (abi as readonly {type: string; name?: string; outputs?: readonly {type: string}[]}[]).find(
      i => i.type === 'function' && i.name === functionName,
    )?.outputs
    const placeholders = (outputs ?? []).map(zeroFor)
    return encodeFunctionResult({
      abi,
      functionName,
      result: (placeholders.length === 1 ? placeholders[0] : placeholders) as never,
    })
  }
  throw new Error(`stub: unhandled method ${method}`)
}

globalThis.fetch = (async (_url: string, init?: RequestInit) => {
  const body = JSON.parse(String(init?.body)) as {id: number; method: string; params?: unknown[]}
  requests.push({method: body.method, params: body.params})
  let payload: unknown
  try {
    payload = {jsonrpc: '2.0', id: body.id, result: rpcResult(body.method, body.params ?? [])}
  } catch (error) {
    payload = {
      jsonrpc: '2.0',
      id: body.id,
      error: {code: -32000, message: error instanceof Error ? error.message : String(error)},
    }
  }
  return {
    ok: true,
    status: 200,
    json: async () => payload,
    text: async () => JSON.stringify(payload),
    headers: new Headers({'content-type': 'application/json'}),
  } as unknown as Response
}) as typeof globalThis.fetch

const rpcUrl = 'http://127.0.0.1:1/'
const countOf = (method: string): number => requests.filter(r => r.method === method).length

try {
  const chain = createTasraChainClient({rpcUrl, addresses})

  // ─── the address book surface ───────────────────────────────────────────────
  ok('addresses are exposed as given', chain.addresses === addresses)
  eq('chainId defaults to the dev chain', chain.client.chain?.id, 1337)
  eq(
    'an explicit chainId is honoured',
    createTasraChainClient({rpcUrl, addresses, chainId: 43113}).client.chain?.id,
    43113,
  )

  {
    const deployed = chain.deployedContracts()
    ok('deployedContracts lists the contracts with an address', deployed.includes('TasraToken') && deployed.includes('NodeRegistry'))
    ok('deployedContracts omits contracts with no address', !deployed.includes('Settlement'))
    // ⚠ The trap logSources exists to work around: a tranche key is not a contract name,
    // so the vaults are invisible to a by-name scan even though their logs matter.
    ok(
      'deployedContracts does NOT see a vault present only under tranche keys',
      !deployed.includes('TasraVestingVault'),
    )
  }

  // ─── logSources ─────────────────────────────────────────────────────────────
  {
    const sources = chain.logSources()
    const byAddress = new Map(sources.map(s => [s.address, s.contract]))
    ok('logSources includes a plain contract', byAddress.get(TOKEN) === 'TasraToken')
    // The invariant: a by-name scan misses these, so logSources must add them back.
    ok('logSources adds both vault tranche addresses', byAddress.get(VAULT_INVESTOR) === 'TasraVestingVault' && byAddress.get(VAULT_TEAM) === 'TasraVestingVault')
    ok('a tranche is attributed to the vault ABI', byAddress.get(VAULT_TEAM) === 'TasraVestingVault')
    eq('logSources de-duplicates by address', sources.length, new Set(sources.map(s => s.address.toLowerCase())).size)

    // A single-vault deployment setting only the bare key must be scanned once, not
    // once per tranche.
    const single = createTasraChainClient({
      rpcUrl,
      addresses: {TasraToken: TOKEN, TasraVestingVault: VAULT_INVESTOR},
    })
    eq(
      'a bare single-vault key yields exactly one vault source',
      single.logSources().filter(s => s.contract === 'TasraVestingVault').length,
      1,
    )
    // Same address under the bare key AND a tranche key: still one entry.
    const overlapping = createTasraChainClient({
      rpcUrl,
      addresses: {TasraVestingVault: VAULT_INVESTOR, TasraVestingVault_investor: VAULT_INVESTOR},
    })
    eq('an address reachable under two keys is scanned once', overlapping.logSources().length, 1)

    // An explicit list is honoured, and excludes the vaults unless asked for.
    const only = chain.logSources(['TasraToken'])
    eq('an explicit list returns just that contract', only.map(s => s.contract), ['TasraToken'])
    ok(
      'an explicit list without the vault excludes the tranches',
      !only.some(s => s.address === VAULT_INVESTOR),
    )
    ok(
      'an explicit list naming the vault includes the tranches',
      chain.logSources(['TasraVestingVault']).length === 2,
    )
    eq('an empty list yields no sources', chain.logSources([]).length, 0)
  }

  // ─── getBlockNumber ─────────────────────────────────────────────────────────
  eq('getBlockNumber returns the tip', await chain.getBlockNumber(), 100n)

  // ─── getLogsWindowed ────────────────────────────────────────────────────────
  {
    requests.length = 0
    const windows: Array<{to: bigint; n: number}> = []
    const events = await chain.getLogsWindowed({
      fromBlock: 0n,
      toBlock: 5n,
      windowSize: 2,
      onWindow: (to, evs) => windows.push({to, n: evs.length}),
    })
    eq('windowed scan makes one getLogs call per window', countOf('eth_getLogs'), 3)
    eq('onWindow reports each window boundary', windows.map(w => w.to), [1n, 3n, 5n])
    eq('onWindow events sum to the returned set', windows.reduce((s, w) => s + w.n, 0), events.length)
    eq('every fixture log is returned', events.length, 4)

    // The point of per-address decoding: Transfer(address,address,uint256) is defined by
    // BOTH TasraToken and MockEurc. Decoding by signature alone cannot tell them apart;
    // decoding per emitting address can.
    const attributed = events.map(e => `${e.contract}@${e.address.toLowerCase()}`)
    ok(
      'a shared event signature is attributed to the emitting contract',
      attributed.filter(a => a === `TasraToken@${TOKEN}`).length === 2 &&
        attributed.filter(a => a === `MockEurc@${EURC}`).length === 2,
    )
    ok('decoded args survive the round trip', events.every(e => typeof e.args.value === 'bigint'))
    eq(
      'values decode per log',
      events.map(e => e.args.value).sort((a, b) => Number(a) - Number(b)),
      [100n, 200n, 300n, 400n],
    )
  }
  {
    // The last window must CLAMP to toBlock. Overshooting asks the RPC for blocks past
    // the requested range, which a range-capped provider rejects.
    requests.length = 0
    await chain.getLogsWindowed({fromBlock: 0n, toBlock: 4n, windowSize: 3})
    const ranges = requests
      .filter(r => r.method === 'eth_getLogs')
      .map(r => {
        const f = (r.params as [{fromBlock: string; toBlock: string}])[0]
        return `${BigInt(f.fromBlock)}-${BigInt(f.toBlock)}`
      })
    eq('the final window clamps to toBlock', ranges, ['0-2', '3-4'])
  }
  {
    // One window covering everything, and a single-block range.
    requests.length = 0
    await chain.getLogsWindowed({fromBlock: 2n, toBlock: 2n})
    eq('a single-block range is one call', countOf('eth_getLogs'), 1)
    const f = (requests[0]?.params as [{fromBlock: string; toBlock: string}])[0]
    eq('a single-block range asks for exactly that block', [BigInt(f.fromBlock), BigInt(f.toBlock)], [2n, 2n])
  }
  {
    // Several logs from one address in one window must all survive the grouping.
    const events = await chain.getLogsWindowed({fromBlock: 10n, toBlock: 11n, windowSize: 10})
    eq('multiple logs from one address in one window are all kept', events.length, 2)
    eq(
      'each keeps its own decoded value',
      events.map(e => e.args.value).sort((a, b) => Number(a) - Number(b)),
      [500n, 600n],
    )
  }
  {
    // An RPC that returns a log from an address that was not requested must be SKIPPED:
    // there is no ABI to attribute it to, and guessing one would mis-decode it.
    injectStrayLog = true
    const events = await chain.getLogsWindowed({fromBlock: 0n, toBlock: 0n})
    ok('a log from an unrequested address is skipped, not mis-decoded', events.every(e => e.address !== addr(0xdead)))
    eq('the requested log still comes through', events.length, 1)
    injectStrayLog = false
  }
  {
    // No sources → no RPC traffic at all. An empty result must not cost a round trip.
    requests.length = 0
    const events = await chain.getLogsWindowed({fromBlock: 0n, toBlock: 1000n, contracts: []})
    eq('no sources yields no events', events.length, 0)
    eq('no sources makes no RPC call', countOf('eth_getLogs'), 0)
  }

  // ─── getBlockTimestamps ─────────────────────────────────────────────────────
  {
    requests.length = 0
    const ts = await chain.getBlockTimestamps([7n, 7n, 9n, 7n, 9n])
    eq('duplicate block numbers are fetched once each', countOf('eth_getBlockByNumber'), 2)
    eq('timestamps are keyed by decimal string', [...ts.keys()].sort(), ['7', '9'])
    eq('timestamp is seconds as a number', ts.get('7'), 1_700_000_007)
    ok('timestamps are numbers, not bigints', typeof ts.get('9') === 'number')
    eq('an empty input makes no call and returns empty', (await chain.getBlockTimestamps([])).size, 0)
  }

  // ─── read / readers ─────────────────────────────────────────────────────────
  eq('generic read returns the decoded value', await chain.read('TasraToken', 'symbol'), 'TSRA')
  eq('typed reader: token symbol', await chain.readers.token.symbol(), 'TSRA')
  eq('typed reader: token decimals', await chain.readers.token.decimals(), 18)
  eq('typed reader: token totalSupply', await chain.readers.token.totalSupply(), 10n ** 24n)
  eq('typed reader: reader with an argument', await chain.readers.token.balanceOf(addr(3)), 42n)
  eq('typed reader: nodeRegistry operatorCount', await chain.readers.nodeRegistry.operatorCount(), 3n)

  // A reader for a contract with no address must name the contract AND what is known,
  // because the usual cause is an address book built for a different deployment.
  await rejectsWith(
    'a missing contract address names the contract and the known keys',
    /AddressBook is missing Settlement\. Known: .*TasraToken/,
    () => chain.readers.settlement.totalHeld(),
  )
  await rejectsWith(
    'an empty address book says so rather than listing nothing',
    /AddressBook is missing NodeRegistry\. Known: \(none\)/,
    () => createTasraChainClient({rpcUrl, addresses: {}}).readers.nodeRegistry.activeCount(),
  )

  // ─── vault tranches ─────────────────────────────────────────────────────────
  {
    eq('vault(tranche) resolves that tranche address', chain.readers.vault('investor').address(), VAULT_INVESTOR)
    eq('a second tranche resolves separately', chain.readers.vault('team').address(), VAULT_TEAM)
    eq('tranche reader reads', await chain.readers.vault('investor').released(), 7n)
    // viem returns EIP-55 checksummed addresses, so compare case-insensitively.
    eq(
      'tranche reader with no args',
      (await chain.readers.vault('team').beneficiary()).toLowerCase(),
      addr(0xbeef),
    )
    // The bare key is the fallback for a single-vault deployment.
    const single = createTasraChainClient({rpcUrl, addresses: {TasraVestingVault: VAULT_INVESTOR}})
    eq('an unset tranche falls back to the bare vault key', single.readers.vault('community').address(), VAULT_INVESTOR)
    await rejectsWith(
      'a missing vault names the tranche key it wanted',
      /AddressBook is missing TasraVestingVault_community/,
      async () => createTasraChainClient({rpcUrl, addresses: {}}).readers.vault('community').address(),
    )
  }

  // ─── readMany ───────────────────────────────────────────────────────────────
  {
    const args = [addr(0x11), addr(0x12), addr(0x13)].map(a => [a])
    eq(
      'readMany returns one value per argument list, in order',
      await chain.readMany<bigint>('TasraToken', 'balanceOf', args),
      [42n, 42n, 42n],
    )

    // The documented contract: a failing item is `null` IN PLACE. A rejected batch would
    // blank the whole set for one unreadable operator, which on a 10k registry means one
    // bad row hides the other 9,999.
    failingArg.add(addr(0x12))
    const mixed = await chain.readMany<bigint>('TasraToken', 'balanceOf', args)
    eq('a failing item becomes null without failing its siblings', mixed, [42n, null, 42n])
    ok('the failure stays in position', mixed[1] === null && mixed[0] === 42n && mixed[2] === 42n)
    failingArg.delete(addr(0x12))

    eq('readMany with no arguments returns an empty array', (await chain.readMany('TasraToken', 'balanceOf', [])).length, 0)
    await rejectsWith(
      'readMany still fails loudly when the contract has no address',
      /AddressBook is missing Settlement/,
      () => chain.readMany('Settlement', 'totalHeld', [[]]),
    )
  }

  // ─── every typed reader hits the right contract with the right selector ─────
  {
    // ~40 near-identical one-line readers, each naming a contract and a function as
    // strings. A copy-pasted address or function name compiles, type-checks, and is only
    // wrong at runtime — a beacon reader pointing at NodeRegistry, or `seedAt` calling
    // `seed`, look identical to a working one from the outside.
    //
    // So this asserts the WIRING rather than the value: which address was called, and
    // which 4-byte selector. The stub answers any view function with a type-correct value
    // derived from the ABI, so no per-reader fixture is needed.
    const full: AddressBook = {
      NodeRegistry: NODES,
      KeyRegistry: addr(0x01),
      ServiceRegistry: addr(0x02),
      Settlement: addr(0x03),
      TasraToken: TOKEN,
      BondingCurve: addr(0x04),
      Treasury: addr(0x05),
      ThresholdRandomBeacon: addr(0x06),
      VerifierSetRegistry: addr(0x07),
      TasraVestingVault_team: VAULT_TEAM,
    }
    for (const [a, c] of Object.entries({
      [addr(0x01)]: 'KeyRegistry',
      [addr(0x02)]: 'ServiceRegistry',
      [addr(0x03)]: 'Settlement',
      [addr(0x04)]: 'BondingCurve',
      [addr(0x05)]: 'Treasury',
      [addr(0x06)]: 'ThresholdRandomBeacon',
      [addr(0x07)]: 'VerifierSetRegistry',
    } as Record<string, ContractName>)) {
      abiAt.set(a as `0x${string}`, c)
    }
    genericReads = true
    const k = createTasraChainClient({rpcUrl, addresses: full})
    const r = k.readers
    const anyAddr = addr(0x99)
    const id32 = `0x${'11'.repeat(32)}` as `0x${string}`

    /** [label, expected contract, expected solidity function, the call]. */
    const cases: Array<[string, ContractName, string, () => Promise<unknown>]> = [
      ['nodeRegistry.nodeOf', 'NodeRegistry', 'nodeOf', () => r.nodeRegistry.nodeOf(anyAddr)],
      ['nodeRegistry.isActive', 'NodeRegistry', 'isActive', () => r.nodeRegistry.isActive(anyAddr)],
      ['nodeRegistry.operatorCount', 'NodeRegistry', 'operatorCount', () => r.nodeRegistry.operatorCount()],
      ['nodeRegistry.operatorAt', 'NodeRegistry', 'operatorAt', () => r.nodeRegistry.operatorAt(0n)],
      ['nodeRegistry.activeCount', 'NodeRegistry', 'activeCount', () => r.nodeRegistry.activeCount()],
      ['nodeRegistry.attributesOf', 'NodeRegistry', 'attributesOf', () => r.nodeRegistry.attributesOf(anyAddr)],
      ['nodeRegistry.rewardBalanceOf', 'NodeRegistry', 'rewardBalanceOf', () => r.nodeRegistry.rewardBalanceOf(anyAddr)],
      ['nodeRegistry.requiredStake', 'NodeRegistry', 'requiredStake', () => r.nodeRegistry.requiredStake()],
      ['nodeRegistry.operatorIdOf', 'NodeRegistry', 'operatorIdOf', () => r.nodeRegistry.operatorIdOf(anyAddr)],
      ['nodeRegistry.hasTag', 'NodeRegistry', 'hasTag', () => r.nodeRegistry.hasTag(anyAddr, id32)],
      ['nodeRegistry.activeOperators', 'NodeRegistry', 'activeOperators', () => r.nodeRegistry.activeOperators()],
      ['keyRegistry.getKeySlot', 'KeyRegistry', 'getKeySlot', () => r.keyRegistry.getKeySlot(id32)],
      ['keyRegistry.assignedNodes', 'KeyRegistry', 'assignedNodes', () => r.keyRegistry.assignedNodes(id32)],
      // ⚠ The reader is `requiresCommitReveal`; the solidity getter is `requireCommitReveal`.
      // The names deliberately differ, so a "tidy-up" rename on either side breaks the call.
      ['keyRegistry.requiresCommitReveal', 'KeyRegistry', 'requireCommitReveal', () => r.keyRegistry.requiresCommitReveal()],
      ['keyRegistry.verifierPolicy', 'KeyRegistry', 'verifierPolicy', () => r.keyRegistry.verifierPolicy(id32)],
      ['settlement.balanceOf', 'Settlement', 'balanceOf', () => r.settlement.balanceOf(id32)],
      ['settlement.lastNonce', 'Settlement', 'lastNonce', () => r.settlement.lastNonce(id32)],
      ['settlement.revenueSplit', 'Settlement', 'revenueSplit', () => r.settlement.revenueSplit()],
      ['settlement.totalHeld', 'Settlement', 'totalHeld', () => r.settlement.totalHeld()],
      ['token.totalSupply', 'TasraToken', 'totalSupply', () => r.token.totalSupply()],
      ['token.balanceOf', 'TasraToken', 'balanceOf', () => r.token.balanceOf(anyAddr)],
      ['token.symbol', 'TasraToken', 'symbol', () => r.token.symbol()],
      ['token.decimals', 'TasraToken', 'decimals', () => r.token.decimals()],
      ['bondingCurve.spotPrice', 'BondingCurve', 'spotPrice', () => r.bondingCurve.spotPrice()],
      ['bondingCurve.weightedAvgPrice365d', 'BondingCurve', 'weightedAvgPrice365d', () => r.bondingCurve.weightedAvgPrice365d()],
      ['bondingCurve.soldTokens', 'BondingCurve', 'soldTokens', () => r.bondingCurve.soldTokens()],
      ['bondingCurve.reserve', 'BondingCurve', 'reserve', () => r.bondingCurve.reserve()],
      ['treasury.balance', 'Treasury', 'balance', () => r.treasury.balance()],
      ['beacon.seed', 'ThresholdRandomBeacon', 'seed', () => r.beacon.seed()],
      ['beacon.epoch', 'ThresholdRandomBeacon', 'epoch', () => r.beacon.epoch()],
      // seedAt takes an argument; `seed` does not. Confusing them silently reads the
      // CURRENT seed for a draw pinned to a past epoch.
      ['beacon.seedAt', 'ThresholdRandomBeacon', 'seedAt', () => r.beacon.seedAt(3n)],
      ['beacon.lastUpdate', 'ThresholdRandomBeacon', 'lastUpdate', () => r.beacon.lastUpdate()],
      ['beacon.mpk', 'ThresholdRandomBeacon', 'mpk', () => r.beacon.mpk()],
      ['verifierSet.snapshotAt', 'VerifierSetRegistry', 'snapshotAt', () => r.verifierSet.snapshotAt(3n)],
      ['serviceRegistry.getService', 'ServiceRegistry', 'getService', () => r.serviceRegistry.getService(id32)],
      ['serviceRegistry.serviceCount', 'ServiceRegistry', 'serviceCount', () => r.serviceRegistry.serviceCount()],
      ['serviceRegistry.serviceIds', 'ServiceRegistry', 'serviceIds', () => r.serviceRegistry.serviceIds(0n, 10n)],
      ['vault.released', 'TasraVestingVault', 'released', () => r.vault('team').released()],
      ['vault.remaining', 'TasraVestingVault', 'remaining', () => r.vault('team').remaining()],
      ['vault.totalLocked', 'TasraVestingVault', 'totalLocked', () => r.vault('team').totalLocked()],
      ['vault.startTime', 'TasraVestingVault', 'startTime', () => r.vault('team').startTime()],
      ['vault.cliffDuration', 'TasraVestingVault', 'cliffDuration', () => r.vault('team').cliffDuration()],
      ['vault.linearDuration', 'TasraVestingVault', 'linearDuration', () => r.vault('team').linearDuration()],
      ['vault.unlockedAt', 'TasraVestingVault', 'unlockedAt', () => r.vault('team').unlockedAt(1n)],
      ['vault.beneficiary', 'TasraVestingVault', 'beneficiary', () => r.vault('team').beneficiary()],
    ]

    const expectedAddress: Record<string, `0x${string}`> = {
      ...Object.fromEntries(Object.entries(full).map(([name, a]) => [name, a as `0x${string}`])),
      TasraVestingVault: VAULT_TEAM,
    }
    let wired = 0
    const wrong: string[] = []
    for (const [label, contract, fn, run] of cases) {
      requests.length = 0
      try {
        await run()
      } catch (error) {
        wrong.push(`${label} threw: ${error instanceof Error ? error.message.split('\n')[0] : String(error)}`)
        continue
      }
      const call = requests.find(q => q.method === 'eth_call')
      const p = call?.params as [{to: `0x${string}`; data: `0x${string}`}] | undefined
      const to = p?.[0].to.toLowerCase()
      const selector = p?.[0].data.slice(0, 10)
      const wantTo = expectedAddress[contract]
      const wantSelector = selectorOf(contract, fn)
      if (to !== wantTo) wrong.push(`${label}: called ${String(to)}, expected ${contract} at ${String(wantTo)}`)
      else if (selector !== wantSelector) wrong.push(`${label}: selector ${String(selector)} is not ${contract}.${fn} (${wantSelector})`)
      else wired++
    }
    eq(`all ${cases.length} typed readers call the right contract and function`, wrong, [])
    eq('every reader was checked', wired, cases.length)
    genericReads = false
  }

  // ─── readMany batches through Multicall3, and survives its absence ───────────
  //
  // This is the round-trip count the client is actually engineered for: a 10k-operator
  // registry is ~40,000 view calls. Every assertion below counts REQUESTS, because that
  // is the whole point — a version of this that "works" but still issues one call per
  // item passes any value-based test.
  {
    const args = Array.from({length: 5}, (_, i) => [addr(0x30 + i)])

    // Bare chain: nothing at the canonical address. One probe, then one call per item,
    // and the probe is NOT repeated on later calls.
    multicall3Mode = 'absent'
    requests.length = 0
    const bare = createTasraChainClient({rpcUrl, addresses})
    eq('auto mode reports no multicall on a bare chain', await bare.multicallAddress(), null)
    eq('the probe is a single eth_getCode', countOf('eth_getCode'), 1)
    requests.length = 0
    eq('without multicall every item still reads', await bare.readMany<bigint>('TasraToken', 'balanceOf', args), [42n, 42n, 42n, 42n, 42n])
    eq('without multicall it is one eth_call per item', countOf('eth_call'), 5)
    eq('the probe is cached, not repeated per call', countOf('eth_getCode'), 0)
    await bare.readMany('TasraToken', 'balanceOf', args)
    eq('still no further probing on a third call', countOf('eth_getCode'), 0)

    // Multicall3 deployed: the same five reads collapse to ONE aggregate call.
    multicall3Mode = 'deployed'
    requests.length = 0
    const batched = createTasraChainClient({rpcUrl, addresses})
    eq('auto mode finds the canonical deployment', (await batched.multicallAddress())?.toLowerCase(), MULTICALL3_ADDRESS.toLowerCase())
    requests.length = 0
    eq('batched reads return the same values', await batched.readMany<bigint>('TasraToken', 'balanceOf', args), [42n, 42n, 42n, 42n, 42n])
    eq('five items cost ONE eth_call', countOf('eth_call'), 1)
    ok(
      'the call went to Multicall3',
      requests.some(r => JSON.stringify(r.params).toLowerCase().includes(MULTICALL3_ADDRESS.toLowerCase().slice(2))),
    )
    requests.length = 0
    const big = Array.from({length: 40}, (_, i) => [addr(0x100 + i)])
    eq('forty items still cost one call', (await batched.readMany('TasraToken', 'balanceOf', big)).length, 40)
    eq('one aggregate for forty items', countOf('eth_call'), 1)

    // A single item is one call either way, so it must not pay for a probe.
    requests.length = 0
    const single = createTasraChainClient({rpcUrl, addresses})
    await single.readMany('TasraToken', 'balanceOf', [[addr(0x31)]])
    eq('a one-item list skips the probe entirely', countOf('eth_getCode'), 0)
    eq('a one-item list is one direct call', countOf('eth_call'), 1)

    // Opting out must cost nothing at all — not even the probe.
    requests.length = 0
    const off = createTasraChainClient({rpcUrl, addresses, multicall3: false})
    eq('multicall3:false reports no address', await off.multicallAddress(), null)
    eq('multicall3:false never probes', countOf('eth_getCode'), 0)
    await off.readMany('TasraToken', 'balanceOf', args)
    eq('multicall3:false reads one item at a time', countOf('eth_call'), 5)

    // An explicit address is used in place of the canonical one.
    const custom = '0x00000000000000000000000000000000000cafe1' as const
    multicall3At = custom
    multicall3Mode = 'deployed'
    requests.length = 0
    const pinned = createTasraChainClient({rpcUrl, addresses, multicall3: custom})
    eq('an explicit multicall3 address is used', (await pinned.multicallAddress())?.toLowerCase(), custom)
    requests.length = 0
    await pinned.readMany('TasraToken', 'balanceOf', args)
    eq('the explicit address batches too', countOf('eth_call'), 1)
    // ...and a WRONG explicit address degrades instead of breaking every read, which is
    // the reason the address is probed rather than trusted.
    requests.length = 0
    const wrongAddr = createTasraChainClient({
      rpcUrl,
      addresses,
      multicall3: '0x000000000000000000000000000000000000dead',
    })
    eq('a wrong explicit address degrades to no batching', await wrongAddr.multicallAddress(), null)
    eq('and the reads still all succeed', await wrongAddr.readMany<bigint>('TasraToken', 'balanceOf', args), [42n, 42n, 42n, 42n, 42n])
    multicall3At = MULTICALL3_ADDRESS.toLowerCase() as `0x${string}`

    // Something deployed at the address that is not Multicall3: the probe sees code and
    // batches, the aggregate fails, and the client must RECOVER rather than fail the read.
    multicall3Mode = 'wrong-contract'
    requests.length = 0
    const broken = createTasraChainClient({rpcUrl, addresses})
    eq(
      'a broken aggregate falls back and still returns every value',
      await broken.readMany<bigint>('TasraToken', 'balanceOf', args),
      [42n, 42n, 42n, 42n, 42n],
    )
    const afterFirst = countOf('eth_call')
    requests.length = 0
    await broken.readMany('TasraToken', 'balanceOf', args)
    // Latched: having failed once, it must not spend a doomed aggregate on every later call.
    eq('the failed aggregate is not retried on the next call', countOf('eth_call'), 5)
    ok('the first call paid for the failed aggregate exactly once', afterFirst === 6)
    eq('and no further probing happens either', countOf('eth_getCode'), 0)

    // The aggregate REJECTED rather than answering wrongly — an out-of-gas eth_call, or an
    // RPC refusing the payload. A different code path from the one above (viem throws
    // here), and the same requirement: recover, do not fail the read.
    multicall3Mode = 'aggregate-error'
    requests.length = 0
    const rejected = createTasraChainClient({rpcUrl, addresses})
    eq(
      'a rejected aggregate falls back and returns every value',
      await rejected.readMany<bigint>('TasraToken', 'balanceOf', args),
      [42n, 42n, 42n, 42n, 42n],
    )
    requests.length = 0
    await rejected.readMany('TasraToken', 'balanceOf', args)
    eq('a rejected aggregate is not retried either', countOf('eth_call'), 5)

    // An RPC that will not answer `eth_getCode`: the probe must decide "no batching",
    // never "no reads". A probe failure that propagated would take out every registry
    // enumeration on that endpoint.
    multicall3Mode = 'probe-error'
    requests.length = 0
    const unprobeable = createTasraChainClient({rpcUrl, addresses})
    eq('a probe that errors reports no multicall', await unprobeable.multicallAddress(), null)
    eq(
      'a probe that errors still reads every item',
      await unprobeable.readMany<bigint>('TasraToken', 'balanceOf', args),
      [42n, 42n, 42n, 42n, 42n],
    )
    multicall3Mode = 'absent'
  }

  // ─── the payoff: a registry enumeration is now a constant number of requests ──
  {
    // The reason any of this exists. `resolveVerifierDirectory` reads two values PER
    // OPERATOR (hasTag, then nodeOf), so on a bare chain an N-operator registry is
    // 1 + 2N requests — the source cites ~40,000 for 10k operators. Batched it is a small
    // constant, and that is only true if discovery actually goes THROUGH readMany.
    //
    // Counted, not assumed: a refactor that reverted discovery to per-operator reads would
    // still return the right directory and pass every other assertion in this file.
    const operators = Array.from({length: 120}, (_, i) => addr(0x1000 + i))
    callResults['NodeRegistry.activeOperators'] = operators
    callResults['NodeRegistry.hasTag'] = true
    callResults['NodeRegistry.nodeOf'] = [
      addr(0x1000),
      'node.example',
      'http://node.example:8080',
      '/ip4/127.0.0.1/tcp/4001',
      `0x${'ab'.repeat(32)}`,
      0n,
      0n,
      0n,
      true,
    ]

    multicall3Mode = 'absent'
    requests.length = 0
    const unbatchedDir = await resolveVerifierDirectory(createTasraChainClient({rpcUrl, addresses}))
    const unbatchedCalls = countOf('eth_call')
    eq('unbatched: the whole directory still resolves', unbatchedDir.length, operators.length)
    eq('unbatched: one call per operator per read, plus the enumeration', unbatchedCalls, 1 + 2 * operators.length)

    multicall3Mode = 'deployed'
    requests.length = 0
    const batchedDir = await resolveVerifierDirectory(createTasraChainClient({rpcUrl, addresses}))
    const batchedCalls = countOf('eth_call')
    eq('batched: the directory is identical', batchedDir.length, unbatchedDir.length)
    eq(
      'batched: the same directory, operator for operator',
      batchedDir.map(v => [v.index, v.operator]),
      unbatchedDir.map(v => [v.index, v.operator]),
    )
    // 1 enumeration + 1 aggregate for hasTag + 1 aggregate for nodeOf. nodeOf's calldata
    // is small, so 120 items fit one chunk.
    eq('batched: 120 operators cost 3 calls, not 241', batchedCalls, 3)
    ok(
      `batching cut the enumeration from ${unbatchedCalls} requests to ${batchedCalls}`,
      batchedCalls < unbatchedCalls / 50,
    )
    delete callResults['NodeRegistry.activeOperators']
    delete callResults['NodeRegistry.hasTag']
    delete callResults['NodeRegistry.nodeOf']
    multicall3Mode = 'absent'
  }

  // ─── failure semantics survive batching ─────────────────────────────────────
  {
    const args = [addr(0x41), addr(0x42), addr(0x43)].map(a => [a])
    failingArg.add(addr(0x42))

    // Batched: a reverting item comes back as null IN PLACE, exactly as it does unbatched.
    // A batch that failed as a whole here would blank the other two.
    multicall3Mode = 'deployed'
    requests.length = 0
    const batched = createTasraChainClient({rpcUrl, addresses})
    eq(
      'a failing item inside a batch is null in place',
      await batched.readMany<bigint>('TasraToken', 'balanceOf', args),
      [42n, null, 42n],
    )
    eq('and it was still a single call', countOf('eth_call'), 1)

    // ⚠ Strict mode. `index` in an ordered operator set is a position, so a dropped item
    // renumbers every operator after it — a plausible-looking directory that is wrong.
    // It must therefore reject, and say which item and how many there were.
    await rejectsWith(
      'allowFailure:false rejects a failing item and names its index',
      /readMany\(TasraToken\.balanceOf\): item 1 of 3 failed/,
      () => batched.readMany('TasraToken', 'balanceOf', args, {allowFailure: false}),
    )
    await rejectsWith(
      'the strict error explains WHY a null would be wrong',
      /misreport every later index/,
      () => batched.readMany('TasraToken', 'balanceOf', args, {allowFailure: false}),
    )
    // The same contract has to hold on the unbatched path, or the guarantee depends on
    // whether the chain happens to have Multicall3.
    const unbatched = createTasraChainClient({rpcUrl, addresses, multicall3: false})
    await rejectsWith('allowFailure:false rejects unbatched too', /./, () =>
      unbatched.readMany('TasraToken', 'balanceOf', args, {allowFailure: false}),
    )
    eq(
      'allowFailure:false with every item readable returns them all',
      await batched.readMany<bigint>('TasraToken', 'balanceOf', [[addr(0x41)], [addr(0x43)]], {allowFailure: false}),
      [42n, 42n],
    )
    failingArg.delete(addr(0x42))

    // ⚠ The counterpart to the broken-aggregate fallback, and the case it could easily
    // break: when EVERY item legitimately fails, the batch mechanism is innocent. The
    // one-off verification must conclude that and KEEP batching — treating an
    // all-unreadable set as a broken batch would permanently degrade the client to one
    // request per item on the strength of one bad read.
    for (const a of [addr(0x51), addr(0x52), addr(0x53)]) failingArg.add(a)
    const allBad = [addr(0x51), addr(0x52), addr(0x53)].map(a => [a])
    multicall3Mode = 'deployed'
    const stillBatching = createTasraChainClient({rpcUrl, addresses})
    eq(
      'an all-unreadable set comes back as all nulls',
      await stillBatching.readMany('TasraToken', 'balanceOf', allBad),
      [null, null, null],
    )
    requests.length = 0
    eq(
      'a genuinely failing batch does NOT disable batching',
      await stillBatching.readMany('TasraToken', 'balanceOf', allBad),
      [null, null, null],
    )
    eq('the next call is still one aggregate', countOf('eth_call'), 1)
    // And a good read through the same client still batches.
    requests.length = 0
    eq(
      'readable items through the same client still batch',
      await stillBatching.readMany<bigint>('TasraToken', 'balanceOf', [[addr(0x41)], [addr(0x43)]]),
      [42n, 42n],
    )
    eq('one aggregate for the readable pair', countOf('eth_call'), 1)
    for (const a of [addr(0x51), addr(0x52), addr(0x53)]) failingArg.delete(a)
    multicall3Mode = 'absent'
  }
} finally {
  globalThis.fetch = realFetch
}

if (failures.length > 0) {
  console.error(`✗ chain.read-client: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ chain.read-client: ${passed} checks passed`)
