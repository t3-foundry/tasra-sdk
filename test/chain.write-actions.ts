// The write client's on-chain actions, against a stubbed EVM.
//
// test/chain.write-signer.ts already covers the signer shapes and the rule commitment.
// What had no coverage was every action that actually sends a transaction — and the two
// pieces of routing logic around them, both of which are correctness-critical and
// invisible from a return value:
//
//   • WHICH DOOR a write goes through. A relay-configured client must forward the calls
//     whose on-chain authority is `_msgSender()` (slot creation, renew, setVerifierPolicy)
//     and must NOT forward the ones that are not ERC-2771 aware — an ERC-20 `approve`
//     forwarded through a relayer approves the RELAYER's allowance, not the caller's. The
//     source calls this out per action; nothing checked it.
//
//   • the nonce-too-low retry, which is LOCAL-KEY ONLY. A supplied browser wallet must
//     never get it, because a retry re-enters the signing flow and the user sees a second
//     approval prompt for one action — which reads as a double-spend attempt.
//
// Everything is asserted from the SIGNED TRANSACTION: the stub parses each
// `eth_sendRawTransaction` payload, so the checks are on what was actually signed and
// broadcast, not on what the code appears to intend.
//
// Run: tsx test/chain.write-actions.ts — exits non-zero on any failure.

import {
  decodeFunctionData,
  encodeFunctionResult,
  keccak256,
  parseTransaction,
  toFunctionSelector,
  toHex,
  type Abi,
  type Hex,
} from 'viem'
import {privateKeyToAccount} from 'viem/accounts'
import {createTasraWriteClient, generateClientKey} from '../src/chain/write.ts'
import {CONTRACT_ABIS, type ContractName} from '../src/chain/abis/index.ts'
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
const KEY_REGISTRY = addr(0x01)
const SETTLEMENT = addr(0x02)
const TOKEN = addr(0x03)
const CURVE = addr(0x04)
const TREASURY = addr(0x05)
const BEACON = addr(0x06)
const EURC = addr(0x07)
const VAULT_TEAM = addr(0x08)
const FORWARDER = addr(0x0f)

const addresses: AddressBook = {
  KeyRegistry: KEY_REGISTRY,
  Settlement: SETTLEMENT,
  TasraToken: TOKEN,
  BondingCurve: CURVE,
  Treasury: TREASURY,
  ThresholdRandomBeacon: BEACON,
  MockEurc: EURC,
  TasraVestingVault_team: VAULT_TEAM,
}
const abiAt = new Map<string, ContractName>([
  [KEY_REGISTRY, 'KeyRegistry'],
  [SETTLEMENT, 'Settlement'],
  [TOKEN, 'TasraToken'],
  [CURVE, 'BondingCurve'],
  [TREASURY, 'Treasury'],
  [BEACON, 'ThresholdRandomBeacon'],
  [EURC, 'MockEurc'],
  [VAULT_TEAM, 'TasraVestingVault'],
])

const privateKey = `0x${'11'.repeat(32)}` as Hex
const account = privateKeyToAccount(privateKey)
const slotId = `0x${'cd'.repeat(32)}` as Hex
const rpcUrl = 'http://127.0.0.1:1/'

/**
 * The selector of `contract.functionName`, from the vendored ABI.
 *
 * The ABI ITEM is handed to viem rather than a signature string built from
 * `inputs.map(i => i.type)`: a struct parameter's type is the literal `"tuple"`, so
 * building the string by hand produces `…(…,tuple)` and the wrong selector.
 */
function selectorOf(contract: ContractName, functionName: string): string {
  const abi = CONTRACT_ABIS[contract] as Abi
  const item = abi.find(i => i.type === 'function' && i.name === functionName)
  if (!item) throw new Error(`no function ${functionName} on ${contract}`)
  return toFunctionSelector(item as Parameters<typeof toFunctionSelector>[0])
}

// ─── the EVM stub ─────────────────────────────────────────────────────────────
interface SentTx {
  to: string
  data: Hex
  value: bigint
  nonce: number
}
const txs: SentTx[] = []
const calls: Array<{to: string; data: Hex}> = []
let nonce = 0
/** Reverts to serve for eth_sendRawTransaction, consumed in order. */
let sendErrors: string[] = []
/**
 * Fail the next N sends whose calldata starts with this selector, so one step of a
 * multi-transaction flow can be failed without disturbing the others.
 */
const selectorFailures = new Map<string, number>()
/** Receipt status for everything mined. */
let receiptStatus: 'success' | 'reverted' = 'success'
/** Canned eth_call results keyed `contract.functionName`. */
const callResults: Record<string, unknown> = {
  'KeyRegistry.MIN_RULE_TIMELOCK': 3600n,
  'KeyRegistry.randomBeacon': BEACON,
  'KeyRegistry.computeCommitment': `0x${'ab'.repeat(32)}`,
  'ThresholdRandomBeacon.epoch': 5n,
  'TasraToken.balanceOf': 1000n,
  'MockEurc.balanceOf': 500n,
  'BondingCurve.spotPrice': 42n,
  'BondingCurve.priceAt': 43n,
  'Settlement.balanceOf': 7n,
}
const chainIdAnswer = 1337

const realFetch = globalThis.fetch

function rpc(method: string, params: unknown[]): unknown {
  switch (method) {
    case 'eth_chainId':
      return `0x${chainIdAnswer.toString(16)}`
    case 'eth_blockNumber':
      return '0x10'
    case 'eth_getTransactionCount':
      return `0x${nonce.toString(16)}`
    case 'eth_gasPrice':
      return '0x3b9aca00'
    case 'eth_maxPriorityFeePerGas':
      return '0x3b9aca00'
    case 'eth_estimateGas':
      return '0x5208'
    case 'eth_getBalance':
      return '0xde0b6b3a7640000'
    case 'eth_feeHistory':
      return {oldestBlock: '0x1', baseFeePerGas: ['0x1', '0x1'], gasUsedRatio: [0.5], reward: [['0x1']]}
    case 'eth_getBlockByNumber':
      return {number: '0x10', timestamp: '0x65000000', baseFeePerGas: '0x1', hash: `0x${'aa'.repeat(32)}`}
    case 'eth_sendRawTransaction': {
      const failure = sendErrors.shift()
      if (failure) throw new Error(failure)
      const parsed = parseTransaction(String(params[0]) as Hex)
      const sel = (parsed.data ?? '0x').slice(0, 10)
      const remaining = selectorFailures.get(sel) ?? 0
      if (remaining > 0) {
        selectorFailures.set(sel, remaining - 1)
        throw new Error(`execution reverted: EpochNotReached()`)
      }
      const tx = parseTransaction(String(params[0]) as Hex)
      txs.push({
        to: String(tx.to ?? '').toLowerCase(),
        data: (tx.data ?? '0x') as Hex,
        value: tx.value ?? 0n,
        nonce: tx.nonce ?? 0,
      })
      nonce++
      return keccak256(String(params[0]) as Hex)
    }
    case 'eth_getTransactionReceipt':
      return {
        transactionHash: String(params[0]),
        blockNumber: '0x11',
        blockHash: `0x${'bb'.repeat(32)}`,
        status: receiptStatus === 'success' ? '0x1' : '0x0',
        gasUsed: '0x5208',
        cumulativeGasUsed: '0x5208',
        logs: [],
        type: '0x2',
        from: account.address,
        to: addr(0x99),
        contractAddress: null,
        transactionIndex: '0x0',
        effectiveGasPrice: '0x3b9aca00',
      }
    case 'eth_call': {
      const {to, data} = params[0] as {to: `0x${string}`; data: Hex}
      calls.push({to: to.toLowerCase(), data})
      const contract = abiAt.get(to.toLowerCase() as `0x${string}`)
      if (!contract) throw new Error(`stub: no ABI at ${to}`)
      const abi = CONTRACT_ABIS[contract] as Abi
      const {functionName} = decodeFunctionData({abi, data})
      const key = `${contract}.${functionName}`
      if (!(key in callResults)) throw new Error(`stub: no canned result for ${key}`)
      return encodeFunctionResult({abi, functionName, result: callResults[key] as never})
    }
    default:
      throw new Error(`stub: unhandled ${method}`)
  }
}

globalThis.fetch = (async (_url: string, init?: RequestInit) => {
  const body = JSON.parse(String(init?.body)) as {id: number; method: string; params?: unknown[]}
  let payload: unknown
  try {
    payload = {jsonrpc: '2.0', id: body.id, result: rpc(body.method, body.params ?? [])}
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

const reset = (): void => {
  txs.length = 0
  calls.length = 0
  sendErrors = []
  selectorFailures.clear()
  receiptStatus = 'success'
}
const lastTx = (): SentTx => {
  const t = txs[txs.length - 1]
  if (!t) throw new Error('no transaction was sent')
  return t
}

try {
  // ─── generateClientKey ──────────────────────────────────────────────────────
  {
    const k1 = generateClientKey()
    const k2 = generateClientKey()
    ok('generateClientKey: 0x-prefixed 32 bytes', /^0x[0-9a-f]{64}$/.test(k1))
    ok('generateClientKey: fresh each call', k1 !== k2)
    ok('generateClientKey: usable as an account key', privateKeyToAccount(k1).address.startsWith('0x'))
  }

  const client = createTasraWriteClient({rpcUrl, addresses, privateKey, chainId: 1337})
  eq('the client exposes the signing address', client.address, account.address)
  eq('relayEnabled is false without a relay', client.relayEnabled, false)

  // ─── every action hits the right contract and function ──────────────────────
  {
    // ~20 near-identical one-line wrappers, each naming a contract and a function as
    // strings. Same bug class as the read client's typed readers: a copy-pasted address or
    // function name compiles, type-checks, and is only wrong once it reverts on chain.
    // Asserted from the SIGNED tx, so this is what the network would actually receive.
    interface Case {
      label: string
      contract: ContractName
      fn: string
      to: `0x${string}`
      run: () => Promise<unknown>
      args?: readonly unknown[]
    }
    const cases: Case[] = [
      {label: 'rotateKey', contract: 'KeyRegistry', fn: 'rotateKey', to: KEY_REGISTRY,
        run: () => client.rotateKey(slotId, 'because'), args: [slotId, 'because']},
      {label: 'reshareKey', contract: 'KeyRegistry', fn: 'reshareKey', to: KEY_REGISTRY,
        run: () => client.reshareKey(slotId, [addr(0x21), addr(0x22)], 2, 3, 'grow'),
        args: [slotId, [addr(0x21), addr(0x22)], 2, 3, 'grow']},
      {label: 'cancelSlot', contract: 'KeyRegistry', fn: 'cancelSlot', to: KEY_REGISTRY,
        run: () => client.cancelSlot(slotId), args: [slotId]},
      {label: 'renewSlot', contract: 'KeyRegistry', fn: 'renew', to: KEY_REGISTRY,
        run: () => client.renewSlot(slotId), args: [slotId]},
      {label: 'setVerifierPolicy', contract: 'KeyRegistry', fn: 'setVerifierPolicy', to: KEY_REGISTRY,
        run: () => client.setVerifierPolicy(slotId, 5, 3), args: [slotId, 5, 3]},
      {label: 'transferTsra', contract: 'TasraToken', fn: 'transfer', to: TOKEN,
        run: () => client.transferTsra(addr(0x31), 25n), args: [addr(0x31), 25n]},
      {label: 'burnTsra', contract: 'TasraToken', fn: 'burn', to: TOKEN,
        run: () => client.burnTsra(9n), args: [9n]},
      {label: 'buyTsra', contract: 'BondingCurve', fn: 'buy', to: CURVE,
        run: () => client.buyTsra(100n, 90n), args: [100n, 90n]},
      {label: 'approveEurcForCurve', contract: 'MockEurc', fn: 'approve', to: EURC,
        run: () => client.approveEurcForCurve(50n), args: [CURVE, 50n]},
      {label: 'mintMockEurc', contract: 'MockEurc', fn: 'mint', to: EURC,
        run: () => client.mintMockEurc(addr(0x32), 77n), args: [addr(0x32), 77n]},
      {label: 'treasuryWithdraw', contract: 'Treasury', fn: 'withdraw', to: TREASURY,
        run: () => client.treasuryWithdraw(addr(0x33), 5n), args: [addr(0x33), 5n]},
      {label: 'treasuryRefund', contract: 'Treasury', fn: 'refund', to: TREASURY,
        run: () => client.treasuryRefund(addr(0x34), 6n), args: [addr(0x34), 6n]},
      {label: 'vaultRelease', contract: 'TasraVestingVault', fn: 'release', to: VAULT_TEAM,
        run: () => client.vaultRelease('team'), args: []},
      {label: 'setRulePolicy', contract: 'KeyRegistry', fn: 'setRulePolicy', to: KEY_REGISTRY,
        run: () => client.setRulePolicy(slotId, {admin: addr(0x41), guardian: addr(0x42), timelockSecs: 60}),
        args: [slotId, addr(0x41), addr(0x42), 60]},
    ]

    const wrong: string[] = []
    let checked = 0
    for (const c of cases) {
      reset()
      try {
        await c.run()
      } catch (error) {
        wrong.push(`${c.label} threw: ${error instanceof Error ? error.message.split('\n')[0] : String(error)}`)
        continue
      }
      const tx = lastTx()
      const want = selectorOf(c.contract, c.fn)
      if (tx.to !== c.to.toLowerCase()) {
        wrong.push(`${c.label}: sent to ${tx.to}, expected ${c.contract} at ${c.to}`)
        continue
      }
      if (tx.data.slice(0, 10) !== want) {
        wrong.push(`${c.label}: selector ${tx.data.slice(0, 10)} is not ${c.contract}.${c.fn} (${want})`)
        continue
      }
      if (c.args) {
        const decoded = decodeFunctionData({abi: CONTRACT_ABIS[c.contract] as Abi, data: tx.data})
        const got = JSON.stringify(decoded.args ?? [], (_k, v) => (typeof v === 'bigint' ? String(v) : v)).toLowerCase()
        const exp = JSON.stringify(c.args, (_k, v) => (typeof v === 'bigint' ? String(v) : v)).toLowerCase()
        if (got !== exp) {
          wrong.push(`${c.label}: args ${got} !== ${exp}`)
          continue
        }
      }
      checked++
    }
    eq(`all ${cases.length} write actions target the right contract, function and args`, wrong, [])
    eq('every action was checked', checked, cases.length)
  }

  // ─── multi-transaction actions ──────────────────────────────────────────────
  {
    // fundSlot is approve-then-fund, in that order. Reversed, the fund reverts for
    // insufficient allowance.
    reset()
    const r = await client.fundSlot(slotId, 500n)
    eq('fundSlot sends exactly two transactions', txs.length, 2)
    eq('fundSlot approves first, on the token', [txs[0]?.to, txs[0]?.data.slice(0, 10)], [TOKEN.toLowerCase(), selectorOf('TasraToken', 'approve')])
    eq('fundSlot then funds, on Settlement', [txs[1]?.to, txs[1]?.data.slice(0, 10)], [SETTLEMENT.toLowerCase(), selectorOf('Settlement', 'fund')])
    const approveArgs = decodeFunctionData({abi: CONTRACT_ABIS.TasraToken as Abi, data: txs[0]!.data}).args
    eq('the approval is for Settlement, for the funded amount', [String(approveArgs?.[0]).toLowerCase(), approveArgs?.[1]], [SETTLEMENT.toLowerCase(), 500n])
    ok('fundSlot returns both hashes', !!r.approveTx && !!r.fundTx && r.approveTx !== r.fundTx)
  }
  {
    reset()
    const r = await client.redeemTsra(200n, 10n)
    eq('redeemTsra sends two transactions', txs.length, 2)
    eq('redeemTsra approves TSRA to the curve first', [txs[0]?.to, txs[0]?.data.slice(0, 10)], [TOKEN.toLowerCase(), selectorOf('TasraToken', 'approve')])
    eq('redeemTsra then redeems on the curve', [txs[1]?.to, txs[1]?.data.slice(0, 10)], [CURVE.toLowerCase(), selectorOf('BondingCurve', 'redeem')])
    const redeemArgs = decodeFunctionData({abi: CONTRACT_ABIS.BondingCurve as Abi, data: txs[1]!.data}).args
    // minEurcOut is the slippage floor; it must reach the contract, not be dropped.
    eq('the slippage floor is forwarded', redeemArgs, [200n, 10n])
    ok('redeemTsra returns both hashes', !!r.approveTx && !!r.redeemTx)
    reset()
    const dflt = await client.redeemTsra(200n)
    void dflt
    eq('redeemTsra defaults the floor to 0 (accept any fill)', decodeFunctionData({abi: CONTRACT_ABIS.BondingCurve as Abi, data: txs[1]!.data}).args, [200n, 0n])
  }
  {
    // sendEth is a plain value transfer: no calldata, and the value must be exact.
    reset()
    await client.sendEth(addr(0x51), 12345n)
    eq('sendEth sends value with no calldata', [lastTx().to, lastTx().data, lastTx().value], [addr(0x51).toLowerCase(), '0x', 12345n])
  }

  // ─── reads through the write client ─────────────────────────────────────────
  {
    eq('tsraBalance defaults to the signing account', await client.tsraBalance(), 1000n)
    eq('eurcBalance reads MockEurc', await client.eurcBalance(addr(0x52)), 500n)
    eq('spotPrice reads the curve', await client.spotPrice(), 42n)
    eq('priceAt reads the curve', await client.priceAt(10n), 43n)
    eq('settlementBalance reads Settlement', await client.settlementBalance(slotId), 7n)
    ok('ethBalance reads a balance', (await client.ethBalance()) > 0n)
  }

  // ─── a reverted receipt must not be reported as success ─────────────────────
  {
    reset()
    receiptStatus = 'reverted'
    await rejectsWith(
      'a reverted tx is an error naming the call and the hash',
      /rotateKey REVERTED on chain \(tx 0x[0-9a-f]{64}\).*did not take effect/,
      () => client.rotateKey(slotId),
    )
    receiptStatus = 'success'
  }

  // ─── rule-policy preconditions, checked before signing ──────────────────────
  {
    // Both are contract preconditions. Failing here costs nothing; discovering them as a
    // revert costs the slot its amendability forever on this path.
    reset()
    await rejectsWith(
      'a guardian equal to the admin is refused (it collapses propose, veto and endorse)',
      /guardian must differ from admin/,
      () => client.setRulePolicy(slotId, {admin: addr(0x41), guardian: addr(0x41), timelockSecs: 7200}),
    )
    eq('and nothing was signed', txs.length, 0)
    // Case-insensitively, too — the same address in different case is the same authority.
    reset()
    await rejectsWith(
      'the admin/guardian comparison is case-insensitive',
      /guardian must differ from admin/,
      () => client.setRulePolicy(slotId, {admin: addr(0x41).toUpperCase().replace('0X', '0x') as `0x${string}`, guardian: addr(0x41), timelockSecs: 7200}),
    )

    // ⚠ With no guardian the timelock is the ONLY thing between a proposal and activation,
    // so the floor is read FROM THE CONTRACT rather than hardcoded. The stub serves 3600,
    // and the error has to quote that value — proving it was read, not assumed.
    reset()
    await rejectsWith(
      'a guardian-less policy below MIN_RULE_TIMELOCK is refused, quoting the contract value',
      /needs a timelock of at least 3600s \(MIN_RULE_TIMELOCK\), got 60s/,
      () => client.setRulePolicy(slotId, {admin: addr(0x41), timelockSecs: 60}),
    )
    ok(
      'the floor came from an on-chain read of MIN_RULE_TIMELOCK',
      calls.some(c => c.to === KEY_REGISTRY.toLowerCase() && c.data.slice(0, 10) === selectorOf('KeyRegistry', 'MIN_RULE_TIMELOCK')),
    )
    eq('and nothing was signed', txs.length, 0)
    // The same policy AT the floor is accepted.
    reset()
    await client.setRulePolicy(slotId, {admin: addr(0x41), timelockSecs: 3600})
    eq('a guardian-less policy exactly at the floor is accepted', txs.length, 1)
    // A different floor must change the verdict — pinning that the number is not baked in.
    callResults['KeyRegistry.MIN_RULE_TIMELOCK'] = 7200n
    reset()
    await rejectsWith(
      'raising the contract floor changes what the client accepts',
      /at least 7200s/,
      () => client.setRulePolicy(slotId, {admin: addr(0x41), timelockSecs: 3600}),
    )
    callResults['KeyRegistry.MIN_RULE_TIMELOCK'] = 3600n
  }

  // ─── createSlot: entry-point selection ──────────────────────────────────────
  {
    const rule = '{"credentials":[{"id":"a","format":"jwt_vc_json","claims":[{"path":["iss"]}]}]}'
    reset()
    const plain = await client.createSlot({dcqlRule: rule, k: 2, n: 3, mode: 'frost'})
    eq('createSlot uses the plain filtered entry point', lastTx().data.slice(0, 10), selectorOf('KeyRegistry', 'createKeySlotFiltered'))
    // ⚠ ruleSalt exists NOWHERE else: without it the rule can never be provisioned to a
    // keeper, so it has to come back from the call that generated it.
    ok('createSlot returns the rule salt', /^0x[0-9a-f]{64}$/.test(plain.ruleSalt))
    ok('createSlot returns a slot id', /^0x[0-9a-f]{64}$/.test(plain.slotId))
    eq('no relay receipt without a relay', plain.relay, undefined)

    reset()
    const withPolicy = await client.createSlot({
      dcqlRule: rule, k: 2, n: 3, mode: 'frost',
      rulePolicy: {admin: addr(0x41), guardian: addr(0x42), timelockSecs: 60},
    })
    // A policy uses a DIFFERENT entry point, so the common path keeps its long-standing
    // call shape.
    eq('a rule policy switches to the WithPolicy entry point', lastTx().data.slice(0, 10), selectorOf('KeyRegistry', 'createKeySlotFilteredWithPolicy'))
    ok('the policy path still returns a salt', !!withPolicy.ruleSalt)

    reset()
    await client.createSlot({dcqlRule: rule, k: 2, n: 3, mode: 'frost', exportable: true})
    eq('exportable uses the Exportable entry point', lastTx().data.slice(0, 10), selectorOf('KeyRegistry', 'createKeySlotFilteredExportable'))

    // No single entry point does both, so the combination is refused locally rather than
    // silently dropping one of them.
    reset()
    await rejectsWith(
      'exportable + rulePolicy is refused, naming both options',
      /`exportable` and `rulePolicy` cannot be combined/,
      () => client.createSlot({dcqlRule: rule, k: 2, n: 3, mode: 'frost', exportable: true, rulePolicy: {admin: addr(0x41), guardian: addr(0x42), timelockSecs: 60}}),
    )
    eq('and nothing was signed for the impossible combination', txs.length, 0)

    // Supplied ids are used verbatim — a caller that pre-derived a slot id needs it kept.
    reset()
    const pinned = await client.createSlot({
      dcqlRule: rule, k: 2, n: 3, mode: 'frost',
      slotId, salt: `0x${'11'.repeat(32)}`, ruleSalt: `0x${'22'.repeat(32)}`,
    })
    eq('a supplied slot id and rule salt are returned unchanged', [pinned.slotId, pinned.ruleSalt], [slotId, `0x${'22'.repeat(32)}`])
    const args = decodeFunctionData({abi: CONTRACT_ABIS.KeyRegistry as Abi, data: lastTx().data}).args
    eq('the supplied slot id is the first argument', args?.[0], slotId)
    // The default tag is keccak256("keykeeper") — a wire value, not a label.
    eq('tags default to keccak256("keykeeper")', args?.[7], [keccak256(toHex('keykeeper'))])
    reset()
    await client.createSlot({dcqlRule: rule, k: 2, n: 3, mode: 'frost', tags: ['verifier']})
    eq('supplied tags are hashed', decodeFunctionData({abi: CONTRACT_ABIS.KeyRegistry as Abi, data: lastTx().data}).args?.[7], [keccak256(toHex('verifier'))])
  }
  {
    // A one-shot creation against a registry that requires commit-reveal reverts
    // CommitRevealRequired(). The remedy is a DIFFERENT CALL, not a different argument, so
    // the raw revert is useless on its own and must be renamed.
    reset()
    sendErrors = ['execution reverted: CommitRevealRequired()']
    await rejectsWith(
      'CommitRevealRequired is rewritten to name createSlotCommitReveal',
      /requires commit-reveal creation.*use createSlotCommitReveal\(\)/s,
      () => client.createSlot({dcqlRule: 'any', k: 2, n: 3, mode: 'frost'}),
    )
    reset()
    // Any OTHER revert must pass through unchanged rather than being mislabelled.
    sendErrors = ['execution reverted: SomethingElse()']
    await rejectsWith(
      'an unrelated revert is not rewritten',
      /SomethingElse/,
      () => client.createSlot({dcqlRule: 'any', k: 2, n: 3, mode: 'frost'}),
    )
    reset()
  }

  // ─── WHICH DOOR: relayed vs signed by the local key ─────────────────────────
  {
    // The routing is per-action and correctness-critical in both directions:
    //
    //   • a call whose on-chain authority is `_msgSender()` MUST be forwarded, or it is
    //     signed by the local key, which is not the creator when the slot was created
    //     under a forwarded identity — the source says exactly this about `renew`.
    //   • an ERC-20 `approve` must NOT be forwarded: approve is not ERC-2771 aware, so a
    //     forwarded approve sets the RELAYER's allowance and the follow-up spend reverts.
    //
    // Tested by configuring a relay that refuses deterministically, then classifying each
    // action by whether it tried. The approvals name a different chain id than the client,
    // so `submit` fails at its first check — before any transport, signing or discovery.
    // That makes "did this call go through the relay?" a clean yes/no.
    const relayClient = createTasraWriteClient({
      rpcUrl,
      addresses,
      privateKey,
      chainId: 1337,
      relay: {
        forwarder: FORWARDER,
        approvals: [{
          chainId: 999, // ≠ 1337, so every relayed submit refuses immediately
          registry: addr(0x0e),
          serviceId: `0x${'01'.repeat(32)}`,
          serviceType: 0,
          owner: addr(0x0d),
          revision: 1n,
          manifestHash: `0x${'02'.repeat(32)}`,
        }],
        transport: {
          request: () => Promise.reject(new Error('transport must not be reached')),
          relayRequest: () => Promise.reject(new Error('transport must not be reached')),
        },
      },
    })
    eq('relayEnabled is true with a relay configured', relayClient.relayEnabled, true)

    const rule = 'any'
    /** [label, call, must it be relayed?] */
    const routes: Array<[string, () => Promise<unknown>, boolean]> = [
      // Forwarded: creator/`_msgSender()`-gated writes.
      ['createSlot', () => relayClient.createSlot({dcqlRule: rule, k: 2, n: 3, mode: 'frost'}), true],
      ['renewSlot', () => relayClient.renewSlot(slotId), true],
      ['setVerifierPolicy', () => relayClient.setVerifierPolicy(slotId, 5, 3), true],
      ['buyTsra', () => relayClient.buyTsra(100n, 90n), true],
      // Local key: not ERC-2771 aware, or deliberately owner-gated on the local account.
      ['rotateKey', () => relayClient.rotateKey(slotId), false],
      ['cancelSlot', () => relayClient.cancelSlot(slotId), false],
      ['reshareKey', () => relayClient.reshareKey(slotId, [addr(0x21)], 1, 1, ''), false],
      ['transferTsra', () => relayClient.transferTsra(addr(0x31), 1n), false],
      ['burnTsra', () => relayClient.burnTsra(1n), false],
      ['approveEurcForCurve', () => relayClient.approveEurcForCurve(1n), false],
      ['mintMockEurc', () => relayClient.mintMockEurc(addr(0x32), 1n), false],
      ['treasuryWithdraw', () => relayClient.treasuryWithdraw(addr(0x33), 1n), false],
      ['treasuryRefund', () => relayClient.treasuryRefund(addr(0x34), 1n), false],
      ['vaultRelease', () => relayClient.vaultRelease('team'), false],
      ['setRulePolicy', () => relayClient.setRulePolicy(slotId, {admin: addr(0x41), guardian: addr(0x42), timelockSecs: 60}), false],
      ['redeemTsra', () => relayClient.redeemTsra(1n), false],
    ]

    const misrouted: string[] = []
    for (const [label, run, shouldRelay] of routes) {
      reset()
      let relayed = false
      let failure = ''
      try {
        await run()
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        relayed = /Relay chain mismatch/.test(message)
        failure = message.split('\n')[0] ?? ''
      }
      if (relayed !== shouldRelay) {
        misrouted.push(
          shouldRelay
            ? `${label}: signed with the LOCAL key, expected it to be forwarded${failure ? ` (${failure})` : ''}`
            : `${label}: was FORWARDED, expected the local key`,
        )
      }
    }
    eq('every action goes through the door its authority requires', misrouted, [])

    // Spelled out for the two that carry a named reason in the source, so a future change
    // to either one fails with a message that says what it broke.
    reset()
    await rejectsWith(
      'renew is forwarded — the creator may be a forwarded identity, not the local key',
      /Relay chain mismatch/,
      () => relayClient.renewSlot(slotId),
    )
    reset()
    await relayClient.approveEurcForCurve(5n)
    eq(
      'approve is NOT forwarded — approve is not ERC-2771 aware, so a relayed one would set the relayer\'s allowance',
      [lastTx().to, lastTx().data.slice(0, 10)],
      [EURC.toLowerCase(), selectorOf('MockEurc', 'approve')],
    )
    // fundSlot is mixed on purpose: the approve is local, the fund is forwarded.
    reset()
    let fundFailed = ''
    await relayClient.fundSlot(slotId, 10n).catch((e: unknown) => {
      fundFailed = e instanceof Error ? e.message : String(e)
    })
    ok('fundSlot signs its approve locally', txs.length === 1 && txs[0]?.to === TOKEN.toLowerCase())
    ok('fundSlot forwards the fund itself', /Relay chain mismatch/.test(fundFailed))
    reset()
  }

  // ─── the nonce-too-low retry (local key only) ───────────────────────────────
  {
    // A dev RPC under load can transiently return a stale nonce, and the node then
    // rejects the tx BEFORE it enters the mempool — safe to retry, no double-submit risk.
    reset()
    sendErrors = ['nonce too low', 'nonce too low']
    await client.rotateKey(slotId)
    eq('a transient nonce-too-low is retried until it lands', txs.length, 1)
    eq('the retries consumed both injected failures', sendErrors.length, 0)

    // The alternative wording a different client emits must also be recognised.
    reset()
    sendErrors = ['the nonce provided for the transaction is lower than the current nonce']
    await client.rotateKey(slotId)
    eq('the other nonce-too-low wording is recognised too', txs.length, 1)

    // ⚠ ONLY nonce errors retry. Anything else must surface immediately — retrying an
    // insufficient-funds or revert error just delays the report.
    reset()
    sendErrors = ['insufficient funds for gas', 'insufficient funds for gas']
    await rejectsWith('a non-nonce error is NOT retried', /insufficient funds/, () => client.rotateKey(slotId))
    eq('one unrelated failure is reported without a retry', sendErrors.length, 1)

    // Bounded: a permanently stale nonce eventually gives up rather than looping.
    reset()
    sendErrors = Array.from({length: 12}, () => 'nonce too low')
    await rejectsWith('a persistent nonce-too-low eventually gives up', /nonce too low/, () => client.rotateKey(slotId))
    ok('the retry budget is bounded (fewer than 12 attempts)', sendErrors.length > 0)
    reset()

    // ⚠ The other half of the rule, and the reason it exists: a SUPPLIED wallet must NOT
    // get the retry. A retry re-enters the signing flow, so the user would see a second
    // approval prompt for one action — which reads as a double-spend attempt. The existing
    // signer suite checks the client is not monkey-patched; this checks the BEHAVIOUR,
    // because "not patched" and "does not retry" are different claims.
    const {createWalletClient, defineChain, http} = await import('viem')
    const chainDef = defineChain({
      id: 1337,
      name: 'stub',
      nativeCurrency: {name: 'Ether', symbol: 'ETH', decimals: 18},
      rpcUrls: {default: {http: [rpcUrl]}},
    })
    const supplied = createWalletClient({account, chain: chainDef, transport: http(rpcUrl)})
    const byoClient = createTasraWriteClient({rpcUrl, addresses, wallet: supplied, chainId: 1337})
    reset()
    sendErrors = ['nonce too low', 'nonce too low']
    await rejectsWith(
      'a supplied wallet does NOT retry a nonce-too-low — no second signature prompt',
      /nonce too low/,
      () => byoClient.rotateKey(slotId),
    )
    eq('exactly one attempt was made on the supplied wallet', sendErrors.length, 1)
    reset()
  }

  // ─── commit-reveal creation ─────────────────────────────────────────────────
  {
    // The production default, and grinding-resistant BECAUSE of the wait: the committee
    // draw must use a beacon seed that did not exist when the parameters were committed.
    // So the ordering is the property — commit, then wait for the beacon to pass the
    // pinned target epoch, then reveal.
    reset()
    const epochs: Array<[number, number]> = []
    // The beacon starts below the commit's target and advances once, so the wait is real
    // rather than skipped.
    callResults['ThresholdRandomBeacon.epoch'] = 5n
    callResults['KeyRegistry.slotCommits'] = [6n, 20n, account.address, false]
    let polls = 0
    const advanceOnSecondPoll = {
      get value() {
        polls++
        return polls >= 2 ? 6n : 5n
      },
    }
    Object.defineProperty(callResults, 'ThresholdRandomBeacon.epoch', {
      get: () => advanceOnSecondPoll.value,
      configurable: true,
    })

    const res = await client.createSlotCommitReveal({
      dcqlRule: 'any',
      k: 2,
      n: 3,
      mode: 'frost',
      slotId,
      maxWaitMs: 60_000,
      onEpoch: (cur, target) => epochs.push([cur, target]),
    })
    eq('commit-reveal returns the pinned target epoch', res.targetEpoch, 6)
    ok('commit and reveal are distinct transactions', res.commitTx !== res.revealTx)
    ok('a rule salt comes back from the commit-reveal path too', /^0x[0-9a-f]{64}$/.test(res.ruleSalt))
    // ⚠ The ordering IS the grinding resistance: commit first, reveal only after.
    const commitSel = selectorOf('KeyRegistry', 'commitKeySlot')
    const revealSel = selectorOf('KeyRegistry', 'revealKeySlot')
    const order = txs.map(t => t.data.slice(0, 10)).filter(s => s === commitSel || s === revealSel)
    eq('the commit is sent before the reveal', order, [commitSel, revealSel])
    ok('the wait actually polled the beacon below the target', epochs.some(([cur, target]) => cur < target))
    ok('onEpoch reported the target it was waiting for', epochs.every(([, target]) => target === 6))
    // The target epoch is READ from the contract, not computed client-side (computing it
    // races the beacon), so a different pinned value must change the wait.
    ok(
      'the target epoch came from an on-chain slotCommits read',
      calls.some(c => c.data.slice(0, 10) === selectorOf('KeyRegistry', 'slotCommits')),
    )

    // A raw-export slot has no commit-reveal entry point, so it is refused up front.
    reset()
    await rejectsWith(
      'commit-reveal refuses an exportable slot',
      /does not support raw-export slots/,
      () => client.createSlotCommitReveal({dcqlRule: 'any', k: 2, n: 3, mode: 'frost', exportable: true}),
    )
    await rejectsWith(
      'commit-reveal validates its wait bound',
      /Invalid commit-reveal wait/,
      () => client.createSlotCommitReveal({dcqlRule: 'any', k: 2, n: 3, mode: 'frost', maxWaitMs: 0}),
    )
    eq('neither refusal signed anything', txs.length, 0)

    // ─── the chain-time nudge ───────────────────────────────────────────────
    // The beacon is anchored to CHAIN time, and on a mint-on-demand chain (the local dev
    // chain) `block.timestamp` only moves when a transaction mints a block. An idle chain
    // therefore FREEZES the beacon, and without this nudge every commit-reveal on a local
    // fleet would sit out its full deadline and fail. The nudge is a zero-value
    // self-transfer, sent only when the epoch has not moved since the last poll AND the
    // head is stale — so on a live chain it never fires.
    reset()
    let stalledPolls = 0
    Object.defineProperty(callResults, 'ThresholdRandomBeacon.epoch', {
      get: () => {
        stalledPolls++
        // Stay put long enough for two consecutive polls to see the same epoch, which is
        // the condition the nudge is gated on.
        return stalledPolls >= 3 ? 6n : 5n
      },
      configurable: true,
    })
    callResults['KeyRegistry.slotCommits'] = [6n, 20n, account.address, false]
    const nudged = await client.createSlotCommitReveal({
      dcqlRule: 'any', k: 2, n: 3, mode: 'frost', slotId, maxWaitMs: 60_000,
    })
    const selfTransfers = txs.filter(t => t.to === account.address.toLowerCase() && t.data === '0x' && t.value === 0n)
    eq('a stalled beacon is nudged with a zero-value self-transfer', selfTransfers.length, 1)
    ok('and the reveal still lands afterwards', !!nudged.revealTx)

    // ─── the reveal retries across the epoch boundary ───────────────────────
    // EpochNotReached / BeaconSeedUnavailable can fire transiently right at the boundary,
    // until the seed for the target epoch has landed. That is a wait, not a failure, so
    // the reveal retries rather than discarding a paid-for commit.
    reset()
    stalledPolls = 3 // beacon already at the target
    selectorFailures.set(selectorOf('KeyRegistry', 'revealKeySlot'), 1)
    const retried = await client.createSlotCommitReveal({
      dcqlRule: 'any', k: 2, n: 3, mode: 'frost', slotId, maxWaitMs: 60_000,
    })
    ok('a transient reveal revert is retried, not surfaced', !!retried.revealTx)
    eq('the injected reveal failure was consumed', selectorFailures.get(selectorOf('KeyRegistry', 'revealKeySlot')), 0)

    // A deployment with no beacon is a configuration error with an actionable name, found
    // before anything is signed.
    reset()
    const noBeacon = createTasraWriteClient({
      rpcUrl,
      addresses: {KeyRegistry: KEY_REGISTRY, Settlement: SETTLEMENT, TasraToken: TOKEN},
      privateKey,
      chainId: 1337,
    })
    callResults['KeyRegistry.randomBeacon'] = '0x0000000000000000000000000000000000000000'
    await rejectsWith(
      'a registry with no random beacon is named as such',
      /KeyRegistry has no random beacon/,
      () => noBeacon.createSlotCommitReveal({dcqlRule: 'any', k: 2, n: 3, mode: 'frost'}),
    )
    eq('and nothing was signed', txs.length, 0)
    callResults['KeyRegistry.randomBeacon'] = BEACON

    delete (callResults as Record<string, unknown>)['KeyRegistry.slotCommits']
    Object.defineProperty(callResults, 'ThresholdRandomBeacon.epoch', {value: 5n, configurable: true, writable: true})
    reset()
  }

  // ─── argument validation and the relay accessors ─────────────────────────────
  {
    // An unknown mode must list the ones that exist; the alternative is a revert from a
    // uint8 the contract does not recognise.
    reset()
    await rejectsWith(
      'an unknown slot mode is refused, listing the valid ones',
      /unknown mode "nonsense" \(expected .*frost.*\)/,
      () => client.createSlot({dcqlRule: 'any', k: 2, n: 3, mode: 'nonsense' as never}),
    )
    eq('an unknown mode signs nothing', txs.length, 0)

    // A malformed RPC URL cannot be loopback, so the chain id becomes mandatory — the URL
    // parse must not throw out of the constructor.
    let named = ''
    try {
      createTasraWriteClient({rpcUrl: 'not a url at all', addresses, privateKey})
    } catch (error) {
      named = error instanceof Error ? error.message : String(error)
    }
    ok('an unparseable rpc url is treated as non-loopback and demands a chain id', /chainId is required/.test(named))

    // The relay accessors must answer on a client with no relay rather than throwing.
    eq('pendingRelayAttempt is undefined without a relay', client.pendingRelayAttempt(), undefined)
    eq('lastRelay is undefined without a relay', client.lastRelay(), undefined)
    eq('reconcileRelay resolves to undefined without a relay', await client.reconcileRelay(), undefined)
  }
} finally {
  globalThis.fetch = realFetch
}

if (failures.length > 0) {
  console.error(`✗ chain.write-actions: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ chain.write-actions: ${passed} checks passed`)
