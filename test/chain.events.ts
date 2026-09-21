// Event registry + decoding conformance: build a synthetic log and decode it,
// and check the registry helpers.
//
// Run: tsx test/chain.events.ts — exits non-zero on any failure.

import {
  encodeEventTopics,
  encodeAbiParameters,
  type Log,
} from 'viem'
import {
  decodeContractLogs,
  categoryFor,
  eventNamesOf,
  jsonSafe,
} from '../src/chain/events.ts'
import {tasraTokenAbi} from '../src/chain/abis/tasraToken.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean) {
  if (cond) passed++
  else failures.push(name)
}

const token = '0xe7f1725e7734ce288f8367e1bb143e90bb3f0512' as `0x${string}`
const from = '0x0000000000000000000000000000000000000001' as `0x${string}`
const to = '0x0000000000000000000000000000000000000002' as `0x${string}`
const value = 1234567890000000000n

// 1. Decode a real ERC-20 Transfer log against the generated TasraToken ABI.
{
  const topics = encodeEventTopics({
    abi: tasraTokenAbi,
    eventName: 'Transfer',
    args: {from, to},
  })
  const data = encodeAbiParameters([{type: 'uint256'}], [value])
  const log: Log = {
    address: token,
    topics: topics as [`0x${string}`, ...`0x${string}`[]],
    data,
    blockNumber: 42n,
    blockHash: ('0x' + '11'.repeat(32)) as `0x${string}`,
    transactionHash: ('0x' + '22'.repeat(32)) as `0x${string}`,
    transactionIndex: 0,
    logIndex: 3,
    removed: false,
  }
  const decoded = decodeContractLogs('TasraToken', token, [log])
  ok('decode: one event produced', decoded.length === 1)
  const e = decoded[0]!
  ok('decode: eventName Transfer', e.eventName === 'Transfer')
  ok('decode: category tasra', e.category === 'tasra')
  ok('decode: from arg', String(e.args.from).toLowerCase() === from)
  ok('decode: to arg', String(e.args.to).toLowerCase() === to)
  ok('decode: value arg', e.args.value === value)
  ok('decode: blockNumber', e.blockNumber === 42n)
  ok('decode: logIndex', e.logIndex === 3)

  // jsonSafe should stringify the bigint value for storage.
  const safe = jsonSafe(e.args) as Record<string, unknown>
  ok('jsonSafe: bigint → string', safe.value === '1234567890000000000')
}

// 2. Registry helpers.
{
  ok('category override: NodeRegistry.Slashed → slashing', categoryFor('NodeRegistry', 'Slashed') === 'slashing')
  ok('category default: NodeRegistry.NodeRegistered → node', categoryFor('NodeRegistry', 'NodeRegistered') === 'node')
  ok('category: KeyRegistry default → slot', categoryFor('KeyRegistry', 'KeySlotCreated') === 'slot')
  const names = eventNamesOf('EquivocationSlasher')
  ok('eventNamesOf: EquivocationSlashed present', names.includes('EquivocationSlashed'))
}

if (failures.length) {
  console.error(`chain.events FAILED (${failures.length}):`)
  for (const f of failures) console.error('  ✗', f)
  process.exit(1)
}
console.log(`chain.events: ${passed} checks passed`)
