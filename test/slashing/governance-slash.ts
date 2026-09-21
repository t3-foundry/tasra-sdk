// Slashing (MUTATING — opt-in): the governance slash path, end-to-end on chain.
//
// The owner slashes a registered operator by `bps`; the operator's stake must drop
// by exactly stake·bps/10000, the Treasury must grow by at least that, and a
// partial (<100%) slash must leave the operator active.
//
// ⚠️  This PERMANENTLY reduces an operator's stake on the target deployment — it is
// irreversible. It is therefore DISABLED by default and only runs when you set
// KK_SLASH_TEST=1 and TASRA_DEPLOY_PK holds the owner key. Pick the victim with
// OP_INDEX (default 1; never the deployer at index 0).
//
// Run: KK_SLASH_TEST=1 tsx test/slashing/governance-slash.ts

import {createPublicClient, createWalletClient, http, parseAbi} from 'viem'
import {privateKeyToAccount} from 'viem/accounts'
import {Suite} from '../fleet/_assert.ts'
import {gate, loadFleetConfig} from '../fleet/_fleet.ts'
import {chainClient} from '../reconcile/_explorer.ts'

interface OnchainNode {
  operator: string
  stake: bigint
  active: boolean
}

const cfg = loadFleetConfig()
const s = new Suite('slashing: governance slash (mutating)')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}
if (process.env.KK_SLASH_TEST !== '1') {
  s.skip('mutating slash', 'set KK_SLASH_TEST=1 to run — this irreversibly slashes a real operator')
  s.done()
  process.exit(0)
}
const registry = cfg.book.NodeRegistry
const treasuryAddr = cfg.book.Treasury
if (!registry || !treasuryAddr || !cfg.deployPk) {
  s.ok('NodeRegistry + Treasury addresses and TASRA_DEPLOY_PK available', false, 'set them in the environment')
  s.done()
  process.exit(1)
}

const bps = Number(process.env.SLASH_BPS ?? 1000) // 10%
const opIndex = BigInt(process.env.OP_INDEX ?? 1)
const ch = chainClient(cfg)
const tokenAddr = cfg.book.TasraToken!

const op = (await ch.readers.nodeRegistry.operatorAt(opIndex)) as `0x${string}`
s.ok('resolved a target operator', /^0x[0-9a-fA-F]{40}$/.test(op) && BigInt(op) !== 0n, op)
s.ok('target is not the deployer/owner', op.toLowerCase() !== cfg.deployAddr, op)

const before = (await ch.readers.nodeRegistry.nodeOf(op)) as OnchainNode
const treasuryBefore = (await ch.readers.token.balanceOf(treasuryAddr)) as bigint
const expectedSlash = (before.stake * BigInt(bps)) / 10000n
s.info(`operator ${op} stake ${before.stake} → expect −${expectedSlash} (bps=${bps})`)

// The slash itself, signed by the owner key.
{
  const account = privateKeyToAccount(cfg.deployPk as `0x${string}`)
  const transport = http(cfg.rpcUrl)
  const wallet = createWalletClient({account, transport})
  const pub = createPublicClient({transport})
  const hash = await wallet.writeContract({
    address: registry as `0x${string}`,
    abi: parseAbi(['function slash(address,uint16,string)']),
    functionName: 'slash',
    args: [op as `0x${string}`, bps, 'e2e_governance_slash'],
    account,
    chain: null,
  })
  const receipt = await pub.waitForTransactionReceipt({hash})
  if (receipt.status !== 'success') throw new Error(`slash reverted: ${hash}`)
}

const after = (await ch.readers.nodeRegistry.nodeOf(op)) as OnchainNode
const treasuryAfter = (await ch.readers.token.balanceOf(treasuryAddr)) as bigint

s.eq('operator stake dropped by exactly stake·bps/10000', before.stake - after.stake, expectedSlash)
s.ok('treasury grew by at least the slashed amount', treasuryAfter - treasuryBefore >= expectedSlash, `Δtreasury=${treasuryAfter - treasuryBefore}`)
s.ok('a partial (<100%) slash keeps the operator active', bps >= 10000 ? !after.active : after.active)
void tokenAddr

s.done()
