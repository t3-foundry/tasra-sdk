// E2E (DESTRUCTIVE, env-gated KK_DESTRUCTIVE=1): operator onboarding → on-chain
// SLASH → unbond, on a THROWAWAY operator so the live fleet stays intact.
//
// Exercises the real on-chain accounting:
//   register (stake REQUIRED_STAKE) → NodeRegistry.slash (stake−bps → treasury)
//   → requestUnbond → completeUnbond is rejected until the 7-day period elapses.
//
// The throwaway never runs a node process, so we slash it via the owner path here
// rather than waiting on the accountant health-check loop (which would also slash
// it for downtime). The byzantine fault-oracle flows (mis-issue / false-slash /
// wrong-bundle) need a fault-injected fleet (KK_DEMO_FAULT_* at fleet-up) and are
// out of scope against this honest fleet.
//
// Run: KK_DESTRUCTIVE=1 tsx test/slashing/node-slash-lifecycle.ts

import {parseEther} from 'viem'
import {Suite} from '../fleet/_assert.ts'
import {gate, loadFleetConfig} from '../fleet/_fleet.ts'
import {createTasraWriteClient, generateClientKey} from '../../src/chain/write.ts'
import {httpFaucet} from '../../src/slots/faucet.ts'
import {nodeRegistryAbi} from '../../src/chain/abis/nodeRegistry.ts'
import {tasraTokenAbi} from '../../src/chain/abis/tasraToken.ts'
import {requireAddress} from '../../src/chain/deployments.ts'

const cfg = loadFleetConfig()
const s = new Suite('e2e: node onboard → slash → unbond (DESTRUCTIVE)')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}
if (process.env.KK_DESTRUCTIVE !== '1') {
  s.skip('destructive node-slash-lifecycle (set KK_DESTRUCTIVE=1 to run)')
  s.done()
  process.exit(0)
}

const reg = requireAddress(cfg.book, 'NodeRegistry')
const treasury = requireAddress(cfg.book, 'Treasury')
const owner = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: cfg.deployPk as `0x${string}`, chainId: cfg.chainId})
const op = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: generateClientKey(), chainId: cfg.chainId})
s.info(`throwaway operator ${op.address}`)

const nodeOf = (a: `0x${string}`) => owner.pub.readContract({address: reg, abi: nodeRegistryAbi, functionName: 'nodeOf', args: [a]}) as Promise<{stake: bigint; unbondingAt: bigint; active: boolean}>
const isActive = (a: `0x${string}`) => owner.pub.readContract({address: reg, abi: nodeRegistryAbi, functionName: 'isActive', args: [a]}) as Promise<boolean>
const required = (await owner.pub.readContract({address: reg, abi: nodeRegistryAbi, functionName: 'requiredStake'})) as bigint

// ── fund + stake the throwaway (faucet ETH for gas; deployer supplies the 2000 TSRA stake) ──
try {
  await httpFaucet(cfg.faucetUrl).fund(op.address)
} catch {
  await owner.sendEth(op.address, parseEther('1'))
}
await owner.transferTsra(op.address, required)
s.ok('throwaway funded with the required stake', (await op.tsraBalance()) >= required, `${required / 10n ** 18n} TSRA`)

// ── register as an operator ───────────────────────────────────────────────────
await op.pub.waitForTransactionReceipt({hash: await op.wallet.writeContract({address: requireAddress(cfg.book, 'TasraToken'), abi: tasraTokenAbi, functionName: 'approve', args: [reg, required]})})
const count0 = (await owner.pub.readContract({address: reg, abi: nodeRegistryAbi, functionName: 'operatorCount'})) as bigint
await op.pub.waitForTransactionReceipt({hash: await op.wallet.writeContract({address: reg, abi: nodeRegistryAbi, functionName: 'register', args: ['e2e-destructive.test', 'http://throwaway.invalid', '', `0x${'ab'.repeat(33)}`]})})
s.ok('operator is registered + active', await isActive(op.address))
s.eq('staked exactly REQUIRED_STAKE', (await nodeOf(op.address)).stake, required)
s.eq('operatorCount incremented', (await owner.pub.readContract({address: reg, abi: nodeRegistryAbi, functionName: 'operatorCount'})) as bigint, count0 + 1n)

// ── owner slashes the throwaway 10% → treasury ────────────────────────────────
const stake0 = (await nodeOf(op.address)).stake
const treasury0 = await owner.tsraBalance(treasury)
const bps = 1000n // 10%
const expectedCut = (stake0 * bps) / 10000n
// waitForTransactionReceipt RESOLVES on a reverted tx (status:'reverted', no
// throw) - the documented viem trap the SDK write helpers already guard. This
// raw call bypassed them and a silently-reverted slash surfaced 20 lines later
// as "stake unchanged" with zero diagnostics on a live cert.
{
  const hash = await owner.wallet.writeContract({address: reg, abi: nodeRegistryAbi, functionName: 'slash', args: [op.address, Number(bps), 'e2e-destructive-slash']})
  const rcpt = await owner.pub.waitForTransactionReceipt({hash})
  s.ok(`slash tx mined OK (${hash.slice(0, 14)}…)`, rcpt.status === 'success', `status=${rcpt.status} block=${rcpt.blockNumber}`)
}
s.eq('slash reduced stake by 10%', (await nodeOf(op.address)).stake, stake0 - expectedCut)
// On a LIVE fleet the treasury also receives the accountant's settlement-revenue
// split concurrently, so the delta can exceed the slash cut by a little dust.
// The sound invariant is that AT LEAST the slash cut landed in the treasury.
const treasuryDelta = (await owner.tsraBalance(treasury)) - treasury0
s.ok('slashed amount routed to treasury (≥ cut; live accountant may add revenue)', treasuryDelta >= expectedCut, `delta ${treasuryDelta} < cut ${expectedCut}`)
s.ok('operator still active after a partial slash', await isActive(op.address))

// ── unbond lifecycle: request, then completeUnbond is rejected (7-day period) ──
await op.pub.waitForTransactionReceipt({hash: await op.wallet.writeContract({address: reg, abi: nodeRegistryAbi, functionName: 'requestUnbond', args: []})})
s.ok('requestUnbond set an unbonding timestamp', (await nodeOf(op.address)).unbondingAt > 0n)
s.ok('operator deactivated while unbonding', !(await isActive(op.address)))

let completeRejected = false
try {
  await op.wallet.writeContract({address: reg, abi: nodeRegistryAbi, functionName: 'completeUnbond', args: []})
} catch {
  completeRejected = true
}
s.ok('completeUnbond rejected before the unbonding period elapses', completeRejected, 'unbondingPeriod = 7d')

s.done()
