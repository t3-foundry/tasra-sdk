// E2E (DESTRUCTIVE, env-gated): verifier MIS-ISSUANCE slashing through the real
// FaultOracle + accountant adjudication path, not the governance owner-slash shortcut.
//
// Needs a deployment with a deliberately byzantine verifier whose unsigned
// /v1/verify is enabled — that route is the mis-issuance injection point, and the
// suite skips cleanly when it is absent.
//
// Flow:
//   1. Present a VP that FAILS the slot rule (dept=Sales) → the byzantine verifier
//      mis-issues a JWT anyway and returns its own signed fault_statement.
//   2. A challenger opens a bonded FaultOracle challenge over keccak(signature).
//   3. Deliver the revealed evidence to the accountant set's fault intake.
//   4. The set re-runs the DCQL rule → Guilty → threshold-signs → resolve → the
//      verifier is slashed (slashed TSRA → Treasury).
//
// Run: KK_DESTRUCTIVE=1 tsx test/slashing/verifier-misissue-slash.ts

import {encodeAbiParameters, keccak256, toHex, type Hex} from 'viem'
import {Suite} from '../fleet/_assert.ts'
import {gate, loadFleetConfig} from '../fleet/_fleet.ts'
import {createTasraWriteClient} from '../../src/chain/write.ts'
import {accountantSlashingAbi} from '../../src/chain/abis/accountantSlashing.ts'
import {tasraTokenAbi} from '../../src/chain/abis/tasraToken.ts'

const cfg = loadFleetConfig()
const s = new Suite('e2e: V1 verifier mis-issuance slashing (DESTRUCTIVE)')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}
if (process.env.KK_DESTRUCTIVE !== '1') {
  s.skip('destructive verifier-misissue-slash (needs demo-faults fleet + KK_DESTRUCTIVE=1)')
  s.done()
  process.exit(0)
}

const verifier = cfg.verifierUrls[0]! // verifier-1 = the byzantine, unsigned-on verifier
const oracle = cfg.raw.FAULT_ORACLE as Hex
const tsra = cfg.raw.TSRA_TOKEN as Hex
const treasury = cfg.raw.TREASURY as Hex
const RULE = '{"credentials":[{"id":"emp","format":"jwt_vc_json","claims":[{"path":["dept"],"values":["Engineering"]}]}],"_kk_legacy":true}'
// Canonical Presentation form (field order matters — it must
// re-serialize to the exact bytes the verifier hashed into vp_hash). `format` is
// NOT optional here: the reference implementation `Credential.format` has a serde default but is always
// serialized, so omitting it changes the hash and every accountant refuses the
// evidence ("vp_json does not match committed vp_hash").
const VP = {holder: 'did:demo:mallory', credentials: [{issuer: 'did:web:hr.acmecorp.example', credential_type: 'EmployeeOf', claims: {dept: 'Sales'}, format: 'jwt_vc_json'}]}

// ── 1. trigger mis-issuance ───────────────────────────────────────────────────
// The prod-profile verifier disables the unsigned /v1/verify (404, empty body),
// so guard the response before parsing — otherwise `.json()` throws on the empty
// body instead of reaching the graceful skip below.
const verifyRes = await fetch(`${verifier}/v1/verify`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({dcql_rule: RULE, presentation: VP})})
if (!verifyRes.ok) {
  s.skip(`verifier /v1/verify unavailable (HTTP ${verifyRes.status}) — needs the demo-faults fleet with verifier-1 unsigned ON`)
  s.done()
  process.exit(0)
}
const resp = (await verifyRes.json()) as {
  token?: string
  fault_statement?: {rule_hash: string; vp_hash: string; signature: Hex; verifier: Hex}
}
const fs = resp.fault_statement
if (!fs) {
  // Honest fleet (no demo-faults, or verifier-1's unsigned path off) — can't trigger V1.
  s.skip('verifier did not mis-issue — needs the demo-faults fleet with verifier-1 unsigned ON')
  s.done()
  process.exit(0)
}
s.ok('byzantine verifier mis-issued a token for a FAILING VP', !!resp.token)
s.ok('verifier returned a signed fault_statement (self-incriminating)', !!fs)

// ── 2. challenger opens a bonded FaultOracle challenge ─────────────────────────
const dep = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: cfg.deployPk as Hex, chainId: cfg.chainId})
const subjectHash = keccak256(fs.signature) // keccak of the 64-byte ed25519 sig
const faultDomain = keccak256(toHex('verifier:mis-issuance'))
const bond = (await dep.pub.readContract({address: oracle, abi: accountantSlashingAbi, functionName: 'challengeBond'})) as bigint
if (bond > 0n) {
  await dep.pub.waitForTransactionReceipt({hash: await dep.wallet.writeContract({address: tsra, abi: tasraTokenAbi, functionName: 'approve', args: [oracle, bond]})})
}
const treasury0 = await dep.tsraBalance(treasury)
// Opening a challenge is COMMIT-then-REVEAL: the commitment binds
// (challenger, accused, domain, subject, salt) and `open` needs it from THIS sender in an
// EARLIER block, so a mempool observer of the reveal cannot steal the challenge.
const salt = keccak256(toHex(`misissue-salt/${Date.now()}/${Math.random()}`))
const fromBlock = await dep.pub.getBlockNumber()
const commitment = keccak256(encodeAbiParameters(
  [{type: 'address'}, {type: 'address'}, {type: 'bytes32'}, {type: 'bytes32'}, {type: 'bytes32'}],
  [dep.wallet.account.address, fs.verifier, faultDomain, subjectHash, salt],
))
await dep.pub.waitForTransactionReceipt({hash: await dep.wallet.writeContract({address: oracle, abi: accountantSlashingAbi, functionName: 'commitChallenge', args: [commitment]})})
// `gas` pinned on purpose: eth_estimateGas simulates on the LATEST block, where
// block.number == committedAtBlock, so the estimate alone reverts CommitTooFresh.
await dep.pub.waitForTransactionReceipt({hash: await dep.wallet.writeContract({address: oracle, abi: accountantSlashingAbi, functionName: 'open', args: [fs.verifier, faultDomain, subjectHash, salt], gas: 400_000n})})
const cid = (await dep.pub.readContract({address: oracle, abi: accountantSlashingAbi, functionName: 'challengeCount'})) as bigint
s.ok('opened a bonded FaultOracle challenge', cid > 0n, `challenge #${cid}, bond=${bond}`)

// ── 3. deliver revealed evidence to the accountant fault intake ────────────────
// The intake is not published by default, so its URLs are explicit: a deployment
// that wants this covered has to expose them.
const evid = JSON.stringify({verifier: fs.verifier, rule_hash: fs.rule_hash, vp_hash: fs.vp_hash, signature: fs.signature, vp_json: JSON.stringify(VP), dcql_rule: RULE})
const intakes = (process.env.TASRA_ACCOUNTANT_EVIDENCE_URLS ?? '')
  .split(',').map(u => u.trim().replace(/\/$/, '')).filter(Boolean)
if (!intakes.length) {
  s.ok('accountant fault intake reachable', false,
    'set TASRA_ACCOUNTANT_EVIDENCE_URLS to the accountants\' fault-evidence base URLs (comma-separated)')
} else {
  let delivered = 0
  for (const url of intakes) {
    try {
      const res = await fetch(`${url}/v1/fault/evidence`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: evid,
        signal: AbortSignal.timeout(10_000),
      })
      if (res.ok) delivered++
    } catch {
      /* intake unreachable — try the rest */
    }
  }
  s.ok('delivered the revealed evidence to the accountant set', delivered > 0, `${delivered}/${intakes.length}`)
}

// ── 4. wait for the 2-of-3 set to adjudicate Guilty → slash (Treasury Δ) ───────
// ⚠ Read THIS challenge's ChallengeResolved event, not a Treasury Δ: on a fault fleet every
// other slash moves the Treasury too, so a Δ reads green for a challenge nobody adjudicated.
s.info(`treasury before: ${treasury0} — waiting up to 120s for challenge #${cid}'s verdict…`)
let verdict: {guilty: boolean; taken: bigint} | undefined
for (let t = 0; t < 24 && !verdict; t++) {
  await new Promise(r => setTimeout(r, 5000))
  const logs = await dep.pub.getContractEvents({address: oracle, abi: accountantSlashingAbi, eventName: 'ChallengeResolved', args: {id: cid}, fromBlock})
  const ev = logs[0] as unknown as {args: {guilty: boolean; taken: bigint}} | undefined
  if (ev) verdict = ev.args
}
s.ok('the accountant set adjudicated THIS challenge Guilty', verdict?.guilty === true, `challenge #${cid}: ${verdict ? `guilty=${verdict.guilty} taken=${verdict.taken}` : 'unresolved'}`)

s.done()
