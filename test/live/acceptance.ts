// Non-destructive operations on dedicated, pre-provisioned test slots.
// Revocation is performed separately through the deployment's documented issuer flow.
import {execFileSync} from 'node:child_process'
import {readFileSync, writeFileSync} from 'node:fs'
import {fromBytes, verifyFrostSignature, credentialsCommitment, decodeJwtClaims} from 'tasra-sdk'
import {committeeClient, decryptPeers, loadHolder, loadNetwork, required, slotId} from '../../examples/live-config.ts'
import {expectDenial} from './acceptance-checks.ts'

const phase = process.argv[2]
if (phase !== 'baseline' && phase !== 'revoked') throw new Error('Usage: npm run test:acceptance -- baseline|revoked')
const output = required('KK_ACCEPTANCE_REPORT')
const network = await loadNetwork()
const bls = slotId()
const frost = slotId('KK_SIGN_SLOT_ID')
if (bls === frost) throw new Error('Acceptance needs separate BLS and FROST test slots')
const identity = loadHolder()
const revision = execFileSync('git', ['rev-parse', 'HEAD'], {encoding: 'utf8'}).trim()
if (execFileSync('git', ['status', '--porcelain'], {encoding: 'utf8'}).trim()) throw new Error('Live release evidence requires a clean committed checkout')
const binding = {deploymentId: network.manifest.deploymentId, manifestSha256: network.digest, revision,
  bls, frost, credentialCommitment: credentialsCommitment(identity.credentials), holder: identity.holder}
const outcomes: Record<string, unknown> = {}
let passed = false
const startedAt = new Date().toISOString()
try {
  // An expired credential is not evidence of issuer revocation.
  for (const credential of identity.credentials) {
    const claims = decodeJwtClaims(credential)
    if (typeof claims?.exp !== 'number' || claims.exp * 1000 <= Date.now()) throw new Error('Acceptance requires unexpired credentials with exp claims')
  }
  const client = committeeClient(network.chain, bls, identity, 'decrypt')
  const peers = await decryptPeers(network.chain, bls)
  const message = new TextEncoder().encode('Tasra release acceptance')
  const envelope = fromBytes(await client.encrypt(bls, message, {identity: new TextEncoder().encode(bls)}))
  const decryptOptions = {ciphertext: envelope.ciphertext, identity: envelope.identity,
    ciphertextEpoch: envelope.epoch === null ? undefined : Number(envelope.epoch),
    decryptingSet: peers.map(p => p.id), blsPeers: peers}
  if (phase === 'baseline') {
    const plaintext = await client.decrypt(bls, decryptOptions)
    if (!Buffer.from(plaintext).equals(Buffer.from(message))) throw new Error('Decryption mismatch')
    outcomes.decrypt = 'passed'
    const signature = await committeeClient(network.chain, frost, identity, 'sign').sign(frost, message)
    if (!verifyFrostSignature(signature.groupPublicKey, message, signature.signature)) throw new Error('Invalid FROST signature')
    outcomes.sign = 'passed'
    const denied = loadHolder('KK_DENIED')
    try {
      outcomes.denial = await expectDenial(() => committeeClient(network.chain, bls, denied, 'decrypt').decrypt(bls, decryptOptions))
    } finally { denied.secretKey.fill(0) }
  } else {
    const baseline = JSON.parse(readFileSync(required('KK_BASELINE_REPORT'), 'utf8')) as {
      passed: boolean; phase: string; binding: typeof binding; finishedAt: string
    }
    if (!baseline.passed || baseline.phase !== 'baseline' || JSON.stringify(baseline.binding) !== JSON.stringify(binding)) {
      throw new Error('Baseline must match this revision, deployment, slots, holder, and credential set')
    }
    const revokedAt = Date.parse(required('KK_REVOKED_AT'))
    const waitSeconds = Number(required('KK_REVOCATION_WAIT_SECONDS'))
    if (!Number.isFinite(revokedAt) || !Number.isSafeInteger(waitSeconds) || waitSeconds < 1 ||
      revokedAt < Date.parse(baseline.finishedAt) || Date.now() < revokedAt + waitSeconds * 1000) {
      throw new Error('Record a revocation after baseline and wait the deployment propagation/token-expiry window')
    }
    outcomes.revokedAt = new Date(revokedAt).toISOString()
    outcomes.waitSeconds = waitSeconds
    outcomes.revokedDecrypt = await expectDenial(() => client.decrypt(bls, decryptOptions))
    outcomes.revokedSign = await expectDenial(() => committeeClient(network.chain, frost, identity, 'sign').sign(frost, message))
  }
  passed = true
} catch {
  // Do not persist upstream errors, credential bodies, tokens, or private endpoints.
  outcomes.failure = 'Acceptance failed; inspect deployment diagnostics privately.'
  process.exitCode = 1
} finally {
  identity.secretKey.fill(0)
  writeFileSync(output, JSON.stringify({phase, binding, startedAt, finishedAt: new Date().toISOString(), passed, outcomes}, null, 2), {flag: 'wx', mode: 0o600})
}
console.log(`Acceptance ${passed ? 'passed' : 'failed'}; redacted evidence: ${output}`)
