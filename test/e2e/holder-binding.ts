// E2E: holder proof-of-possession (verifier F1/F4) on the demo fleet.
//
// Demonstrates the gap the security review closed: when the verifier runs with
// `require_holder_binding`, presenting a valid signed VC is NOT enough — the presenter
// must prove control of the holder DID's authentication key over a fresh single-use
// `/v1/nonce` + the verifier audience + a commitment to the exact credentials.
//
// Holder = an app-controlled `did:key` (we hold its Ed25519 key, so the SDK can sign the
// proof). The VC is issued by the demo's anchored issuer (did:web:hr.acmecorp.example) to
// that did:key, so the verifier trusts it and `did_accept_methods` resolves the holder.
//
// Asserts: (1) a bare presentation is REJECTED, (2) a valid holder proof is ACCEPTED,
// (3) replaying the same proof is REJECTED (single-use nonce), (4) a proof bound to a
// different credential set is REJECTED (credential-commitment binding).
//
// Run: tsx test/e2e/holder-binding.ts

import {ed25519} from '@noble/curves/ed25519'
import {Suite} from '../fleet/_assert.ts'
import {ENGINEERING_RULE, gate, issueVc, loadFleetConfig} from '../fleet/_fleet.ts'
import {verifyVpJwt} from '../../src/auth/verifier.ts'
import {createHolderProof, ed25519DidKey, type HolderSigner} from '../../src/auth/holderProof.ts'

const cfg = loadFleetConfig()
const s = new Suite('e2e: holder proof-of-possession (F1/F4)')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}

const verifier = cfg.verifierUrls[0]!
// The holder proof's `aud` must equal the verifier's token `iss` (its stable identity).
if (!cfg.jwtIss) throw new Error('set TASRA_JWT_ISS to the verifier iss this deployment issues under')
const audience = cfg.jwtIss

// An app-controlled did:key holder (we hold the signing key → we can prove possession).
const holderSk = ed25519.utils.randomPrivateKey()
const holderDid = ed25519DidKey(ed25519.getPublicKey(holderSk))
const signer: HolderSigner = {alg: 'EdDSA', did: holderDid, secretKey: holderSk}

// A VC issued by the anchored issuer to that did:key (CLI signs with the trusted issuer).
const vc = issueVc(cfg, {holder: holderDid, claims: {dept: 'Engineering', employer: 'AcmeCorp'}})
const credentials = [vc]
const rule = ENGINEERING_RULE

async function rejected(label: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn()
    s.ok(label, false, 'expected the verifier to reject, but it accepted')
  } catch {
    s.ok(label, true)
  }
}

// The SDK rejects bare VP-JWT presentations before they can reach the verifier.
await rejected('a bare presentation (no holder proof) is rejected', () =>
  verifyVpJwt(verifier, {dcql_rule: rule, holder: holderDid, credentials} as {dcql_rule: string; holder: string; credentials: string[]; holder_proof: string}),
)

// ── (2) a valid holder proof is accepted ──────────────────────────────────────────
const proof = await createHolderProof(verifier, {signer, audience, credentials})
let token = ''
try {
  const issued = await verifyVpJwt(verifier, {dcql_rule: rule, holder: holderDid, credentials, holder_proof: proof})
  token = issued.token
  s.ok('a valid holder proof mints a token', !!issued.token)
  s.eq('token is bound to the holder did:key', issued.holder, holderDid)
} catch (e) {
  s.ok('a valid holder proof mints a token', false, String(e))
}

// ── (3) replaying the SAME proof is rejected (single-use nonce) ────────────────────
await rejected('replaying the same holder proof is rejected (nonce consumed)', () =>
  verifyVpJwt(verifier, {dcql_rule: rule, holder: holderDid, credentials, holder_proof: proof}),
)

// ── (4) a proof bound to a DIFFERENT credential set is rejected ────────────────────
// Build a fresh proof committing to a different credential list, then present it with the
// real credentials — the verifier recomputes the commitment and refuses the mismatch.
const otherVc = issueVc(cfg, {holder: holderDid, claims: {dept: 'Sales', employer: 'AcmeCorp'}})
const mismatchedProof = await createHolderProof(verifier, {signer, audience, credentials: [otherVc]})
await rejected('a holder proof bound to other credentials is rejected (commitment mismatch)', () =>
  verifyVpJwt(verifier, {dcql_rule: rule, holder: holderDid, credentials, holder_proof: mismatchedProof}),
)

if (token) {
  console.log('  ✓ F1/F4 holder binding enforced: theft-of-credentials and replay both denied')
}

s.done()
