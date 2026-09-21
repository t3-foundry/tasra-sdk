// Unit tests for the F1/F4 holder proof-of-possession helpers.
//
// Run: `tsx test/holder-proof.ts` (part of `npm test`). No network — exercises the
// proof construction + signing locally, and pins the cross-language credential
// commitment against the verifier's the reference implementation `credentials_commitment`.

import assert from 'node:assert/strict'
import {ed25519} from '@noble/curves/ed25519'
import {
  buildHolderProof,
  credentialsCommitment,
  ed25519DidKey,
  type HolderSigner,
} from '../src/auth/holderProof.js'

function b64urlToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad)
  return Uint8Array.from(bin, c => c.charCodeAt(0))
}
function b64urlToStr(s: string): string {
  return new TextDecoder().decode(b64urlToBytes(s))
}

let passed = 0
function check(name: string, fn: () => void) {
  fn()
  passed++
  console.log(`ok - ${name}`)
}

// 1) Cross-language KAT: must match the reference holder-proof implementation
//    `credentials_commitment_known_answer` — base64url(sha256("a\nb")).
check('credentialsCommitment matches the verifier KAT', () => {
  assert.equal(credentialsCommitment(['a', 'b']), 'fhj3NzEbLcOy8mndeDlrA1HxT7Zu-oefdoyyMYGIPHg')
})

check('credentialsCommitment is order-sensitive', () => {
  assert.notEqual(credentialsCommitment(['x', 'y']), credentialsCommitment(['y', 'x']))
})

// 2) buildHolderProof produces a verifiable EdDSA compact-JWS with the right claims.
await (async () => {
  const sk = ed25519.utils.randomPrivateKey()
  const pk = ed25519.getPublicKey(sk)
  const did = ed25519DidKey(pk)
  const signer: HolderSigner = {alg: 'EdDSA', did, secretKey: sk}
  const creds = ['credA', 'credB']
  const proof = await buildHolderProof({
    signer,
    audience: 'verifier-1',
    nonce: 'deadbeef',
    credentials: creds,
    slotId: '0xabc',
    action: 'sign',
    nowSecs: 1_700_000_000,
  })

  check('holder proof has three JWS segments', () => {
    assert.equal(proof.split('.').length, 3)
  })

  const [h, p, s] = proof.split('.')
  check('holder proof header is EdDSA/JWT', () => {
    const header = JSON.parse(b64urlToStr(h!))
    assert.equal(header.alg, 'EdDSA')
    assert.equal(header.typ, 'JWT')
  })

  check('holder proof claims bind iss/aud/nonce/vp_hash/slot/action', () => {
    const c = JSON.parse(b64urlToStr(p!))
    assert.equal(c.iss, did)
    assert.equal(c.aud, 'verifier-1')
    assert.equal(c.nonce, 'deadbeef')
    assert.equal(c.vp_hash, credentialsCommitment(creds))
    assert.equal(c.slot_id, '0xabc')
    assert.equal(c.action, 'sign')
    assert.equal(c.exp, 1_700_000_000 + 300)
  })

  check('holder proof signature verifies under the holder public key', () => {
    const signingInput = new TextEncoder().encode(`${h}.${p}`)
    const sig = b64urlToBytes(s!)
    assert.ok(ed25519.verify(sig, signingInput, pk), 'signature must verify')
  })

  check('a tampered payload fails verification', () => {
    const tampered = JSON.parse(b64urlToStr(p!))
    tampered.nonce = 'cafebabe'
    const badP = btoa(JSON.stringify(tampered)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const signingInput = new TextEncoder().encode(`${h}.${badP}`)
    const sig = b64urlToBytes(s!)
    assert.ok(!ed25519.verify(sig, signingInput, pk), 'tampered claims must not verify')
  })
})()

// 3) A callback signer (HSM/wallet) path works too.
await (async () => {
  const sk = ed25519.utils.randomPrivateKey()
  const pk = ed25519.getPublicKey(sk)
  const did = ed25519DidKey(pk)
  const signer: HolderSigner = {
    alg: 'EdDSA',
    did,
    sign: input => ed25519.sign(input, sk),
  }
  const proof = await buildHolderProof({signer, audience: 'v', nonce: 'n', credentials: ['c']})
  const [h, p, s] = proof.split('.')
  check('callback signer produces a verifiable proof', () => {
    assert.ok(ed25519.verify(b64urlToBytes(s!), new TextEncoder().encode(`${h}.${p}`), pk))
  })
})()

console.log(`\n${passed} checks passed`)
