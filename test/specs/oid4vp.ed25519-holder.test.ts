// A credential is bound to one holder key, and the KB-JWT has to be signed by that key.
//
// The wallet used to sign every KB-JWT with ES256, so it could only ever present credentials bound to
// a P-256 holder. `tasra-cli vc issue-sd-jwt` binds an Ed25519 holder key, which made the
// network's own issuer and this SDK's wallet unable to meet: a sandbox agent could hold a credential
// the slot's rule admits and still not present it.
import {expect, it} from 'vitest'
import {ed25519} from '@noble/curves/ed25519'
import {ed25519HolderKey, holderSigner, randomHolderKey, b64url} from '../../src/oid4vp/jose.js'
import {didJwkIssuer, issueSdJwtVc, parseSdJwt, presentSdJwt, verifyKbJwt} from '../../src/oid4vp/sd-jwt.js'

const seed = new Uint8Array(32).fill(7)
const issuerKey = new Uint8Array(32).fill(3)

it('derives an Ed25519 holder whose did:jwk carries its public key', () => {
  const holder = ed25519HolderKey(seed)
  expect(holder.publicJwk).toEqual({kty: 'OKP', crv: 'Ed25519', x: b64url(ed25519.getPublicKey(seed))})
  expect(holder.did.startsWith('did:jwk:')).toBe(true)
  expect(holderSigner(holder).alg).toBe('EdDSA')
  expect(holderSigner(randomHolderKey()).alg).toBe('ES256')
})

it('presents a credential bound to an Ed25519 holder, and the KB-JWT verifies', () => {
  const holder = ed25519HolderKey(seed)
  const credential = issueSdJwtVc({
    issuer: didJwkIssuer(issuerKey),
    vct: 'EmployeeOf',
    claims: {dept: 'Engineering'},
    cnf: {jwk: holder.publicJwk},
    sub: holder.did,
  })
  const presentation = presentSdJwt({
    parsed: parseSdJwt(credential),
    disclose: 'all',
    holder,
    nonce: 'n-1',
    aud: 'decentralized_identifier:did:web:example',
  })
  const {holderJwk, claims} = verifyKbJwt(presentation, {nonce: 'n-1', aud: 'decentralized_identifier:did:web:example'})
  expect(holderJwk).toEqual(holder.publicJwk)
  expect(claims.nonce).toBe('n-1')
})

it('a P-256 holder still presents exactly as before', () => {
  const holder = randomHolderKey()
  const credential = issueSdJwtVc({
    issuer: didJwkIssuer(issuerKey),
    vct: 'EmployeeOf',
    claims: {dept: 'Engineering'},
    cnf: {jwk: holder.publicJwk},
    sub: holder.did,
  })
  const presentation = presentSdJwt({parsed: parseSdJwt(credential), disclose: 'all', holder, nonce: 'n-2', aud: 'x'})
  expect(verifyKbJwt(presentation, {nonce: 'n-2', aud: 'x'}).holderJwk).toEqual(holder.publicJwk)
})
