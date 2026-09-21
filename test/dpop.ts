// unit tests for the DPoP helper (src/auth/dpop.ts).
//
// No network. What these pin is the ONE property everything else rests on: the proof's key
// must be the key the access token is bound to, so `jwkThumbprint` here and the verifier's
// RFC 7638 thumbprint must produce the SAME string for the same key. A mismatch presents as
// "DPoP proof jwk is not the key the access token is bound to" on every drawn verifier, with
// nothing in the client to point at.
//
// Run: `tsx test/dpop.ts` (part of `npm test`).

import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {
  createDpopKey,
  jwkThumbprint,
  accessTokenHash,
  auth0DpopSigner,
  isHeaderSafeNonce,
} from '../src/auth/dpop.js'
import {platformAudience, dpopHtu} from '../src/committee/oauth.js'

let passed = 0
async function check(name: string, fn: () => void | Promise<void>) {
  await fn()
  passed++
  console.log(`ok - ${name}`)
}

function b64url(b: Buffer): string {
  return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function decodeSegment(jws: string, i: number): Record<string, unknown> {
  const seg = jws.split('.')[i]
  assert.ok(seg, `segment ${i} missing`)
  const pad = seg.length % 4 === 0 ? '' : '='.repeat(4 - (seg.length % 4))
  const json = Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString()
  return JSON.parse(json) as Record<string, unknown>
}

await check('RFC 7638 thumbprint matches the independently computed hash', async () => {
  // A worked RFC 7638 example shape: the canonical JSON is exactly the four required EC
  // members, lexicographic, no whitespace. Computing it here a SECOND way is what makes this
  // a known-answer test rather than a round-trip that would pass if both halves were wrong.
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  }
  const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
  const expected = b64url(createHash('sha256').update(canonical).digest())
  assert.equal(await jwkThumbprint(jwk), expected)

  // ⚠ THE CROSS-LANGUAGE VECTOR. The SAME pair is pinned in the reference adapter
  // (`vc/adapters/oidc.rs::rfc_7638_thumbprint_vector`), computed there through
  // `ssi_jwk::JWK::thumbprint()`. Three implementations of RFC 7638 sit on this value — the
  // tenant's IdP (which writes it into `cnf.jkt`), the verifier (which recomputes it from
  // the proof header) and this one — and a disagreement presents as every proof being
  // refused, with nothing in the client to point at. Changing one side without the other is
  // exactly the drift this line catches.
  assert.equal(await jwkThumbprint(jwk), 'oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U')
})

await check('a generated key mints a proof carrying every RFC 9449 claim', async () => {
  const key = await createDpopKey()
  const token = 'header.payload.signature'
  const proof = await key.signer.proof({
    htm: 'POST',
    htu: 'https://agent.example/v1/sessions/oauth-response',
    nonce: 'kk-nonce-abc',
    accessToken: token,
  })

  const header = decodeSegment(proof, 0)
  assert.equal(header.typ, 'dpop+jwt', 'RFC 9449 §4.2 requires this typ')
  assert.equal(header.alg, 'ES256')
  // The public key rides in the header — and ONLY the public half. A `d` here would be the
  // client leaking its own secret to every verifier.
  const jwk = header.jwk as Record<string, unknown>
  assert.equal(jwk.kty, 'EC')
  assert.equal(jwk.crv, 'P-256')
  assert.ok(!('d' in jwk), 'a proof must never carry private key material')

  const payload = decodeSegment(proof, 1)
  assert.equal(payload.htm, 'POST')
  assert.equal(payload.htu, 'https://agent.example/v1/sessions/oauth-response')
  assert.equal(payload.nonce, 'kk-nonce-abc')
  assert.equal(payload.ath, await accessTokenHash(token))
  assert.ok(typeof payload.jti === 'string' && payload.jti.length > 0)
  assert.ok(typeof payload.iat === 'number')
})

await check('the header jwk is the key the thumbprint names', async () => {
  // THE binding, from the client side: an IdP puts `thumbprint()` in the token's `cnf.jkt`,
  // and every verifier recomputes it from the proof's header `jwk`. If these two ever
  // disagreed, every proof this SDK mints would be refused.
  const key = await createDpopKey()
  const proof = await key.signer.proof({
    htm: 'POST',
    htu: 'https://agent.example/v1/sessions/oauth-response',
    nonce: 'n',
    accessToken: 't',
  })
  const headerJwk = decodeSegment(proof, 0).jwk as Record<string, unknown>
  assert.equal(await jwkThumbprint(headerJwk), await key.thumbprint())
})

await check('ath is the base64url sha256 of the token, not of anything else', async () => {
  const token = 'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhbGljZSJ9.sig'
  const expected = b64url(createHash('sha256').update(token, 'ascii').digest())
  assert.equal(await accessTokenHash(token), expected)
  // A different token must produce a different hash — otherwise `ath` binds nothing.
  assert.notEqual(await accessTokenHash(token), await accessTokenHash(`${token}x`))
})

await check('each proof is fresh: jti never repeats', async () => {
  const key = await createDpopKey()
  const args = {
    htm: 'POST',
    htu: 'https://agent.example/v1/sessions/oauth-response',
    nonce: 'n',
    accessToken: 't',
  }
  const seen = new Set<string>()
  for (let i = 0; i < 8; i++) {
    const jti = decodeSegment(await key.signer.proof(args), 1).jti as string
    assert.ok(!seen.has(jti), 'jti must be fresh per proof')
    seen.add(jti)
  }
})

await check('the auth0 adapter forwards the URL, method and nonce unchanged', async () => {
  // The Auth0 SDK owns the key, so all this wrapper may do is pass our values through. A
  // transformation here (a trailing slash, a lower-cased method) would make the proof's
  // `htu`/`htm` disagree with what every verifier derives.
  let seen: Record<string, unknown> | undefined
  const signer = auth0DpopSigner(async (a) => {
    seen = a as unknown as Record<string, unknown>
    return 'proof-from-auth0'
  })
  const out = await signer.proof({
    htm: 'POST',
    htu: 'https://agent.example/v1/sessions/oauth-response',
    nonce: 'kk-nonce',
    accessToken: 'tok',
  })
  assert.equal(out, 'proof-from-auth0')
  assert.deepEqual(seen, {
    url: 'https://agent.example/v1/sessions/oauth-response',
    method: 'POST',
    nonce: 'kk-nonce',
    accessToken: 'tok',
  })
})

await check('a non-EC key is refused rather than thumbprinted wrongly', async () => {
  await assert.rejects(() => jwkThumbprint({kty: 'RSA', n: 'x', e: 'AQAB'}))
  await assert.rejects(() => jwkThumbprint({kty: 'EC', crv: 'P-256', x: 'x'}))
})

await check('a header-unsafe nonce is detectable before it breaks a challenge', () => {
  assert.equal(isHeaderSafeNonce('kk-nonce_abc123'), true)
  assert.equal(isHeaderSafeNonce(''), false)
  assert.equal(isHeaderSafeNonce('has space'), false)
  assert.equal(isHeaderSafeNonce('has\nnewline'), false)
})

// ─── derivation vectors ────────────────────────────────────────────
//
// ⚠ These are THE SAME vectors as `keykeeper-committee/src/oauth.rs::{audience_vectors,
// htu_vectors, the_origin_is_normalised_so_one_deployment_has_one_audience}`. A tenant
// registers the audience with its IdP from THIS side; every drawn verifier derives it from
// the reference implementation. A divergence means every token is refused for the wrong audience, and the
// tenant has no way to see why.

await check('platformAudience vectors match the reference implementation derivation', () => {
  assert.equal(
    platformAudience('https://agent.kk.example', 43113),
    'https://agent.kk.example/authz/43113',
  )
  assert.equal(
    platformAudience('https://agent.kk.example:8443', 43114),
    'https://agent.kk.example:8443/authz/43114',
  )
  // The chain id separates deployments of one platform.
  assert.notEqual(
    platformAudience('https://agent.kk.example', 43113),
    platformAudience('https://agent.kk.example', 43114),
  )
})

await check('dpopHtu vectors match the reference implementation derivation', () => {
  assert.equal(
    dpopHtu('https://agent.kk.example'),
    'https://agent.kk.example/v1/sessions/oauth-response',
  )
})

await check('one deployment has ONE audience whatever the origin spelling', () => {
  for (const spelling of [
    'https://Agent.KK.Example/',
    'HTTPS://agent.kk.example',
    '  https://agent.kk.example  ',
  ]) {
    assert.equal(
      platformAudience(spelling, 43113),
      'https://agent.kk.example/authz/43113',
      spelling,
    )
    assert.equal(dpopHtu(spelling), 'https://agent.kk.example/v1/sessions/oauth-response')
  }
})

console.log(`\nDPoP helper: ${passed}/${passed} passed`)
