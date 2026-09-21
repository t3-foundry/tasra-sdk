// OID4VP primitives — the derivations, the key encodings and every guard around them.
//
// test/oid4vp.wallet.ts drives the happy path end to end against known-answer vectors.
// What was left uncovered is the part that decides whether a MALFORMED input is rejected
// or silently accepted, which for a credential parser is the half that matters: a wallet
// takes these bytes from a QR code, a remote JAR and a stored credential, none of which it
// controls.
//
// Two groups are worth more than their line count:
//
//   • `payloadDigestFor` dispatches per action, and the actions disagree about which input
//     they digest. Handing it the wrong one must be an error, not a digest over the wrong
//     bytes — the keeper recomputes this at `enforce_request_binding`, so a wrong digest is
//     a refusal that looks like an authorization failure.
//   • `decryptPayloadDigest` EXCLUDES the AEAD nonce deliberately (it is not authorised
//     content) and length-prefixes both fields. Both properties are asserted, because a
//     concatenation without prefixes lets two different (u, ct) pairs collide.
//
// Run: tsx test/oid4vp.primitives.ts — exits non-zero on any failure.

import {ed25519} from '@noble/curves/ed25519'
import {p256} from '@noble/curves/p256'
import {sha256} from '@noble/hashes/sha256'
import {
  COMMITTEE_ACTIONS,
  decryptPayloadDigest,
  derivedNonce,
  payloadDigestFor,
  requestHash,
  type CommitteeAction,
  type NonceContext,
} from '../src/oid4vp/binding.ts'
import {didWebUrl, resolveDidWeb, verificationKey, type DidDocument} from '../src/oid4vp/did-web.ts'
import {
  b64url,
  b64urlDecode,
  base58Decode,
  base58Encode,
  ed25519DidKey,
  ed25519FromDidKey,
  ed25519HolderKey,
  holderSigner,
  jwkFromDid,
  p256DidKey,
  p256HolderKey,
  signCompactJws,
  utf8,
  verifyCompactJws,
  type Jwk,
} from '../src/oid4vp/jose.ts'
import {concatKdf, decryptJwe, encryptJwe} from '../src/oid4vp/jwe.ts'
import {
  didJwkIssuer,
  holderCnf,
  issueSdJwtVc,
  parseSdJwt,
  peekSdJwt,
  presentSdJwt,
  verifyKbJwt,
} from '../src/oid4vp/sd-jwt.ts'
import {
  PRESENTATION_EIP712_NAME,
  VerifierAgentSessionError,
  presentationOperationTypedData,
  verifierAgentResult,
  verifierAgentVerifierProofs,
} from '../src/oid4vp/verifier-agent.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean, detail = ''): void {
  if (cond) passed++
  else failures.push(name + (detail ? ` — ${detail}` : ''))
}
function eq(name: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual)
  const b = JSON.stringify(expected)
  ok(name, a === b, `got ${a}, want ${b}`)
}
function throwsWith(name: string, re: RegExp, run: () => unknown): void {
  try {
    run()
    ok(name, false, 'did not throw')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    ok(name, re.test(message), `message was ${JSON.stringify(message)}`)
  }
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
const hex = (b: Uint8Array): string => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')
const fill = (n: number, v: number): Uint8Array => new Uint8Array(n).fill(v)

// ─── request binding: size guards ─────────────────────────────────────────────
{
  const slot = fill(32, 0xcd)
  const digest = fill(32, 0x11)
  // These sizes are load-bearing: the preimage is fixed-width at both fields, so a short
  // input would shift everything after it and produce a hash nothing else computes.
  throwsWith('requestHash rejects a short slot id', /slotId must be 32 bytes/, () => requestHash(1, fill(31, 1), 'sign', digest))
  throwsWith('requestHash rejects a long slot id', /slotId must be 32 bytes/, () => requestHash(1, fill(33, 1), 'sign', digest))
  throwsWith('requestHash rejects a short payload digest', /payloadDigest must be 32 bytes/, () => requestHash(1, slot, 'sign', fill(31, 1)))

  // The action is length-prefixed, so two actions cannot collide by concatenation.
  const hashes = new Set(COMMITTEE_ACTIONS.map(a => hex(requestHash(1, slot, a, digest))))
  eq('every committee action yields a distinct request hash', hashes.size, COMMITTEE_ACTIONS.length)
  // The chain id is in the preimage, so the same request on another chain is a different hash.
  ok('the chain id changes the request hash', hex(requestHash(1, slot, 'sign', digest)) !== hex(requestHash(2, slot, 'sign', digest)))
  ok('a bigint chain id matches the number form', hex(requestHash(43113n, slot, 'sign', digest)) === hex(requestHash(43113, slot, 'sign', digest)))
}

// ─── derivedNonce: size guards + field sensitivity ────────────────────────────
{
  const reqHash = fill(32, 0x22)
  const random = fill(32, 0x33)
  const ctx: NonceContext = {epoch: 7, snapshotRoot: fill(32, 0x44), registrySize: 5, committee: 3, quorum: 2, operationExp: 1_700_000_000}
  const base = derivedNonce(reqHash, random, ctx)
  throwsWith('derivedNonce rejects a short reqHash', /reqHash must be 32 bytes/, () => derivedNonce(fill(31, 1), random, ctx))
  throwsWith('derivedNonce rejects a short random', /random must be 32 bytes/, () => derivedNonce(reqHash, fill(31, 1), ctx))
  throwsWith('derivedNonce rejects a short snapshotRoot', /snapshotRoot must be 32 bytes/, () =>
    derivedNonce(reqHash, random, {...ctx, snapshotRoot: fill(31, 1)}),
  )
  // ⚠ EVERY context field is authenticated: changing any of them needs a new wallet proof,
  // so each must move the nonce. A field silently left out of the preimage would let a
  // proof be replayed under different committee parameters.
  const variants: Array<[string, NonceContext]> = [
    ['epoch', {...ctx, epoch: 8}],
    ['snapshotRoot', {...ctx, snapshotRoot: fill(32, 0x45)}],
    ['registrySize', {...ctx, registrySize: 6}],
    ['committee', {...ctx, committee: 4}],
    ['quorum', {...ctx, quorum: 3}],
    ['operationExp', {...ctx, operationExp: 1_700_000_001}],
  ]
  for (const [field, v] of variants) {
    ok(`derivedNonce changes when ${field} changes`, derivedNonce(reqHash, random, v) !== base)
  }
  ok('the nonce is base64url (no padding, url-safe alphabet)', /^[A-Za-z0-9_-]+$/.test(base))
  // A negative operation expiry is encoded as a two's-complement u64, not rejected.
  ok('a negative operationExp encodes rather than throwing', typeof derivedNonce(reqHash, random, {...ctx, operationExp: -1}) === 'string')
  ok('bigint and number epochs agree', derivedNonce(reqHash, random, {...ctx, epoch: 7n}) === base)
}

// ─── payloadDigestFor: per-action dispatch ────────────────────────────────────
{
  const message = utf8('the message')
  const identity = 'did:example:alice/imaging'
  const explicit = fill(32, 0x55)

  eq('sign digests the message with sha256', hex(payloadDigestFor('sign', {message})), hex(sha256(message)))
  eq('ibe-extract digests the identity STRING', hex(payloadDigestFor('ibe-extract', {identity})), hex(sha256(utf8(identity))))
  // decrypt and dual-approve take the digest the caller already holds.
  eq('decrypt takes the supplied digest', hex(payloadDigestFor('decrypt', {payloadDigest: explicit})), hex(explicit))
  eq('dual-approve takes the supplied digest', hex(payloadDigestFor('dual-approve', {payloadDigest: explicit})), hex(explicit))
  // An empty identity is a VALUE, not a missing input — `''` must digest, not fall through.
  eq('an empty identity still digests', hex(payloadDigestFor('ibe-extract', {identity: ''})), hex(sha256(utf8(''))))

  // ⚠ Handing an action the wrong input must be an error. Falling through to a digest over
  // different bytes would produce a request the keeper refuses at binding enforcement,
  // which reads as an authorization failure rather than a caller mistake.
  for (const action of ['sign', 'ibe-extract', 'decrypt', 'dual-approve'] satisfies CommitteeAction[]) {
    throwsWith(`${action} with no usable input names the action`, new RegExp(`payloadDigestFor\\(${action}\\): missing the input`), () =>
      payloadDigestFor(action, {}),
    )
  }
  throwsWith('sign given only an identity is refused', /missing the input/, () => payloadDigestFor('sign', {identity}))
  throwsWith('ibe-extract given only a message is refused', /missing the input/, () => payloadDigestFor('ibe-extract', {message}))
  throwsWith('a wrong-length explicit digest is refused', /payloadDigest must be 32 bytes/, () =>
    payloadDigestFor('decrypt', {payloadDigest: fill(31, 1)}),
  )
  // An explicit digest is the fallback for sign too, when the caller has it already.
  eq('sign accepts an explicit digest when it has no message', hex(payloadDigestFor('sign', {payloadDigest: explicit})), hex(explicit))
}

// ─── decryptPayloadDigest ─────────────────────────────────────────────────────
{
  const u = fill(96, 0x66)
  const ct = fill(48, 0x77)
  const digest = decryptPayloadDigest(u, ct)
  eq('the decrypt digest is 32 bytes', digest.length, 32)
  // ⚠ Length prefixes: without them, (u ‖ ct) for one split equals another split of the
  // same bytes, so two different ciphertexts would authorise interchangeably.
  ok(
    'moving the boundary between u and ct changes the digest',
    hex(decryptPayloadDigest(fill(97, 0x66), fill(47, 0x77))) !== hex(digest),
  )
  ok('a different u changes the digest', hex(decryptPayloadDigest(fill(96, 0x67), ct)) !== hex(digest))
  ok('a different ciphertext changes the digest', hex(decryptPayloadDigest(u, fill(48, 0x78))) !== hex(digest))
  // ⚠ The AEAD nonce is NOT in the preimage: it is not authorised content. Nothing to
  // assert directly, so this pins the signature — the function takes exactly two inputs.
  eq('decryptPayloadDigest takes only u and the ciphertext', decryptPayloadDigest.length, 2)
  eq('empty inputs still produce a digest', decryptPayloadDigest(new Uint8Array(), new Uint8Array()).length, 32)
}

// ─── did:key / did:jwk encodings ──────────────────────────────────────────────
{
  const edPub = ed25519.getPublicKey(fill(32, 0x01))
  const did = ed25519DidKey(edPub)
  ok('ed25519DidKey produces a z6Mk… did:key', /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/.test(did))
  eq('ed25519FromDidKey round-trips the key', hex(ed25519FromDidKey(did)), hex(edPub))
  // jwkFromDid must agree with the dedicated decoder, or a JAR verifies under one and not
  // the other.
  const jwk = jwkFromDid(did)
  eq('jwkFromDid agrees with ed25519FromDidKey', hex(b64urlDecode((jwk as {x: string}).x)), hex(edPub))
  eq('jwkFromDid yields an OKP Ed25519 key', [jwk.kty, (jwk as {crv: string}).crv], ['OKP', 'Ed25519'])
  eq('a #fragment is ignored', JSON.stringify(jwkFromDid(`${did}#0`)), JSON.stringify(jwk))

  throwsWith('ed25519FromDidKey rejects a non-did:key', /not a base58btc did:key/, () => ed25519FromDidKey('did:web:example.com'))
  // A P-256 did:key is a valid did:key but NOT an Ed25519 one — the error has to say so
  // rather than returning 32 bytes of the wrong curve.
  const p256Did = p256DidKey(p256.getPublicKey(fill(32, 0x02), false))
  throwsWith('ed25519FromDidKey rejects a P-256 did:key', /not an Ed25519 key/, () => ed25519FromDidKey(p256Did))
  const p256Jwk = jwkFromDid(p256Did)
  eq('jwkFromDid decodes a P-256 did:key to an EC JWK', [p256Jwk.kty, (p256Jwk as {crv: string}).crv], ['EC', 'P-256'])
  ok('the P-256 JWK carries both coordinates', !!(p256Jwk as {x?: string}).x && !!(p256Jwk as {y?: string}).y)

  throwsWith('an unsupported multicodec is named', /unsupported did:key multicodec/, () =>
    jwkFromDid(`did:key:z${base58Encode(new Uint8Array([0x99, 0x99, 1, 2, 3]))}`),
  )
  throwsWith('a did method with no offline key is refused by method name', /cannot derive a key offline from did:web/, () =>
    jwkFromDid('did:web:example.com'),
  )
  // did:jwk carries the JWK inline.
  const inline = {kty: 'OKP', crv: 'Ed25519', x: b64url(edPub)} satisfies Jwk
  eq('a did:jwk decodes to its inline JWK', JSON.stringify(jwkFromDid(`did:jwk:${b64url(JSON.stringify(inline))}`)), JSON.stringify(inline))

  // base58 round trip + rejection of an out-of-alphabet character.
  eq('base58 round-trips arbitrary bytes', hex(base58Decode(base58Encode(fill(20, 0xab)))), hex(fill(20, 0xab)))
  eq('base58 preserves leading zero bytes', hex(base58Decode(base58Encode(new Uint8Array([0, 0, 7])))), '000007')
  throwsWith('base58 rejects a character outside the alphabet', /bad base58/, () => base58Decode('abc0def'))
}

// ─── compact JWS ──────────────────────────────────────────────────────────────
{
  const holder = p256HolderKey(fill(32, 0x03))
  const jws = signCompactJws({typ: 'JWT'}, {sub: 'alice'}, {alg: 'ES256', privateKey: holder.privateKey})
  eq('a P-256 JWS verifies and returns its claims', verifyCompactJws<{sub: string}>(jws, holder.publicJwk).payload.sub, 'alice')
  const ed = ed25519HolderKey(fill(32, 0x04))
  const edJws = signCompactJws({typ: 'JWT'}, {sub: 'bob'}, {alg: 'EdDSA', privateKey: ed.privateKey})
  eq('an EdDSA JWS verifies', verifyCompactJws<{sub: string}>(edJws, ed.publicJwk).payload.sub, 'bob')

  throwsWith('a non-compact JWS is refused', /not a compact JWS/, () => verifyCompactJws('a.b', holder.publicJwk))
  // ⚠ The alg must match the KEY TYPE. Verifying an EdDSA token against an EC key (or the
  // reverse) must be refused rather than attempted — an alg/key confusion is how a
  // signature check gets skipped entirely.
  throwsWith('an EdDSA token against an EC key is refused', /does not match the key type EC/, () =>
    verifyCompactJws(edJws, holder.publicJwk),
  )
  throwsWith('an ES256 token against an OKP key is refused', /does not match the key type OKP/, () =>
    verifyCompactJws(jws, ed.publicJwk),
  )
  throwsWith('a tampered payload fails verification', /./, () => {
    const [h, , s] = jws.split('.')
    return verifyCompactJws(`${h!}.${b64url(JSON.stringify({sub: 'mallory'}))}.${s!}`, holder.publicJwk)
  })
  // The size guard is at the holder-key constructor, which is where a caller's bytes enter.
  throwsWith('a short P-256 private key is refused at the key constructor', /P-256 private key must be 32 bytes/, () =>
    p256HolderKey(fill(31, 1)),
  )
}

// ─── JWE (ECDH-ES on P-256) ───────────────────────────────────────────────────
{
  const recipientPriv = p256.utils.randomPrivateKey()
  const recipientPub = p256.getPublicKey(recipientPriv, false)
  const recipient = {kty: 'EC' as const, crv: 'P-256' as const, x: b64url(recipientPub.slice(1, 33)), y: b64url(recipientPub.slice(33, 65)), kid: 'agent-key-1'}

  for (const enc of ['A256GCM', 'A128GCM'] as const) {
    const jwe = encryptJwe('{"vp_token":1}', recipient, enc)
    eq(`${enc}: round-trips`, decryptJwe(jwe, recipientPriv), '{"vp_token":1}')
    eq(`${enc}: compact form is 5 dot-separated parts`, jwe.split('.').length, 5)
    eq(`${enc}: the encrypted-key part is empty for ECDH-ES`, jwe.split('.')[1], '')
    const header = JSON.parse(Buffer.from(jwe.split('.')[0]!, 'base64url').toString()) as {enc: string; alg: string; kid?: string}
    eq(`${enc}: the header names the alg and enc`, [header.alg, header.enc], ['ECDH-ES', enc])
    eq(`${enc}: the recipient kid is echoed`, header.kid, 'agent-key-1')
  }
  // A fresh sender key per call, so two encryptions of the same plaintext differ.
  ok('each encryption uses a fresh ephemeral key', encryptJwe('x', recipient) !== encryptJwe('x', recipient))
  eq('no kid is emitted when the recipient key has none', JSON.parse(Buffer.from(encryptJwe('x', {kty: 'EC', crv: 'P-256', x: recipient.x, y: recipient.y}).split('.')[0]!, 'base64url').toString() ).kid, undefined)

  throwsWith('a non-P-256 recipient is refused', /JWE recipient must be an EC P-256 key/, () =>
    encryptJwe('x', {kty: 'OKP', crv: 'Ed25519', x: 'AA'} as never),
  )
  const good = encryptJwe('secret', recipient)
  throwsWith('a JWE with the wrong part count is named', /JWE must have 5 parts, got 3/, () => decryptJwe('a.b.c', recipientPriv))
  throwsWith('a non-empty encrypted-key part is refused', /encrypted-key part must be empty/, () => {
    const p = good.split('.')
    return decryptJwe([p[0], 'AAAA', p[2], p[3], p[4]].join('.'), recipientPriv)
  })
  const reheader = (h: Record<string, unknown>): string => [b64url(JSON.stringify(h)), '', ...good.split('.').slice(2)].join('.')
  throwsWith('an unsupported alg is named', /unsupported JWE alg RSA-OAEP/, () => decryptJwe(reheader({alg: 'RSA-OAEP', enc: 'A256GCM', epk: {}}), recipientPriv))
  throwsWith('an unsupported enc is named', /unsupported JWE enc A192GCM/, () => decryptJwe(reheader({alg: 'ECDH-ES', enc: 'A192GCM', epk: {}}), recipientPriv))
  throwsWith('a missing epk is named', /missing epk/, () => decryptJwe(reheader({alg: 'ECDH-ES', enc: 'A256GCM'}), recipientPriv))
  // The header is the AEAD's associated data, so swapping it must fail the tag rather than
  // decrypt to something else.
  throwsWith('a tampered header fails the AEAD tag', /./, () => {
    const p = good.split('.')
    const h = JSON.parse(Buffer.from(p[0]!, 'base64url').toString()) as Record<string, unknown>
    return decryptJwe([b64url(JSON.stringify({...h, extra: 1})), '', p[2], p[3], p[4]].join('.'), recipientPriv)
  })
  throwsWith('the wrong recipient key fails', /./, () => decryptJwe(good, p256.utils.randomPrivateKey()))

  // Concat KDF: a different alg/length must derive a different key (it is the only thing
  // separating A128GCM from A256GCM key material).
  const z = fill(32, 0x88)
  ok('concatKdf is alg-separated', hex(concatKdf(z, 'A256GCM', new Uint8Array(), new Uint8Array(), 32)) !== hex(concatKdf(z, 'A128GCM', new Uint8Array(), new Uint8Array(), 32)))
  eq('concatKdf honours the requested length', concatKdf(z, 'A128GCM', new Uint8Array(), new Uint8Array(), 16).length, 16)
  eq('concatKdf can span more than one SHA-256 block', concatKdf(z, 'A256GCM', new Uint8Array(), new Uint8Array(), 48).length, 48)
}

// ─── SD-JWT parsing, presentation and KB-JWT guards ───────────────────────────
{
  const issuerKey = p256HolderKey(fill(32, 0x05))
  const issuer = didJwkIssuer(issuerKey.privateKey)
  const holder = p256HolderKey(fill(32, 0x06))
  const vc = issueSdJwtVc({
    issuer,
    vct: 'https://example.com/EmployeeCard',
    claims: {given_name: 'Alice', dept: 'Engineering', level: 7},
    cnf: holderCnf(holder),
    sub: holder.did,
    nowSecs: 1_000,
    ttlSecs: 9_000_000,
  })

  const parsed = parseSdJwt(vc)
  ok('a freshly issued VC parses', parsed.disclosures.length === 3)
  const peeked = peekSdJwt(vc)
  eq('peekSdJwt reads vct/exp/sub without verifying', [peeked.vct, peeked.exp, peeked.sub], ['https://example.com/EmployeeCard', 9_001_000, holder.did])
  ok('peekSdJwt reports the issuer DID', typeof peeked.iss === 'string' && peeked.iss.startsWith('did:jwk:'))

  throwsWith('a first segment that is not a compact JWS is refused', /first segment is not a compact JWS/, () => parseSdJwt('nope~'))
  throwsWith('an empty input is refused', /first segment is not a compact JWS/, () => parseSdJwt(''))
  // A trailing segment is either empty (no KB-JWT) or a compact JWS. Anything else is
  // malformed and must not be treated as a disclosure.
  throwsWith('a trailing segment that is neither empty nor a KB-JWT is refused', /neither empty nor a KB-JWT/, () =>
    parseSdJwt(`${vc}garbage`),
  )
  throwsWith('a disclosure that is not [salt, name, value] is refused', /disclosure is not \[salt, name, value\]/, () => {
    const [jwt] = vc.split('~')
    return parseSdJwt(`${jwt!}~${b64url(JSON.stringify(['only-two', 'parts']))}~`)
  })
  throwsWith('didJwkIssuer refuses a non-ES256 alg', /only P-256 \/ ES256 is supported/, () =>
    didJwkIssuer(issuerKey.privateKey, 'EdDSA'),
  )

  // Presentation + KB-JWT.
  const presentation = presentSdJwt({parsed, disclose: ['given_name'], holder, nonce: 'nonce-1', aud: 'client-1', nowSecs: 2_000})
  const verified = verifyKbJwt(presentation, {nonce: 'nonce-1', aud: 'client-1'})
  eq('the KB-JWT verifies against its nonce and audience', verified.claims.nonce, 'nonce-1')
  // Selective disclosure: exactly what was asked for, nothing else.
  const shown = parseSdJwt(presentation).disclosures.map(d => d.name)
  eq('only the disclosed claim travels', shown, ['given_name'])

  throwsWith('a presentation with no KB-JWT is refused', /carries no KB-JWT/, () =>
    verifyKbJwt(vc, {nonce: 'nonce-1', aud: 'client-1'}),
  )
  // ⚠ sd_hash binds the KB-JWT to the exact disclosure set. Adding or removing a
  // disclosure after signing must break it, or a holder could present more (or fewer)
  // claims than they bound to.
  throwsWith('adding a disclosure after binding breaks sd_hash', /sd_hash mismatch/, () => {
    const parts = presentation.split('~')
    const kb = parts.pop()!
    const extra = parseSdJwt(vc).disclosures.find(d => d.name === 'dept')!.encoded
    return verifyKbJwt([...parts, extra, kb].join('~'), {nonce: 'nonce-1', aud: 'client-1'})
  })
  // ⚠ The typ check has to be reached on a VALIDLY SIGNED token, so the replacement KB-JWT
  // is re-signed by the holder rather than re-headered. Swapping the header alone breaks
  // the signature, and the test would then pass on the wrong error — asserting that a
  // forged token is rejected, while saying nothing about whether `typ` is checked at all.
  throwsWith('a validly-signed KB-JWT with the wrong typ is still refused', /KB-JWT typ must be kb\+jwt/, () => {
    const parts = presentation.split('~')
    const kb = parts.pop()!
    const claims = JSON.parse(Buffer.from(kb.split('.')[1]!, 'base64url').toString()) as Record<string, unknown>
    const forged = signCompactJws({typ: 'jwt'}, claims, holderSigner(holder))
    return verifyKbJwt([...parts, forged].join('~'), {nonce: 'nonce-1', aud: 'client-1'})
  })
  // A cnf that is present but carries neither a jwk nor a kid names nothing to verify
  // against, so it must be refused rather than fall through to an undefined key.
  throwsWith('a cnf with neither jwk nor kid is refused', /cnf has neither jwk nor kid/, () => {
    const empty = issueSdJwtVc({issuer, vct: 'x', claims: {a: 1}, nowSecs: 1_000, cnf: {} as unknown as {kid: string}})
    const p = parseSdJwt(empty)
    return verifyKbJwt(presentSdJwt({parsed: p, disclose: ['a'], holder, nonce: 'n', aud: 'c', nowSecs: 2_000}), {nonce: 'n', aud: 'c'})
  })
  // A credential with no cnf cannot be key-bound at all. `cnf` is required by the type, so
  // omitting it here is deliberate — this is the malformed credential a wallet might be
  // handed, not a shape the SDK can mint by accident.
  const noCnf = issueSdJwtVc({issuer, vct: 'x', claims: {a: 1}, nowSecs: 1_000, cnf: undefined as unknown as {kid: string}})
  throwsWith('a credential with no cnf cannot be KB-verified', /no cnf claim/, () => {
    const p = parseSdJwt(noCnf)
    const pres = presentSdJwt({parsed: p, disclose: ['a'], holder, nonce: 'n', aud: 'c', nowSecs: 2_000})
    return verifyKbJwt(pres, {nonce: 'n', aud: 'c'})
  })
}

// ─── did:web ──────────────────────────────────────────────────────────────────
{
  eq('a host-only did:web resolves to /.well-known/did.json', didWebUrl('did:web:agent.example'), 'https://agent.example/.well-known/did.json')
  // The path form drops .well-known — a different URL entirely, per the method spec.
  eq('a path did:web resolves without /.well-known', didWebUrl('did:web:agent.example:tenants:acme'), 'https://agent.example/tenants/acme/did.json')
  eq('a percent-encoded port is decoded', didWebUrl('did:web:localhost%3A8443'), 'https://localhost:8443/.well-known/did.json')
  eq('a #fragment is ignored when resolving', didWebUrl('did:web:agent.example#z6Mk'), 'https://agent.example/.well-known/did.json')
  throwsWith('a non-did:web is refused', /not a did:web/, () => didWebUrl('did:key:z6Mk'))

  const edPub = ed25519.getPublicKey(fill(32, 0x07))
  const keyDid = ed25519DidKey(edPub)
  const doc: DidDocument = {
    id: 'did:web:agent.example',
    verificationMethod: [
      {id: `did:web:agent.example#${keyDid.slice('did:key:'.length)}`, publicKeyJwk: {kty: 'OKP', crv: 'Ed25519', x: b64url(edPub)}},
      {id: 'did:web:agent.example#verifier-1', publicKeyMultibase: keyDid.slice('did:key:'.length)},
      {id: 'did:web:agent.example#empty'},
    ],
  }
  // ⚠ Named by KEY since the set document became roster-derived, so a join/leave never
  // changes what a fragment means. Both encodings must resolve, by full URL or fragment.
  ok('a key-named verification method resolves by full id', !!verificationKey(doc, `did:web:agent.example#${keyDid.slice('did:key:'.length)}`))
  ok('…and by bare fragment', !!verificationKey(doc, `#${keyDid.slice('did:key:'.length)}`))
  // The legacy position-named encoding carries the key as multibase instead of a JWK.
  const fromMultibase = verificationKey(doc, '#verifier-1')
  eq('a publicKeyMultibase method decodes to a JWK', hex(b64urlDecode((fromMultibase as {x: string}).x)), hex(edPub))
  throwsWith('an unknown kid names the document', /has no verification method #nope/, () => verificationKey(doc, '#nope'))
  throwsWith('a method with no key material is named', /carries no key material/, () => verificationKey(doc, '#empty'))
  throwsWith('an unsupported multibase codec is named', /unsupported publicKeyMultibase codec/, () =>
    verificationKey({id: 'did:web:x', verificationMethod: [{id: '#k', publicKeyMultibase: base58Encode(new Uint8Array([1, 2, 3, 4]))}]}, '#k'),
  )
  throwsWith('a document with no verification methods at all is refused', /has no verification method/, () =>
    verificationKey({id: 'did:web:x'}, '#k'),
  )

  // Resolution over an injected fetch — no global stubbing needed.
  const serve = (body: unknown, status = 200): typeof fetch =>
    (async () => ({ok: status === 200, status, json: async () => body, text: async () => JSON.stringify(body)})) as unknown as typeof fetch
  eq('resolveDidWeb returns the document', (await resolveDidWeb('did:web:agent.example', {fetchImpl: serve(doc)})).id, 'did:web:agent.example')
  await rejectsWith('a non-200 is reported with the URL and status', /did:web resolution https:\/\/agent\.example\/\.well-known\/did\.json → HTTP 404/, () =>
    resolveDidWeb('did:web:agent.example', {fetchImpl: serve({}, 404)}),
  )
  // ⚠ The document id must equal the DID asked for, or a host could serve someone else's
  // keys under its own URL.
  await rejectsWith('a document whose id does not match the DID is refused', /document id did:web:other != did:web:agent\.example/, () =>
    resolveDidWeb('did:web:agent.example', {fetchImpl: serve({...doc, id: 'did:web:other'})}),
  )
  {
    // allowInsecureLoopback downgrades to http ONLY for a loopback host.
    const seen: string[] = []
    const record = (body: unknown): typeof fetch =>
      (async (u: string) => {
        seen.push(String(u))
        return {ok: true, status: 200, json: async () => body} as unknown as Response
      }) as typeof fetch
    await resolveDidWeb('did:web:localhost%3A8443', {fetchImpl: record({id: 'did:web:localhost%3A8443'}), allowInsecureLoopback: true})
    ok('a loopback host is fetched over http when allowed', seen[0] === 'http://localhost:8443/.well-known/did.json')
    seen.length = 0
    await resolveDidWeb('did:web:agent.example', {fetchImpl: record({id: 'did:web:agent.example'}), allowInsecureLoopback: true})
    ok('a PUBLIC host stays https even with the flag set', seen[0]?.startsWith('https://') === true)
    seen.length = 0
    await resolveDidWeb('did:web:localhost%3A8443', {fetchImpl: record({id: 'did:web:localhost%3A8443'})})
    ok('loopback stays https without the flag', seen[0]?.startsWith('https://') === true)
  }
}

// ─── `plain` claims travel in the clear ───────────────────────────────────────
{
  const issuer = didJwkIssuer(fill(32, 0x0a))
  const holder = p256HolderKey(fill(32, 0x0b))
  const vc = issueSdJwtVc({
    issuer,
    vct: 'https://example.com/Badge',
    claims: {vct_label: 'Staff badge', given_name: 'Alice'},
    plain: ['vct_label'],
    cnf: holderCnf(holder),
    nowSecs: 1_000,
  })
  const parsed = parseSdJwt(vc)
  // ⚠ A `plain` claim is NOT selectively disclosable: it is in the issuer JWT for everyone
  // who sees the credential. Getting this backwards either leaks a claim meant to be
  // withheld, or makes a claim the verifier needs unavailable unless disclosed.
  eq('a plain claim does not become a disclosure', parsed.disclosures.map(d => d.name), ['given_name'])
  eq('a plain claim is in the issuer payload in the clear', parsed.payload.vct_label, 'Staff badge')
  eq('a disclosable claim is NOT in the issuer payload', parsed.payload.given_name, undefined)
  // The _sd digest list covers only the disclosable claims.
  eq('_sd carries one digest per disclosure', (parsed.payload._sd as string[]).length, 1)
}

// ─── the verifier-agent's operation binding + typed session errors ────────────
{
  const slotId = `0x${'cd'.repeat(32)}` as `0x${string}`
  const base = {
    chainId: 43113,
    keyRegistry: `0x${'11'.repeat(20)}` as `0x${string}`,
    action: 'sign' as const,
    message: utf8('sign me'),
    description: 'Sign a document',
    nowSecs: 1_000,
  }
  const built = presentationOperationTypedData({...base, slotId})
  eq('the EIP-712 domain is the Presentation one', built.typedData.domain.name, PRESENTATION_EIP712_NAME)
  eq('the domain names the KeyRegistry as verifyingContract', built.typedData.domain.verifyingContract, base.keyRegistry)
  eq('the chain id is in the domain', built.typedData.domain.chainId, 43113)
  eq('the digest is sha256 of the message', hex(built.payloadDigest), hex(sha256(utf8('sign me'))))
  // ⚠ The verifier-agent's `message_hex` is 0x-PREFIXED, unlike the keeper request bodies
  // (which are bare hex because some node handlers hex-decode directly). Two conventions in
  // one flow, so the value is pinned rather than described.
  eq('message_hex is the 0x-prefixed message', built.messageHex, `0x${hex(utf8('sign me'))}`)
  // For decrypt/dual-approve there is no message, so the DIGEST is what gets stored.
  eq(
    'with no message, message_hex is the digest itself',
    presentationOperationTypedData({...base, slotId, action: 'decrypt', message: undefined, payloadDigest: fill(32, 0x5a)}).messageHex,
    `0x${hex(fill(32, 0x5a))}`,
  )
  // A hex slot id and a byte slot id must produce the same operation.
  eq('a byte slot id matches the hex form', hex(presentationOperationTypedData({...base, slotId: fill(32, 0xcd)}).payloadDigest), hex(built.payloadDigest))
  throwsWith('a short slot id is refused', /slotId must be 32 bytes/, () =>
    presentationOperationTypedData({...base, slotId: fill(31, 0xcd)}),
  )

  // ⚠ A malformed `verifier_proofs` must arrive as a TYPED session error, not a raw one:
  // the caller distinguishes a protocol fault from a refusal, and retries only one of them.
  const requestHashBytes = fill(32, 0x77)
  const session = {sessionId: 'sess-1', requestHash: requestHashBytes}
  const goodToken = {request_hash: `0x${hex(requestHashBytes)}`} as unknown as Parameters<typeof verifierAgentResult>[1]['compoundToken']
  throwsWith('a malformed verifier_proofs becomes a protocol session error', /not \{verifier_index/, () =>
    verifierAgentResult(session, {status: 'done', compoundToken: goodToken, verifierProofs: [{verifier_index: 'x'}]} as never),
  )
  try {
    verifierAgentResult(session, {status: 'done', compoundToken: goodToken, verifierProofs: [{}]} as never)
    ok('the typed error names the session', false, 'did not throw')
  } catch (error) {
    ok('the typed error is a VerifierAgentSessionError', error instanceof VerifierAgentSessionError)
    eq('…of kind protocol', (error as VerifierAgentSessionError).kind, 'protocol')
    eq('…carrying the session id for correlation', (error as VerifierAgentSessionError).correlation, 'sess-1')
  }
  // A token that binds a DIFFERENT request must be refused — that check is the whole point
  // of carrying requestHash through the session.
  throwsWith('a token binding another request is refused', /does not bind the request this session opened/, () =>
    verifierAgentResult(session, {status: 'done', compoundToken: {request_hash: `0x${'00'.repeat(32)}`}} as never),
  )
  throwsWith('a session that is not done is a refusal', /presentation refused/, () =>
    verifierAgentResult(session, {status: 'refused', error: 'the holder declined'} as never),
  )
}

// ─── the verifier-agent's verifier_proofs DTO ─────────────────────────────────
{
  const good = [{verifier_index: 1, operator: '0xabc', pubkey: '0xdef', proof: ['0x11', '0x22']}]
  eq('a well-formed DTO maps to the SDK shape', verifierAgentVerifierProofs(good), [
    {verifierIndex: 1, operator: '0xabc', pubkey: '0xdef', proof: ['0x11', '0x22']},
  ])
  // Absent is not an error — proofs are optional (the keeper falls back to its configured set).
  eq('a non-array is undefined rather than an error', verifierAgentVerifierProofs(undefined), undefined)
  eq('a string is undefined', verifierAgentVerifierProofs('nope'), undefined)
  eq('an empty array maps to an empty list', verifierAgentVerifierProofs([]), [])
  // But a MALFORMED entry must throw: silently dropping one would hand the keeper a
  // proof set that does not cover the token's signers.
  throwsWith('a null entry is refused', /entry is not an object/, () => verifierAgentVerifierProofs([null]))
  throwsWith('a non-numeric index is refused', /not \{verifier_index, operator, pubkey, proof\[\]\}/, () =>
    verifierAgentVerifierProofs([{...good[0]!, verifier_index: '1'}]),
  )
  throwsWith('a missing pubkey is refused', /not \{verifier_index/, () =>
    verifierAgentVerifierProofs([{verifier_index: 1, operator: '0xabc', proof: []}]),
  )
  throwsWith('a proof array holding a non-string is refused', /not \{verifier_index/, () =>
    verifierAgentVerifierProofs([{...good[0]!, proof: ['0x11', 7]}]),
  )
}

if (failures.length > 0) {
  console.error(`✗ oid4vp.primitives: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ oid4vp.primitives: ${passed} checks passed`)
