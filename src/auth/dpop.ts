// DPoP (RFC 9449) proofs for the Tasra OAuth authorization flow.
//
// TWO CALL SHAPES, and which one you need is decided by WHERE YOUR TOKEN'S KEY LIVES.
// A DPoP proof is only worth anything if its key is the key the access token is bound to
// (`cnf.jkt`), so the proof must be signed by whatever holds that key:
//
//   1. **Your app obtained the token with a key this helper owns** — a plain OAuth client,
//      `oidc-client-ts`, or the fleet test client. Use `createDpopKey()` to mint the
//      non-extractable key, pass its `signer` to the token request, and hand the same
//      `signer` to `submitOauthResponse`.
//
//   2. **An SDK holds the key internally** — `auth0-spa-js` with `useDpop`. It will not
//      hand you the key, but it WILL mint a proof for a URL and nonce you choose
//      (`auth0.generateDpopProof({url, method, nonce, accessToken})`). Wrap that call as a
//      {@link DpopSigner} and pass it through; this file never sees the key.
//
// ⚠ `keycloak-js` has NO released DPoP API (`dpopConfig` exists only in an unreleased PR).
// A Keycloak tenant therefore uses shape 1: obtain the token with a key from
// `createDpopKey()` and reuse it here.
//
// ⚠ The key MUST be non-extractable where the platform allows it. `createDpopKey` asks
// WebCrypto for `extractable: false`, which is what makes a stolen token inert: an attacker
// who exfiltrates the token cannot exfiltrate the key that spends it.

import {TasraError} from '../errors.js'

/** Anything that can produce a DPoP proof for a given request. */
export interface DpopSigner {
  /**
   * Mint a proof binding `accessToken` to `(htm, htu, nonce)`.
   *
   * An implementation MUST sign with the key the access token is bound to; a proof under
   * any other key is refused by every drawn verifier with `DPoP proof jwk is not the key
   * the access token is bound to`.
   */
  proof(args: {htm: string; htu: string; nonce: string; accessToken: string}): Promise<string>
}

const B64URL_ALPHABET_SAFE = /^[A-Za-z0-9\-_]*$/

function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64urlJson(value: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(value)))
}

/** RFC 9449 §4.2 `ath`: base64url(sha256(ASCII(access_token))). */
export async function accessTokenHash(accessToken: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken))
  return b64url(new Uint8Array(digest))
}

/** An ES256 key pair for DPoP, plus a {@link DpopSigner} over it. */
export interface DpopKey {
  /** The public half, as the JWK that rides in every proof header. */
  publicJwk: JsonWebKey
  /** RFC 7638 thumbprint — the value the IdP puts in the token's `cnf.jkt`. */
  thumbprint(): Promise<string>
  signer: DpopSigner
}

/**
 * Mint a fresh ES256 DPoP key.
 *
 * Non-extractable: the private half never leaves WebCrypto, so it cannot be copied out of a
 * compromised page along with the token. That is the entire point of sender constraining.
 */
export async function createDpopKey(): Promise<DpopKey> {
  const pair = await crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, false, [
    'sign',
  ])
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  // A JWK carrying anything beyond the public EC parameters would leak into every proof
  // header; keep exactly what RFC 7638 hashes.
  const header: JsonWebKey = {
    kty: 'EC',
    crv: 'P-256',
    x: publicJwk.x,
    y: publicJwk.y,
  }
  return {
    publicJwk: header,
    async thumbprint() {
      return jwkThumbprint(header)
    },
    signer: {
      async proof({htm, htu, nonce, accessToken}) {
        const protectedHeader = {alg: 'ES256', typ: 'dpop+jwt', jwk: header}
        const payload = {
          htm,
          htu,
          nonce,
          ath: await accessTokenHash(accessToken),
          jti: randomJti(),
          iat: Math.floor(Date.now() / 1000),
        }
        const signingInput = `${b64urlJson(protectedHeader)}.${b64urlJson(payload)}`
        const raw = await crypto.subtle.sign(
          {name: 'ECDSA', hash: 'SHA-256'},
          pair.privateKey,
          new TextEncoder().encode(signingInput),
        )
        return `${signingInput}.${b64url(new Uint8Array(raw))}`
      },
    },
  }
}

/**
 * RFC 7638 JWK thumbprint of an EC P-256 public key.
 *
 * ⚠ The member order is LEXICOGRAPHIC and the JSON has no whitespace — the RFC hashes an
 * exactly specified string, so `JSON.stringify` over an object literal in a different order
 * yields a different thumbprint and the token's `cnf.jkt` would never match.
 */
export async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  if (jwk.kty !== 'EC' || !jwk.crv || !jwk.x || !jwk.y) {
    throw new TasraError('jwkThumbprint: only EC public keys are supported here', {
      retryable: false,
    })
  }
  const canonical = `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  return b64url(new Uint8Array(digest))
}

function randomJti(): string {
  const b = new Uint8Array(16)
  crypto.getRandomValues(b)
  return b64url(b)
}

/**
 * Wrap `auth0-spa-js`'s own proof minter as a {@link DpopSigner}.
 *
 * The SDK holds the key, so this is the ONLY way an Auth0 app can produce a proof whose
 * `jkt` matches its token's `cnf.jkt`.
 *
 * ```ts
 * const signer = auth0DpopSigner((args) => auth0.generateDpopProof(args))
 * ```
 */
export function auth0DpopSigner(
  generate: (args: {
    url: string
    method: string
    nonce?: string
    accessToken?: string
  }) => Promise<string>,
): DpopSigner {
  return {
    async proof({htm, htu, nonce, accessToken}) {
      return generate({url: htu, method: htm, nonce, accessToken})
    },
  }
}

/** Guard for a nonce that can ride in a header (the agent's challenge carries it back). */
export function isHeaderSafeNonce(nonce: string): boolean {
  return nonce.length > 0 && B64URL_ALPHABET_SAFE.test(nonce)
}
