// Holder proof-of-possession (F1) + nonce/replay binding (F4) for the verifier.
//
// When a verifier runs with `require_holder_binding`, presenting credentials is not
// enough: the presenter must prove control of the holder DID's `authentication` key over
//   * a fresh single-use server nonce (POST /v1/nonce)  — anti-replay,
//   * this verifier's audience (its token `iss`)         — anti cross-verifier replay,
//   * a commitment to the exact ordered credentials      — so a captured proof can't be
//     reused with a different credential set,
//   * optionally the slot id + action the nonce was bound to (per-resource / action).
//
// This stays product-agnostic: the consumer brings the holder key (or a sign callback —
// e.g. an HSM / browser wallet). The SDK never persists it. Browser-safe (no Buffer).

import {ed25519} from '@noble/curves/ed25519'
import {sha256} from '@noble/hashes/sha256'
import {httpError} from '../errors.js'

function base(url: string): string {
  return url.replace(/\/$/, '')
}

/** base64url (no padding) of raw bytes — browser + Node safe via btoa. */
function b64urlBytes(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64urlString(s: string): string {
  return b64urlBytes(new TextEncoder().encode(s))
}

/**
 * `base64url(sha256(credentials joined by "\n"))`.
 *
 * MUST byte-for-byte match the verifier's `credentials_commitment`
 * (the reference holder-proof implementation). Order-sensitive and delimiter-framed so both
 * sides agree without JSON canonicalization. Binds a holder proof to the exact set of
 * compact-JWS credentials being presented.
 */
export function credentialsCommitment(credentials: string[]): string {
  return b64urlBytes(sha256(new TextEncoder().encode(credentials.join('\n'))))
}

export interface HolderNonce {
  nonce: string
  /** Expiry, Unix seconds. */
  expiresAt: number
  /** The slot's DCQL rule (present only for public-disclosure slots). */
  dcqlRule?: string
  /** The salt used in the rule's on-chain commitment (present with dcqlRule). */
  dcqlSalt?: string
  /** Rule version counter (present with dcqlRule). */
  ruleVersion?: number
}

/**
 * Mint a single-use challenge nonce, optionally bound to a slot id + action (F4).
 * POST {verifier}/v1/nonce
 */
export async function fetchHolderNonce(
  verifierUrl: string,
  opts?: {slotId?: string; action?: string},
): Promise<HolderNonce> {
  const url = `${base(verifierUrl)}/v1/nonce`
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({slot_id: opts?.slotId, action: opts?.action}),
  })
  if (!res.ok) throw await httpError(res, url, 'v1/nonce')
  const b = (await res.json()) as {
    nonce: string
    expires_at: number
    dcql_rule?: string
    dcql_salt?: string
    rule_version?: number
  }
  const out: HolderNonce = {nonce: b.nonce, expiresAt: b.expires_at}
  if (b.dcql_rule !== undefined) out.dcqlRule = b.dcql_rule
  if (b.dcql_salt !== undefined) out.dcqlSalt = b.dcql_salt
  if (b.rule_version !== undefined) out.ruleVersion = b.rule_version
  return out
}

/**
 * A signer for the holder DID's `authentication` key. Either the SDK holds the raw
 * Ed25519 secret, or the caller supplies a `sign` callback (HSM / wallet / WebCrypto)
 * that returns the raw JWS signature bytes for the given signing input.
 */
export type HolderSigner =
  | {alg: 'EdDSA'; did: string; secretKey: Uint8Array; kid?: string}
  | {
      alg: 'EdDSA' | 'ES256'
      did: string
      sign: (signingInput: Uint8Array) => Uint8Array | Promise<Uint8Array>
      kid?: string
    }

export interface BuildHolderProofOpts {
  signer: HolderSigner
  /** The verifier's expected audience (its token `iss`). */
  audience: string
  /** The challenge from {@link fetchHolderNonce}. */
  nonce: string
  /** The exact compact-JWS credentials being presented, in order. */
  credentials: string[]
  /** Echo the nonce's slot binding (when the nonce was slot-bound). */
  slotId?: string
  /** Echo the nonce's action binding. */
  action?: string
  /** Proof lifetime, seconds (default 300). */
  ttlSecs?: number
  /** Override `iat` (Unix seconds) — for tests. */
  nowSecs?: number
}

/** Build a holder-proof compact-JWS (header.payload.signature). */
export async function buildHolderProof(opts: BuildHolderProofOpts): Promise<string> {
  const now = opts.nowSecs ?? Math.floor(Date.now() / 1000)
  const header: Record<string, unknown> = {alg: opts.signer.alg, typ: 'JWT'}
  if (opts.signer.kid) header.kid = opts.signer.kid
  const payload: Record<string, unknown> = {
    iss: opts.signer.did,
    aud: opts.audience,
    iat: now,
    exp: now + (opts.ttlSecs ?? 300),
    nonce: opts.nonce,
    vp_hash: credentialsCommitment(opts.credentials),
  }
  if (opts.slotId) payload.slot_id = opts.slotId
  if (opts.action) payload.action = opts.action

  const signingInput = `${b64urlString(JSON.stringify(header))}.${b64urlString(JSON.stringify(payload))}`
  const inputBytes = new TextEncoder().encode(signingInput)

  let sig: Uint8Array
  if ('secretKey' in opts.signer) {
    if (opts.signer.alg !== 'EdDSA') {
      throw new Error('buildHolderProof: a raw secretKey signer only supports EdDSA')
    }
    sig = ed25519.sign(inputBytes, opts.signer.secretKey)
  } else {
    sig = await opts.signer.sign(inputBytes)
  }
  return `${signingInput}.${b64urlBytes(sig)}`
}

/**
 * Convenience: fetch a nonce and build the holder proof in one step. Returns the
 * compact-JWS to put in the `holder_proof` field of a `verify-vp-jwt` /
 * `committee-authorize` request.
 */
export async function createHolderProof(
  verifierUrl: string,
  opts: {
    signer: HolderSigner
    audience: string
    credentials: string[]
    slotId?: string
    action?: string
    ttlSecs?: number
  },
): Promise<string> {
  const {nonce} = await fetchHolderNonce(verifierUrl, {slotId: opts.slotId, action: opts.action})
  return buildHolderProof({
    signer: opts.signer,
    audience: opts.audience,
    nonce,
    credentials: opts.credentials,
    slotId: opts.slotId,
    action: opts.action,
    ttlSecs: opts.ttlSecs,
  })
}

/** A did:key identifier for an Ed25519 public key (multicodec 0xed01, base58btc). Useful
 *  when the holder is identified by a self-certifying did:key. */
export function ed25519DidKey(publicKey: Uint8Array): string {
  // multibase base58btc('z') prefix; multicodec 0xed 0x01 || 32-byte key.
  const data = new Uint8Array(2 + publicKey.length)
  data[0] = 0xed
  data[1] = 0x01
  data.set(publicKey, 2)
  return `did:key:z${base58btc(data)}`
}

// Minimal base58btc (Bitcoin alphabet) for did:key. Kept local + dependency-free.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function base58btc(bytes: Uint8Array): string {
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++
  const digits: number[] = []
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]!
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8
      digits[j] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }
  let out = '1'.repeat(zeros)
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]!]
  return out
}
