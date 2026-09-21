// Minimal JOSE plumbing shared by the wallet modules: base64url, compact JWS over ES256 (P-256)
// and EdDSA (Ed25519), JWK ⇄ DID helpers (`did:jwk`, `did:key` for both curves), and the
// holder key shape the Hovi profile uses (a P-256 `did:jwk`, `#0` fragment). Pure noble; runs in
// a browser extension, a PWA and Node alike.

import {ed25519} from '@noble/curves/ed25519'
import {p256} from '@noble/curves/p256'
import {sha256} from '@noble/hashes/sha256'

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s)
export const fromUtf8 = (b: Uint8Array): string => new TextDecoder().decode(b)

export function b64url(bytes: Uint8Array | string): string {
  const b = typeof bytes === 'string' ? utf8(bytes) : bytes
  let bin = ''
  for (const x of b) bin += String.fromCharCode(x)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
export function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad), c => c.charCodeAt(0))
}
export const decodeJson = <T = unknown>(b64: string): T => JSON.parse(fromUtf8(b64urlDecode(b64))) as T

// ─── JWKs + DIDs ────────────────────────────────────────────────────────────────────────

export interface EcJwk {
  kty: 'EC'
  crv: 'P-256'
  x: string
  y: string
  kid?: string
  alg?: string
  use?: string
}
export interface OkpJwk {
  kty: 'OKP'
  crv: 'Ed25519'
  x: string
  kid?: string
}
export type Jwk = EcJwk | OkpJwk

/** A holder key in the shape the Hovi profile presents: `cnf.kid = did:jwk:…#0`. */
export interface HolderKey {
  /** 32 bytes: a P-256 private scalar, or an Ed25519 seed. */
  privateKey: Uint8Array
  publicJwk: Jwk
  /** `did:jwk:<base64url(JSON(publicJwk))>` */
  did: string
}

/**
 * How to sign for this holder. P-256 keys sign ES256, Ed25519 keys EdDSA — a credential is bound to
 * one key, and the KB-JWT it is presented with has to be signed by that key's own algorithm. Issuers
 * outside the P-256 profile exist: `tasra-cli vc issue-sd-jwt` binds an Ed25519 holder key.
 */
export function holderSigner(holder: HolderKey): JwsSigner {
  return {alg: holder.publicJwk.kty === 'OKP' ? 'EdDSA' : 'ES256', privateKey: holder.privateKey}
}

export function p256PublicJwk(privateKey: Uint8Array): EcJwk {
  const pub = p256.getPublicKey(privateKey, false)
  return {kty: 'EC', crv: 'P-256', x: b64url(pub.slice(1, 33)), y: b64url(pub.slice(33, 65))}
}
/** `did:jwk` of a JWK — the JSON is serialised in `kty, crv, x, y` order, the vault's convention. */
export function didJwk(jwk: Jwk): string {
  const canon = jwk.kty === 'EC' ? {kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y} : {kty: jwk.kty, crv: jwk.crv, x: jwk.x}
  return `did:jwk:${b64url(JSON.stringify(canon))}`
}
export function p256HolderKey(privateKey: Uint8Array): HolderKey {
  if (privateKey.length !== 32) throw new Error('P-256 private key must be 32 bytes')
  const publicJwk = p256PublicJwk(privateKey)
  return {privateKey, publicJwk, did: didJwk(publicJwk)}
}
/** An Ed25519 holder key from a 32-byte seed — the shape `tasra-cli vc issue-sd-jwt` binds. */
export function ed25519HolderKey(seed: Uint8Array): HolderKey {
  const publicJwk: OkpJwk = {kty: 'OKP', crv: 'Ed25519', x: b64url(ed25519.getPublicKey(seed))}
  return {privateKey: seed, publicJwk, did: didJwk(publicJwk)}
}

export function randomHolderKey(): HolderKey {
  return p256HolderKey(p256.utils.randomPrivateKey())
}

// base58btc (did:key)
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
export function base58Encode(bytes: Uint8Array): string {
  let n = 0n
  for (const b of bytes) n = (n << 8n) | BigInt(b)
  let out = ''
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out
    n /= 58n
  }
  for (const b of bytes) {
    if (b !== 0) break
    out = '1' + out
  }
  return out
}
export function base58Decode(s: string): Uint8Array {
  let n = 0n
  for (const c of s) {
    const i = B58.indexOf(c)
    if (i < 0) throw new Error('bad base58')
    n = n * 58n + BigInt(i)
  }
  const bytes: number[] = []
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn))
    n >>= 8n
  }
  let zeros = 0
  for (const c of s) {
    if (c !== '1') break
    zeros++
  }
  return new Uint8Array([...new Array<number>(zeros).fill(0), ...bytes])
}

/** `did:key` of an Ed25519 public key (multicodec 0xed01). */
export function ed25519DidKey(publicKey: Uint8Array): string {
  return `did:key:z${base58Encode(new Uint8Array([0xed, 0x01, ...publicKey]))}`
}
/** `did:key` of a P-256 public key (multicodec 0x1200 → varint `80 24`, compressed point) — Hovi's issuer shape. */
export function p256DidKey(publicKeyUncompressedOrCompressed: Uint8Array): string {
  const compressed = p256.ProjectivePoint.fromHex(publicKeyUncompressedOrCompressed).toRawBytes(true)
  return `did:key:z${base58Encode(new Uint8Array([0x80, 0x24, ...compressed]))}`
}
/** The 32-byte Ed25519 key inside a `did:key:z6Mk…`; throws for any other key type. */
export function ed25519FromDidKey(did: string): Uint8Array {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did)
  if (!m) throw new Error('not a base58btc did:key')
  const raw = base58Decode(m[1]!)
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) throw new Error('did:key is not an Ed25519 key')
  return raw.slice(2)
}

/** The public JWK inside a `did:jwk` or a `did:key` (Ed25519 / P-256); a `#fragment` is ignored. */
export function jwkFromDid(did: string): Jwk {
  const bare = did.split('#')[0]!
  if (bare.startsWith('did:jwk:')) return decodeJson<Jwk>(bare.slice('did:jwk:'.length))
  if (bare.startsWith('did:key:z')) {
    const raw = base58Decode(bare.slice('did:key:z'.length))
    if (raw[0] === 0xed && raw[1] === 0x01) return {kty: 'OKP', crv: 'Ed25519', x: b64url(raw.slice(2))}
    if (raw[0] === 0x80 && raw[1] === 0x24) {
      const u = p256.ProjectivePoint.fromHex(raw.slice(2)).toRawBytes(false)
      return {kty: 'EC', crv: 'P-256', x: b64url(u.slice(1, 33)), y: b64url(u.slice(33, 65))}
    }
    throw new Error(`unsupported did:key multicodec 0x${raw[0]?.toString(16)}${raw[1]?.toString(16)}`)
  }
  throw new Error(`cannot derive a key offline from ${bare.split(':').slice(0, 2).join(':')}`)
}

// ─── compact JWS ────────────────────────────────────────────────────────────────────────

export type JwsAlg = 'ES256' | 'EdDSA'
/** A signer for a compact JWS: a raw private key of the named curve. */
export interface JwsSigner {
  alg: JwsAlg
  privateKey: Uint8Array
}

export function signCompactJws(header: Record<string, unknown>, payload: Record<string, unknown>, signer: JwsSigner): string {
  const h = {...header, alg: signer.alg}
  const input = `${b64url(JSON.stringify(h))}.${b64url(JSON.stringify(payload))}`
  const sig = signer.alg === 'ES256'
    ? p256.sign(sha256(utf8(input)), signer.privateKey).toCompactRawBytes()
    : ed25519.sign(utf8(input), signer.privateKey)
  return `${input}.${b64url(sig)}`
}

/** Verify a compact JWS under `jwk` and return its decoded payload; throws on any failure. */
export function verifyCompactJws<T = Record<string, unknown>>(jws: string, jwk: Jwk): {header: Record<string, unknown>; payload: T} {
  const [h, p, s] = jws.split('.')
  if (!h || !p || !s) throw new Error('not a compact JWS')
  const header = decodeJson<Record<string, unknown>>(h)
  const input = utf8(`${h}.${p}`)
  const sig = b64urlDecode(s)
  let ok: boolean
  if (header.alg === 'ES256' && jwk.kty === 'EC') {
    const pub = new Uint8Array([0x04, ...b64urlDecode(jwk.x), ...b64urlDecode(jwk.y)])
    ok = p256.verify(sig, sha256(input), pub)
  } else if (header.alg === 'EdDSA' && jwk.kty === 'OKP') {
    ok = ed25519.verify(sig, input, b64urlDecode(jwk.x))
  } else {
    throw new Error(`JWS alg ${String(header.alg)} does not match the key type ${jwk.kty}`)
  }
  if (!ok) throw new Error('JWS signature does not verify')
  return {header, payload: decodeJson<T>(p)}
}
