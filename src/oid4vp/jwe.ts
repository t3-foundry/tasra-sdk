// JWE compact serialisation for OID4VP `direct_post.jwt`: ECDH-ES direct key agreement on P-256 +
// A256GCM / A128GCM, Concat KDF per RFC 7518 §4.6.2. Byte-compatible with the Verifier Agent's
// the reference implementation (both directions round-trip in the reference tests and the live fleet).
// Pure noble: `p256` for ECDH, `@noble/ciphers` for AES-GCM.

import {gcm} from '@noble/ciphers/aes'
import {p256} from '@noble/curves/p256'
import {sha256} from '@noble/hashes/sha256'
import {b64url, b64urlDecode, decodeJson, utf8, type EcJwk} from './jose.js'

export type JweEnc = 'A256GCM' | 'A128GCM'

function be32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255])
}
function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

/** Concat KDF (NIST SP 800-56A, single-pass SHA-256) — AlgorithmID = `enc` for ECDH-ES direct. */
export function concatKdf(z: Uint8Array, alg: string, apu: Uint8Array, apv: Uint8Array, keyLen: number): Uint8Array {
  const reps = Math.ceil(keyLen / 32)
  const out: Uint8Array[] = []
  for (let counter = 1; counter <= reps; counter++) {
    const algB = utf8(alg)
    out.push(sha256(cat(be32(counter), z, be32(algB.length), algB, be32(apu.length), apu, be32(apv.length), apv, be32(keyLen * 8))))
  }
  return cat(...out).slice(0, keyLen)
}

function ecdhZ(privateKey: Uint8Array, peer: EcJwk): Uint8Array {
  const peerPub = new Uint8Array([0x04, ...b64urlDecode(peer.x), ...b64urlDecode(peer.y)])
  // The shared secret is the x-coordinate of the ECDH point.
  return p256.getSharedSecret(privateKey, peerPub, true).slice(1, 33)
}

/**
 * Encrypt `plaintext` to the recipient's ephemeral P-256 JWK (the JAR's `client_metadata.jwks.keys[0]`)
 * as `header..iv.ciphertext.tag`. A fresh sender key per call; `kid` echoed when the recipient key has one.
 */
export function encryptJwe(plaintext: string, recipient: EcJwk, enc: JweEnc = 'A256GCM', random: (n: number) => Uint8Array = n => crypto.getRandomValues(new Uint8Array(n))): string {
  if (recipient.kty !== 'EC' || recipient.crv !== 'P-256') throw new Error('JWE recipient must be an EC P-256 key')
  const keyLen = enc === 'A256GCM' ? 32 : 16
  const senderPriv = p256.utils.randomPrivateKey()
  const senderPub = p256.getPublicKey(senderPriv, false)
  const epk = {kty: 'EC', crv: 'P-256', x: b64url(senderPub.slice(1, 33)), y: b64url(senderPub.slice(33, 65))}
  const header: Record<string, unknown> = {alg: 'ECDH-ES', enc, epk, ...(recipient.kid ? {kid: recipient.kid} : {})}
  const headerB64 = b64url(JSON.stringify(header))
  const cek = concatKdf(ecdhZ(senderPriv, recipient), enc, new Uint8Array(), new Uint8Array(), keyLen)
  const iv = random(12)
  const sealed = gcm(cek, iv, utf8(headerB64)).encrypt(utf8(plaintext))
  const ct = sealed.slice(0, sealed.length - 16)
  const tag = sealed.slice(sealed.length - 16)
  return `${headerB64}..${b64url(iv)}.${b64url(ct)}.${b64url(tag)}`
}

/** Decrypt a compact JWE produced by {@link encryptJwe} (or a wallet) with the recipient's private scalar. */
export function decryptJwe(compact: string, recipientPrivateKey: Uint8Array): string {
  const parts = compact.split('.')
  if (parts.length !== 5) throw new Error(`JWE must have 5 parts, got ${parts.length}`)
  const [headerB64, encKey, ivB64, ctB64, tagB64] = parts as [string, string, string, string, string]
  if (encKey !== '') throw new Error('JWE encrypted-key part must be empty for ECDH-ES')
  const header = decodeJson<{alg?: string; enc?: string; epk?: EcJwk; apu?: string; apv?: string}>(headerB64)
  if (header.alg !== 'ECDH-ES') throw new Error(`unsupported JWE alg ${String(header.alg)}`)
  if (header.enc !== 'A256GCM' && header.enc !== 'A128GCM') throw new Error(`unsupported JWE enc ${String(header.enc)}`)
  if (!header.epk) throw new Error('JWE header missing epk')
  const keyLen = header.enc === 'A256GCM' ? 32 : 16
  const apu = header.apu ? b64urlDecode(header.apu) : new Uint8Array()
  const apv = header.apv ? b64urlDecode(header.apv) : new Uint8Array()
  const cek = concatKdf(ecdhZ(recipientPrivateKey, header.epk), header.enc, apu, apv, keyLen)
  const iv = b64urlDecode(ivB64)
  const sealed = cat(b64urlDecode(ctB64), b64urlDecode(tagB64))
  return new TextDecoder().decode(gcm(cek, iv, utf8(headerB64)).decrypt(sealed))
}
