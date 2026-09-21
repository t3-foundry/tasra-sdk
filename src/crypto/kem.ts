// BLS12-381 threshold KEM — mirrors the reference KEM implementation.
//
// Protocol: ElGamal in G2 with a ChaCha20-Poly1305 envelope.
//
//   Encrypt(mpk, identity, message):
//     r  ← Fr  (random)
//     U  = r · G2                              (ephemeral public key)
//     S  = r · mpk                             (shared secret)
//     k  = SHA256(KEM_DOMAIN || "key" || len(identity) || identity || compress(S))
//     n  = SHA256(KEM_DOMAIN || "nonce" || compress(U))[0..12]
//     ct = ChaCha20Poly1305(k, n, aad=identity).encrypt(message)
//     return { U, n, ct }
//
//   Decrypt(msk, {U, n, ct}, identity):
//     S  = msk · U
//     k  = SHA256(KEM_DOMAIN || "key" || len(identity) || identity || compress(S))
//     return ChaCha20Poly1305(k, n, aad=identity).decrypt(ct)
//
//   AssembleKey([(id₁,sk₁), …, (idₖ,skₖ)]):
//     msk = Σ λᵢ · skᵢ   (Lagrange interpolation at 0 over Fr)

import {chacha20poly1305} from '@noble/ciphers/chacha'
import {bls12_381} from '@noble/curves/bls12-381'
import {sha256} from '@noble/hashes/sha256'
import {randomBytes} from '@noble/hashes/utils'

import {KEM_DOMAIN} from './constants.js'

const {Fr} = bls12_381.fields
const G1 = bls12_381.G1
const G2 = bls12_381.G2
const Fp12 = bls12_381.fields.Fp12

// ─── Fr scalar helpers ────────────────────────────────────────────────────────

// Convert 32-byte little-endian encoding (the reference scalar encoding)
// to bigint. Throws if the value is >= Fr.ORDER (non-canonical).
export function leToScalar(leBytes: Uint8Array): bigint {
  if (leBytes.length !== 32) {
    throw new Error(`leToScalar: expected 32 bytes, got ${leBytes.length}`)
  }
  let n = 0n
  for (let i = leBytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(leBytes[i] as number)
  }
  if (n >= Fr.ORDER) {
    throw new Error('leToScalar: non-canonical scalar (>= field order)')
  }
  return n
}

// Convert Fr bigint to 32-byte little-endian (matching the reference scalar encoding).
export function scalarToLe(n: bigint): Uint8Array {
  const canonical: bigint = ((n % Fr.ORDER) + Fr.ORDER) % Fr.ORDER
  const out = new Uint8Array(32)
  let v: bigint = canonical
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

// Sample a uniformly random non-zero Fr scalar.
function randomScalar(): bigint {
  // Sample 64 bytes (2× field width) for uniformity, then reduce mod ORDER.
  // Retry on the astronomically unlikely event of getting zero.
  while (true) {
    const bytes = randomBytes(64)
    let n = 0n
    for (const b of bytes) n = (n << 8n) | BigInt(b)
    const r = n % Fr.ORDER
    if (r !== 0n) return r
  }
}

// ─── KDF ─────────────────────────────────────────────────────────────────────

// Derive 32-byte ChaCha20-Poly1305 key from identity and shared G2 point.
// Mirrors the reference derive_key exactly:
//   SHA256(KEM_DOMAIN || "key" || u64_le(identity.len) || identity || compress(shared))
function deriveKey(
  identity: Uint8Array,
  sharedCompressed: Uint8Array,
): Uint8Array {
  const lenBuf = new Uint8Array(8)
  new DataView(lenBuf.buffer).setBigUint64(0, BigInt(identity.length), true)

  const h = sha256.create()
  h.update(KEM_DOMAIN)
  h.update(new TextEncoder().encode('key'))
  h.update(lenBuf)
  h.update(identity)
  h.update(sharedCompressed)
  return h.digest()
}

// Derive 12-byte AEAD nonce from the ephemeral G2 point U.
// Mirrors the reference derive_nonce exactly:
//   SHA256(KEM_DOMAIN || "nonce" || u_bytes)[0..12]
function deriveNonce(uBytes: Uint8Array): Uint8Array {
  const h = sha256.create()
  h.update(KEM_DOMAIN)
  h.update(new TextEncoder().encode('nonce'))
  h.update(uBytes)
  return h.digest().slice(0, 12)
}

// ─── Lagrange ────────────────────────────────────────────────────────────────

// Lagrange basis polynomial evaluated at 0 for participant `id`
// over index set `xs`. Mirrors the reference lagrange_at_zero exactly.
function lagrangeAtZero(id: bigint, xs: bigint[]): bigint {
  const xi = id
  let num = 1n
  let den = 1n
  for (const xj of xs) {
    if (xj === xi) continue
    num = Fr.mul(num, Fr.neg(xj)) // num *= -xj
    den = Fr.mul(den, Fr.sub(xi, xj)) // den *= (xi - xj)
  }
  return Fr.mul(num, Fr.inv(den))
}

// ─── Public types ─────────────────────────────────────────────────────────────

export interface Ciphertext {
  /** 96-byte compressed G2 ephemeral public key U = r·G2. */
  u: Uint8Array
  /** 12-byte ChaCha20-Poly1305 nonce, derived from U. */
  nonce: Uint8Array
  /** AEAD ciphertext: plaintext.len + 16 (Poly1305 tag). */
  aeadCt: Uint8Array
}

export interface Shard {
  /** 1-indexed participant identifier (u16, non-zero). */
  id: number
  /** 32-byte little-endian BLS12-381 Fr scalar (sk_i). */
  bytes: Uint8Array
}

// ─── Core operations ─────────────────────────────────────────────────────────

// Assemble master secret key from k raw shard scalars via Lagrange interpolation.
// Mirrors the reference assemble_key. Returns 32-byte LE-encoded msk.
//
// Security note: the returned msk is the full threshold private key.
// Keep it in memory only for the session duration.
export function assembleKey(shards: Shard[]): Uint8Array {
  if (shards.length === 0) {
    throw new Error('assembleKey: no shards provided')
  }

  const ids = shards.map(s => s.id)
  const sortedIds = [...ids].sort((a, b) => a - b)
  for (let i = 0; i < sortedIds.length - 1; i++) {
    if (sortedIds[i] === sortedIds[i + 1]) {
      throw new Error(`assembleKey: duplicate identifier ${sortedIds[i]}`)
    }
  }

  const xs = shards.map(s => BigInt(s.id))
  let msk = 0n

  for (const shard of shards) {
    const scalar = leToScalar(shard.bytes) // validates canonical range
    const lambda = lagrangeAtZero(BigInt(shard.id), xs)
    msk = Fr.add(msk, Fr.mul(scalar, lambda))
  }

  return scalarToLe(msk)
}

// Encrypt plaintext to a group's master public key.
//
// mpkBytes: 96-byte compressed G2 point (from GET /v1/keys/{slot}/public)
// identity: AEAD additional authenticated data — typically the room/slot
//           identifier the receiver must replay on decryption
export function encrypt(
  mpkBytes: Uint8Array,
  identity: Uint8Array,
  plaintext: Uint8Array,
): Ciphertext {
  const mpk = G2.ProjectivePoint.fromHex(mpkBytes)

  const r = randomScalar()

  const uPoint = G2.ProjectivePoint.BASE.multiply(r)
  const uBytes = uPoint.toRawBytes(true) // 96 bytes compressed

  const shared = mpk.multiply(r)
  const sharedBytes = shared.toRawBytes(true) // 96 bytes compressed

  const aeadKey = deriveKey(identity, sharedBytes)
  const nonce = deriveNonce(uBytes)

  const aeadCt = chacha20poly1305(aeadKey, nonce, identity).encrypt(plaintext)

  return {u: uBytes, nonce, aeadCt}
}

// Decrypt ciphertext using the assembled master secret key.
// mskBytes: 32-byte LE scalar (output of assembleKey).
// Throws on authentication failure or malformed input.
export function decryptWithMasterKey(
  mskBytes: Uint8Array,
  ct: Ciphertext,
  identity: Uint8Array,
): Uint8Array {
  const msk = leToScalar(mskBytes) // validates canonical range

  const u = G2.ProjectivePoint.fromHex(ct.u)
  const shared = u.multiply(msk)
  const sharedBytes = shared.toRawBytes(true)

  const aeadKey = deriveKey(identity, sharedBytes)

  try {
    return chacha20poly1305(aeadKey, ct.nonce, identity).decrypt(ct.aeadCt)
  } catch {
    throw new Error('decryptWithMasterKey: AEAD authentication failed')
  }
}

// ─── Threshold partial-decrypt (share path) ─────────────────────────────────────
// Mirrors the reference verify_share, combine_decrypt. The client fetches a partial
// decryption D_i = sk_i·U from each of k nodes and combines them WITHOUT ever
// assembling the master key: D = Σ λ_i·D_i = (Σ λ_i·sk_i)·U = msk·U = S, the same
// shared secret decryptWithMasterKey derives — so the KEM-DEM step is identical.

export interface DecryptShare {
  /** 1-indexed BLS participant identifier (u16). */
  id: number
  /** 96-byte compressed G2 partial decryption D_i = sk_i·U. */
  decryptionShare: Uint8Array
  /** 144-byte verifying share: 96B compressed G2 (sk_i·g2) ‖ 48B compressed G1
   *  (sk_i·g1). Required only for verifyDecryptShare. */
  verifyingShare?: Uint8Array
}

// Verify a partial decryption share via the pairing equation
//   e(Y_i^{G1}, U) == e(g1, D_i),   where Y_i^{G1} = sk_i·g1.
// Mirrors the reference verify_share. Returns false on malformed input.
export function verifyDecryptShare(share: DecryptShare, u: Uint8Array): boolean {
  try {
    if (!share.verifyingShare || share.verifyingShare.length !== 144) return false
    const yiG1 = G1.ProjectivePoint.fromHex(share.verifyingShare.subarray(96, 144))
    const U = G2.ProjectivePoint.fromHex(u)
    const di = G2.ProjectivePoint.fromHex(share.decryptionShare)
    return Fp12.eql(
      bls12_381.pairing(yiG1, U),
      bls12_381.pairing(G1.ProjectivePoint.BASE, di),
    )
  } catch {
    return false
  }
}

// Combine k partial decryption shares into the plaintext. With `verify`, each
// share is pairing-checked first (identifiable abort) and a bad share throws
// naming its id. Mirrors the reference combine_decrypt.
export function combineDecryptShares(
  shares: DecryptShare[],
  ct: Ciphertext,
  identity: Uint8Array,
  opts: {verify?: boolean} = {},
): Uint8Array {
  if (shares.length === 0) throw new Error('combineDecryptShares: no shares provided')

  const sortedIds = shares.map(s => s.id).sort((a, b) => a - b)
  for (let i = 0; i < sortedIds.length - 1; i++) {
    if (sortedIds[i] === sortedIds[i + 1]) {
      throw new Error(`combineDecryptShares: duplicate identifier ${sortedIds[i]}`)
    }
  }

  if (opts.verify) {
    for (const s of shares) {
      if (!verifyDecryptShare(s, ct.u)) {
        throw new Error(`combineDecryptShares: invalid decryption share from identifier ${s.id}`)
      }
    }
  }

  const xs = shares.map(s => BigInt(s.id))
  let dPoint = G2.ProjectivePoint.ZERO
  for (const s of shares) {
    const di = G2.ProjectivePoint.fromHex(s.decryptionShare)
    const lambda = lagrangeAtZero(BigInt(s.id), xs)
    if (lambda !== 0n) dPoint = dPoint.add(di.multiply(lambda))
  }

  const aeadKey = deriveKey(identity, dPoint.toRawBytes(true)) // compress(S)
  try {
    return chacha20poly1305(aeadKey, ct.nonce, identity).decrypt(ct.aeadCt)
  } catch {
    throw new Error('combineDecryptShares: AEAD authentication failed')
  }
}
