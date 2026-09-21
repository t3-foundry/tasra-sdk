// BF-IBE (Boneh-Franklin BasicIdent) over BLS12-381 — mirrors the reference IBE implementation.
//
// ⚠⚠ THIS FILE MUST AGREE WITH THE RUST CRATE BYTE-FOR-BYTE. Real IBE, not the ElGamal
// KEM in ./kem.ts: the ciphertext is bound to the IDENTITY at the pairing level, and
// only sk_ID = msk·Q_ID (extracted by k threshold nodes for THAT identity via
// POST /v1/shards/ibe/extract) decrypts. The guard against drift is the
// shared corpus test/ibe-vectors.json — a byte-identical copy of the reference implementation's
// vector file, run through THESE shipped functions by test/ibe.conformance.ts.
//
//   Encrypt(mpk, identity, message):
//     Q_ID = HashToCurveG1(identity, IBE_HASH_DST)          (RFC 9380, SHA-256 XMD)
//     r    ← Fr
//     U    = r · G2
//     T    = e(Q_ID, r · mpk) ∈ Gt                          (bilinearity: e(Q_ID,mpk)^r)
//     k    = SHA256(IBE_DOMAIN || "key" || u64le(|identity|) || identity
//                    || u64le(576) || gtBytes(T))
//     n    = SHA256(IBE_DOMAIN || "nonce" || compress(U))[0..12]
//     ct   = ChaCha20Poly1305(k, n, aad=identity).encrypt(message)
//
//   CombineDecrypt(verifyingShares, [(id, D_i)], {U,n,ct}, identity):
//     verify each: e(D_i, G2) == e(Q_ID, Y_i_g2)            (identifiable abort)
//     sk_ID = Σ λ_i · D_i                                   (Lagrange at 0 over Fr)
//     T     = e(sk_ID, U); k as above; AEAD open.
//
// ⚠ gtBytes: `bls12_381_plus::Gt::to_bytes()` has NO standard encoding — it is the 12
// Fp tower components in order c0.c0.c0, c0.c0.c1, c0.c1.c0, … c1.c2.c1, each 48-byte
// BIG-endian. Determined EMPIRICALLY against the reference vectors (fwd-be matched; three
// other candidate layouts did not) and pinned by the `gt_shared` vector field, so a
// noble upgrade that reshapes the tower fails loudly there.

import {chacha20poly1305} from '@noble/ciphers/chacha'
import {bls12_381} from '@noble/curves/bls12-381'
import {sha256} from '@noble/hashes/sha256'
import {randomBytes} from '@noble/hashes/utils'

const {Fr, Fp12} = bls12_381.fields
const G1 = bls12_381.G1
const G2 = bls12_381.G2

/** Domain tag for the KDF/nonce derivations (mirrors `IBE_DOMAIN`). */
export const IBE_DOMAIN = new TextEncoder().encode('keykeeper/BLS12381-BF-IBE-v1')
/** RFC 9380 DST for identity hashing (mirrors `IBE_HASH_DST`). */
export const IBE_HASH_DST = 'keykeeper/BLS12381-BF-IBE-HashToG1-v1'

/** Encrypted message — wire shape of `bls::ibe::Ciphertext`. */
export interface IbeCiphertext {
  /** 96-byte compressed G2 ephemeral public key U = r·G2. */
  u: Uint8Array
  /** 12-byte ChaCha20-Poly1305 nonce, derived deterministically from U. */
  nonce: Uint8Array
  /** AEAD output (plaintext.len + 16-byte tag). */
  aeadCt: Uint8Array
}

/** One node's partial `D_i = sk_i · Q_ID` (48-byte compressed G1). */
export interface IbeDecryptionShare {
  /** 1-indexed BLS group identifier (the extract reply's `identifier`). */
  identifier: number
  /** 48-byte compressed G1. */
  value: Uint8Array
}

/** A node's dual-group verifying share — only the 96-byte G2 half is needed here. */
export type IbeVerifyingShares = ReadonlyMap<number, Uint8Array>

// ─── internals ───────────────────────────────────────────────────────────────

type G1Point = InstanceType<typeof G1.ProjectivePoint>
type G2Point = InstanceType<typeof G2.ProjectivePoint>

function hashToG1(identity: Uint8Array): G1Point {
  const p = bls12_381.G1.hashToCurve(identity, {DST: IBE_HASH_DST})
  return G1.ProjectivePoint.fromAffine(p.toAffine())
}

function decodeG1(bytes: Uint8Array, what: string): G1Point {
  if (bytes.length !== 48) throw new Error(`${what}: expected 48 bytes, got ${bytes.length}`)
  const p = G1.ProjectivePoint.fromHex(bytes)
  // Reject the identity, mirroring the reference decode_g1 — an infinity D_i defeats
  // identifiable abort (it "verifies" against an infinity verifying share).
  if (p.equals(G1.ProjectivePoint.ZERO)) throw new Error(`${what}: point at infinity`)
  return p
}

function decodeG2(bytes: Uint8Array, what: string): G2Point {
  if (bytes.length !== 96) throw new Error(`${what}: expected 96 bytes, got ${bytes.length}`)
  const p = G2.ProjectivePoint.fromHex(bytes)
  // Reject the identity, mirroring the reference decode_g2 — a U = O ciphertext "decrypts"
  // under every key.
  if (p.equals(G2.ProjectivePoint.ZERO)) throw new Error(`${what}: point at infinity`)
  return p
}

/**
 * `bls12_381_plus::Gt::to_bytes()` — 576 bytes: the 12 Fp tower components in order,
 * each 48-byte big-endian. See the module header for how this layout was established.
 */
function gtToBytes(gt: ReturnType<typeof bls12_381.pairing>): Uint8Array {
  const out = new Uint8Array(576)
  const g = gt as unknown as {
    c0: {c0: {c0: bigint; c1: bigint}; c1: {c0: bigint; c1: bigint}; c2: {c0: bigint; c1: bigint}}
    c1: {c0: {c0: bigint; c1: bigint}; c1: {c0: bigint; c1: bigint}; c2: {c0: bigint; c1: bigint}}
  }
  const comps: bigint[] = []
  for (const six of [g.c0, g.c1]) {
    for (const two of [six.c0, six.c1, six.c2]) {
      comps.push(two.c0, two.c1)
    }
  }
  comps.forEach((c, i) => {
    let v = c
    for (let j = 47; j >= 0; j--) {
      out[i * 48 + j] = Number(v & 0xffn)
      v >>= 8n
    }
  })
  return out
}

function deriveKey(identity: Uint8Array, gtBytes: Uint8Array): Uint8Array {
  const len = (n: number) => {
    const b = new Uint8Array(8)
    new DataView(b.buffer).setBigUint64(0, BigInt(n), true)
    return b
  }
  const h = sha256.create()
  h.update(IBE_DOMAIN)
  h.update(new TextEncoder().encode('key'))
  h.update(len(identity.length))
  h.update(identity)
  h.update(len(gtBytes.length))
  h.update(gtBytes)
  return h.digest()
}

function deriveNonce(uBytes: Uint8Array): Uint8Array {
  const h = sha256.create()
  h.update(IBE_DOMAIN)
  h.update(new TextEncoder().encode('nonce'))
  h.update(uBytes)
  return h.digest().slice(0, 12)
}

function lagrangeAtZero(id: bigint, xs: bigint[]): bigint {
  let num = 1n
  let den = 1n
  for (const xj of xs) {
    if (xj === id) continue
    num = Fr.mul(num, Fr.neg(xj))
    den = Fr.mul(den, Fr.sub(id, xj))
  }
  return Fr.mul(num, Fr.inv(den))
}

function randomScalar(): bigint {
  while (true) {
    const bytes = randomBytes(64)
    let n = 0n
    for (const b of bytes) n = (n << 8n) | BigInt(b)
    const r = n % Fr.ORDER
    if (r !== 0n) return r
  }
}

// ─── conformance seams (mirror the reference helpers) ──────────────

/** `Q_ID` as 48 compressed bytes — pins the hash-to-curve suite + DST cross-language. */
export function ibeHashIdentityToG1(identity: Uint8Array): Uint8Array {
  return hashToG1(identity).toRawBytes(true)
}

/**
 * `gtBytes(e(Q_ID, r·mpk))` through the shipped internals — pins the Fp12 byte layout
 * (the `gt_shared` vector field) so a serializer drift is diagnosed at the intermediate
 * rather than as an opaque final-ciphertext mismatch.
 */
export function ibeSharedGtBytes(mpkBytes: Uint8Array, identity: Uint8Array, r: bigint): Uint8Array {
  const qId = hashToG1(identity)
  const mpk = decodeG2(mpkBytes, 'mpk')
  return gtToBytes(bls12_381.pairing(qId, mpk.multiply(r)))
}

// ─── encrypt ─────────────────────────────────────────────────────────────────

/**
 * Encrypt `message` to `identity` under the slot's master public key (96-byte
 * compressed G2). Offline and permissionless — the identity's key need not exist yet.
 */
export function ibeEncrypt(
  mpkBytes: Uint8Array,
  identity: Uint8Array,
  message: Uint8Array,
): IbeCiphertext {
  return ibeEncryptWithScalar(mpkBytes, identity, message, randomScalar())
}

/**
 * {@link ibeEncrypt} with the ephemeral scalar supplied — the CONFORMANCE SEAM,
 * mirroring the reference `encrypt_with_scalar`: `ibeEncrypt` delegates here, so the
 * deterministic vector leg pins the shipped code path. Never reuse an `r`.
 */
export function ibeEncryptWithScalar(
  mpkBytes: Uint8Array,
  identity: Uint8Array,
  message: Uint8Array,
  r: bigint,
): IbeCiphertext {
  const qId = hashToG1(identity)
  const mpk = decodeG2(mpkBytes, 'mpk')

  const uPoint = G2.ProjectivePoint.BASE.multiply(r)
  const uBytes = uPoint.toRawBytes(true)

  // Bilinearity: e(Q_ID, mpk)^r = e(Q_ID, r·mpk).
  const shared = bls12_381.pairing(qId, mpk.multiply(r))
  const aeadKey = deriveKey(identity, gtToBytes(shared))
  const nonce = deriveNonce(uBytes)

  const aeadCt = chacha20poly1305(aeadKey, nonce, identity).encrypt(message)
  return {u: uBytes, nonce, aeadCt}
}

// ─── verify + combine ────────────────────────────────────────────────────────

/**
 * Verify one extraction partial against its node's dual-group verifying share (the
 * 96-byte G2 half): `e(D_i, G2) == e(Q_ID, Y_i)`. Throws naming the identifier —
 * identifiable abort: the caller knows WHICH node served a bad share.
 */
export function ibeVerifyShare(
  verifyingShares: IbeVerifyingShares,
  identity: Uint8Array,
  share: IbeDecryptionShare,
): void {
  const vsBytes = verifyingShares.get(share.identifier)
  if (!vsBytes) throw new Error(`ibeVerifyShare: unknown identifier ${share.identifier}`)
  const dI = decodeG1(share.value, `share ${share.identifier}`)
  const yI = decodeG2(vsBytes, `verifying share ${share.identifier}`)
  const qId = hashToG1(identity)
  const lhs = bls12_381.pairing(dI, G2.ProjectivePoint.BASE)
  const rhs = bls12_381.pairing(qId, yI)
  if (!Fp12.eql(lhs, rhs)) {
    throw new Error(`ibeVerifyShare: invalid share from identifier ${share.identifier}`)
  }
}

/**
 * Lagrange-combine k verified partials into the identity key `sk_ID = msk · Q_ID`
 * (48-byte compressed G1).
 *
 * ⚠ Holding `sk_ID` is a DURABLE capability over every past and future ciphertext to
 * this identity — prefer {@link ibeCombineDecrypt}, which uses and drops it. Verifies
 * every share first (a caller combining unverified shares could be fed garbage that
 * silently fails the AEAD later, unattributed).
 */
export function ibeCombineExtract(
  verifyingShares: IbeVerifyingShares,
  shares: IbeDecryptionShare[],
  identity: Uint8Array,
): Uint8Array {
  if (shares.length === 0) throw new Error('ibeCombineExtract: no shares')
  const ids = shares.map(s => s.identifier)
  if (new Set(ids).size !== ids.length) {
    throw new Error('ibeCombineExtract: duplicate identifier')
  }
  for (const s of shares) ibeVerifyShare(verifyingShares, identity, s)

  const xs = ids.map(BigInt)
  let skId = G1.ProjectivePoint.ZERO
  for (const s of shares) {
    const lambda = lagrangeAtZero(BigInt(s.identifier), xs)
    skId = skId.add(decodeG1(s.value, `share ${s.identifier}`).multiply(lambda))
  }
  return skId.toRawBytes(true)
}

/**
 * Combine k extraction partials and AEAD-decrypt `ct` — mirrors
 * `bls::ibe::combine_decrypt` (verify every share → Lagrange-combine → `T = e(sk_ID,U)`
 * → KDF → open). The intermediate `sk_ID` never leaves this function.
 */
export function ibeCombineDecrypt(
  verifyingShares: IbeVerifyingShares,
  shares: IbeDecryptionShare[],
  ct: IbeCiphertext,
  identity: Uint8Array,
): Uint8Array {
  const skIdBytes = ibeCombineExtract(verifyingShares, shares, identity)
  try {
    return ibeDecryptWithKey(skIdBytes, ct, identity)
  } finally {
    skIdBytes.fill(0)
  }
}

/**
 * Decrypt with an already-extracted identity key (48-byte compressed G1) — the
 * custody-opt-in path pairing with {@link ibeCombineExtract}.
 */
export function ibeDecryptWithKey(
  skIdBytes: Uint8Array,
  ct: IbeCiphertext,
  identity: Uint8Array,
): Uint8Array {
  const skId = decodeG1(skIdBytes, 'sk_ID')
  const u = decodeG2(ct.u, 'ciphertext.u')
  const shared = bls12_381.pairing(skId, u)
  const aeadKey = deriveKey(identity, gtToBytes(shared))
  if (ct.nonce.length !== 12) throw new Error('ciphertext.nonce: expected 12 bytes')
  return chacha20poly1305(aeadKey, ct.nonce, identity).decrypt(ct.aeadCt)
}
