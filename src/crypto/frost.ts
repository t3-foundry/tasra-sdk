// FROST-Ed25519 client-side aggregation + verification.
//
// This is the CLIENT half of the shard-delivery signing flow: the
// nodes each return a Round-1 commitment (hiding D_i, binding E_i) and a Round-2
// signature share z_i; the client (this code) combines them into a single group
// Schnorr signature, byte-for-byte compatible with the keepers' implementation.
//
// ⚠ The CHALLENGE is RFC 9591 H2, which IS the RFC 8032 PureEdDSA challenge:
// a bare SHA-512(R ‖ Y ‖ M) mod L, with NO domain tag and NO length prefix.
// So an aggregate here is also a valid stock Ed25519 (and `ssh-ed25519`)
// signature. Adding a domain tag here rejects every signature the network
// produces. The BINDING FACTOR (ρ) does carry one — do not "simplify" that one
// to match. test/frost.crypto.ts pins both against known-answer vectors.
//
// All scalars are little-endian mod L (the ed25519 group order); all points are
// 32-byte compressed Edwards. Hash-to-scalar wide-reduces SHA-512 little-endian.

import {ed25519} from '@noble/curves/ed25519'
import {mod, invert} from '@noble/curves/abstract/modular'
import {sha512} from '@noble/hashes/sha512'
import {concatBytes, utf8ToBytes} from '@noble/hashes/utils'

const Point = ed25519.Point
/** ed25519 group order L = 2^252 + 27742317777372353535851937790883648493. */
const L = ed25519.CURVE.n

// Pinned domain-separation tag for the binding factor (the reference// implementation RHO_DOMAIN). The challenge deliberately has none — see the header.
const DST_RHO = utf8ToBytes('FROST-Ed25519-SHA512-v1/rho')

// ─── encoding helpers ─────────────────────────────────────────────────────────

function u16le(n: number): Uint8Array {
  const b = new Uint8Array(2)
  new DataView(b.buffer).setUint16(0, n, true)
  return b
}

function u64le(n: number): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true)
  return b
}

/** 32-byte little-endian → bigint (also used wide, for the 64-byte SHA-512). */
function leToBig(b: Uint8Array): bigint {
  let n = 0n
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i] as number)
  return n
}

/** bigint → 32-byte little-endian, reduced canonical mod L. */
export function scalarToLe(n: bigint): Uint8Array {
  let v = mod(n, L)
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/** SHA-512 over the parts, interpreted little-endian, reduced mod L. */
function hashToScalar(...parts: Uint8Array[]): bigint {
  return mod(leToBig(sha512(concatBytes(...parts))), L)
}

type Pt = ReturnType<typeof Point.fromHex>

function decompress(b: Uint8Array): Pt {
  return Point.fromHex(b)
}

/** Scalar-multiply, tolerating k ≡ 0 (noble's multiply throws on 0). */
function mul(p: Pt, k: bigint): Pt {
  const kk = mod(k, L)
  return kk === 0n ? Point.ZERO : p.multiply(kk)
}

// Lagrange basis polynomial for `xi` evaluated at 0 over the index set `xs`,
// in the scalar field mod L. Mirrors the reference lagrange-at-0.
function lagrangeAtZero(xi: bigint, xs: bigint[]): bigint {
  let num = 1n
  let den = 1n
  for (const xj of xs) {
    if (xj === xi) continue
    num = mod(num * mod(-xj, L), L)
    den = mod(den * mod(xi - xj, L), L)
  }
  return mod(num * invert(den, L), L)
}

// ─── public types ─────────────────────────────────────────────────────────────

/** One node's Round-1 commitment (from POST /v1/shards/sign/commit). */
export interface FrostCommitment {
  /** 1-indexed FROST participant id (u16). */
  identifier: number
  /** 32-byte compressed Edwards hiding nonce commitment D_i. */
  hiding: Uint8Array
  /** 32-byte compressed Edwards binding nonce commitment E_i. */
  binding: Uint8Array
}

/** One node's Round-2 signature share (from POST /v1/shards/sign/partial). */
export interface FrostShare {
  identifier: number
  /** 32-byte little-endian scalar z_i. */
  z: Uint8Array
  /** 32-byte compressed Edwards verifying share Y_i = g^{s_i}. */
  verifyingShare: Uint8Array
}

/** A FROST-Ed25519 group signature: R (32B compressed) + z (32B LE scalar). */
export interface FrostSignature {
  r: Uint8Array
  z: Uint8Array
}

// ─── aggregation + verification ────────────────────────────────────────────────

/**
 * Combine k Round-1 commitments + k Round-2 shares into the group signature.
 * `commitments` MUST be in the same order that was sent to every node (the
 * binding factors depend on the serialized list order). Each share is
 * identifiable-abort verified; an invalid share throws naming its identifier.
 *
 * Mirrors the reference signing implementation::aggregate.
 */
export function aggregate(
  message: Uint8Array,
  groupPublicKey: Uint8Array,
  commitments: FrostCommitment[],
  shares: FrostShare[],
): FrostSignature {
  if (commitments.length === 0) throw new Error('aggregate: no commitments')

  // serialized = ‖ over commitments of (u16_LE(id) ‖ hiding32 ‖ binding32)
  const serialized = concatBytes(
    ...commitments.flatMap(c => [u16le(c.identifier), c.hiding, c.binding]),
  )
  const lenMsg = u64le(message.length)

  // ρ_i = H_rho(id_i, len(msg), msg, serialized)  — per signer
  const rho = new Map<number, bigint>()
  for (const c of commitments) {
    rho.set(c.identifier, hashToScalar(DST_RHO, u16le(c.identifier), lenMsg, message, serialized))
  }

  // R = Σ_i (D_i + ρ_i · E_i)
  let R: Pt = Point.ZERO
  for (const c of commitments) {
    const Ri = decompress(c.hiding).add(mul(decompress(c.binding), rho.get(c.identifier)!))
    R = R.add(Ri)
  }
  const Rc = R.toRawBytes()

  // c = SHA-512(R ‖ Y ‖ M) mod L  — RFC 8032, no domain tag, no length prefix
  const chal = hashToScalar(Rc, groupPublicKey, message)

  const ids = commitments.map(c => BigInt(c.identifier))
  const shareById = new Map(shares.map(s => [s.identifier, s]))

  let z = 0n
  for (const c of commitments) {
    const share = shareById.get(c.identifier)
    if (!share) throw new Error(`aggregate: missing share for identifier ${c.identifier}`)
    const lambda = lagrangeAtZero(BigInt(c.identifier), ids)
    const zi = leToBig(share.z)

    // identifiable abort: g^{z_i} == D_i + ρ_i·E_i + (λ_i·c)·Y_i
    const lhs = mul(Point.BASE, zi)
    const rhs = decompress(c.hiding)
      .add(mul(decompress(c.binding), rho.get(c.identifier)!))
      .add(mul(decompress(share.verifyingShare), mod(lambda * chal, L)))
    if (!lhs.equals(rhs)) {
      throw new Error(`aggregate: invalid signature share from identifier ${c.identifier}`)
    }
    z = mod(z + zi, L)
  }

  return {r: Rc, z: scalarToLe(z)}
}

/**
 * Verify a FROST-Ed25519 group signature: g^z == R + Y^c, where
 * c = H_chal(R, Y, len(msg), msg). Returns false on any malformed input.
 */
export function verify(
  groupPublicKey: Uint8Array,
  message: Uint8Array,
  sig: FrostSignature,
): boolean {
  try {
    const R = decompress(sig.r)
    const Y = decompress(groupPublicKey)
    const z = leToBig(sig.z)
    const chal = hashToScalar(sig.r, groupPublicKey, message)
    return mul(Point.BASE, z).equals(R.add(mul(Y, chal)))
  } catch {
    return false
  }
}
