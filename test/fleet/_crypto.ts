// Independent cryptographic verification of fleet outputs — so tests assert the
// real artifact (a valid signature), never a status-code proxy.

import {ed25519} from '@noble/curves/ed25519'


const cat = (...as: Uint8Array[]): Uint8Array => {
  const o = new Uint8Array(as.reduce((s, x) => s + x.length, 0))
  let k = 0
  for (const x of as) {
    o.set(x, k)
    k += x.length
  }
  return o
}

/**
 * Verify a threshold signature with a STOCK Ed25519 verifier.
 *
 * The crate's challenge is RFC 9591 H2, which IS the RFC 8032 PureEdDSA
 * challenge — a bare `SHA-512(R ‖ A ‖ M) mod L`, no domain tag, no length
 * prefix — so the 64-byte `R ‖ z` aggregate is an ordinary Ed25519 signature.
 * Checking it with noble's `ed25519.verify` rather than re-deriving `z·B ==
 * R + c·A` by hand is deliberate: a hand-transcribed relation drifts in
 * LOCKSTEP with the implementation it is meant to check (it did — a
 * domain-separated `…/chal` tag lived here until 2026-08-08 and had to be
 * removed when the reference implementation dropped it). A stock
 * verifier is an EXTERNAL oracle: it cannot be satisfied by a self-consistent
 * but wrong challenge, and it is the exact check `sshd` performs.
 */
export function frostVerify(R: Uint8Array, z: Uint8Array, A: Uint8Array, message: Uint8Array): boolean {
  try {
    return ed25519.verify(cat(R, z), message, A)
  } catch {
    return false
  }
}
