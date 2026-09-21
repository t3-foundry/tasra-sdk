// FROST-Ed25519 aggregation conformance — self-consistent full round-trip.
//
// An INDEPENDENT signer simulation (trusted-dealer Shamir keygen → per-signer
// nonce commitments → signature shares), transcribed from the spec, is fed
// through the public aggregate()/verify(). This cross-checks the point math,
// Lagrange reconstruction (Σ λ_i s_i = s), per-share identifiable-abort, and the
// final verification equation.
//
// This suite is SELF-CONSISTENT by construction — it feeds its own simulated
// shares through aggregate()/verify(), so it stays green even if both sides
// compute the WRONG challenge together. That is exactly how a stale
// domain-separated tag survived here until 2026-08-08. The check that cannot
// be fooled that way is the stock-Ed25519 assertion at the end.
//
// Run: tsx test/frost.crypto.ts — exits non-zero on any failure.

import {ed25519} from '@noble/curves/ed25519'
import {mod, invert} from '@noble/curves/abstract/modular'
import {sha512} from '@noble/hashes/sha512'
import {concatBytes, utf8ToBytes} from '@noble/hashes/utils'
import {
  aggregate,
  verify,
  type FrostCommitment,
  type FrostShare,
} from '../src/crypto/frost.ts'
import {hexToBytes} from '../src/crypto/hex.ts'

const Point = ed25519.Point
const L = ed25519.CURVE.n
const DST_RHO = utf8ToBytes('FROST-Ed25519-SHA512-v1/rho')

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean) {
  if (cond) passed++
  else failures.push(name)
}

// ─── spec helpers (independent transcription) ──────────────────────────────────
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
function leToBig(b: Uint8Array): bigint {
  let n = 0n
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i] as number)
  return n
}
function scalarToLe(n: bigint): Uint8Array {
  let v = mod(n, L)
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}
function hashToScalar(...parts: Uint8Array[]): bigint {
  return mod(leToBig(sha512(concatBytes(...parts))), L)
}
type Pt = ReturnType<typeof Point.fromHex>
function mul(p: Pt, k: bigint): Pt {
  const kk = mod(k, L)
  return kk === 0n ? Point.ZERO : p.multiply(kk)
}
function lagrange(xi: bigint, xs: bigint[]): bigint {
  let num = 1n
  let den = 1n
  for (const xj of xs) {
    if (xj === xi) continue
    num = mod(num * mod(-xj, L), L)
    den = mod(den * mod(xi - xj, L), L)
  }
  return mod(num * invert(den, L), L)
}

// ─── trusted-dealer keygen (deterministic) ─────────────────────────────────────
// degree k-1 = 1 polynomial f(x) = s + a1·x ; shares s_i = f(i).
const secret = mod(leToBig(sha512(utf8ToBytes('frost-test-secret'))), L) || 1n
const a1 = mod(leToBig(sha512(utf8ToBytes('frost-test-a1'))), L) || 1n
const f = (x: bigint): bigint => mod(secret + mod(a1 * x, L), L)

const allIds = [1, 2, 3]
const sBy = new Map(allIds.map(i => [i, f(BigInt(i))]))
const Y = mul(Point.BASE, secret) // group public key
const groupPk = Y.toRawBytes()

const message = utf8ToBytes('threshold-signed by k of n keykeepers')

// pick a k-subset of signers
const signers = [1, 3]
const xs = signers.map(i => BigInt(i))

// per-signer nonces (deterministic, non-zero)
const nonce = (label: string, i: number): bigint =>
  (mod(hashToScalar(utf8ToBytes(label), u16le(i)), L) || 1n)
const dBy = new Map(signers.map(i => [i, nonce('d', i)]))
const eBy = new Map(signers.map(i => [i, nonce('e', i)]))

// Round-1 commitments, in canonical (id-sorted) order
const commitments: FrostCommitment[] = signers
  .slice()
  .sort((p, q) => p - q)
  .map(i => ({
    identifier: i,
    hiding: mul(Point.BASE, dBy.get(i)!).toRawBytes(),
    binding: mul(Point.BASE, eBy.get(i)!).toRawBytes(),
  }))

// recompute the binding factors / group commitment / challenge the way the
// aggregator will, so each signer can produce a consistent share
const serialized = concatBytes(
  ...commitments.flatMap(c => [u16le(c.identifier), c.hiding, c.binding]),
)
const lenMsg = u64le(message.length)
const rhoBy = new Map(
  commitments.map(c => [c.identifier, hashToScalar(DST_RHO, u16le(c.identifier), lenMsg, message, serialized)]),
)
let R: Pt = Point.ZERO
for (const c of commitments) {
  R = R.add(Point.fromHex(c.hiding).add(mul(Point.fromHex(c.binding), rhoBy.get(c.identifier)!)))
}
// RFC 8032: bare SHA-512(R ‖ Y ‖ M), no domain tag, no length prefix.
const chal = hashToScalar(R.toRawBytes(), groupPk, message)

// Round-2 shares: z_i = d_i + ρ_i·e_i + λ_i·c·s_i
const shares: FrostShare[] = signers.map(i => {
  const lambda = lagrange(BigInt(i), xs)
  const zi = mod(dBy.get(i)! + mod(rhoBy.get(i)! * eBy.get(i)!, L) + mod(mod(lambda * chal, L) * sBy.get(i)!, L), L)
  return {identifier: i, z: scalarToLe(zi), verifyingShare: mul(Point.BASE, sBy.get(i)!).toRawBytes()}
})

// ─── checks ────────────────────────────────────────────────────────────────────

// Lagrange reconstructs the secret from the k-subset.
{
  const recon = signers.reduce((acc, i) => mod(acc + mod(lagrange(BigInt(i), xs) * sBy.get(i)!, L), L), 0n)
  ok('lagrange: Σ λ_i·s_i reconstructs the group secret', recon === secret)
}

// aggregate() produces a signature that verify() accepts.
{
  const sig = aggregate(message, groupPk, commitments, shares)
  ok('aggregate: R is 32 bytes', sig.r.length === 32)
  ok('aggregate: z is 32 bytes', sig.z.length === 32)
  ok('aggregate: R matches the independently-computed group commitment', leToBig(sig.r) === leToBig(R.toRawBytes()))
  ok('verify: accepts the aggregated signature', verify(groupPk, message, sig) === true)
  ok('verify: rejects a tampered message', verify(groupPk, utf8ToBytes('different'), sig) === false)
}

// identifiable abort: a corrupted share is rejected, naming the signer.
{
  const bad = shares.map((s, idx) => (idx === 0 ? {...s, z: scalarToLe(leToBig(s.z) + 1n)} : s))
  let threw = false
  try {
    aggregate(message, groupPk, commitments, bad)
  } catch {
    threw = true
  }
  ok('aggregate: rejects an invalid signature share', threw)
}

// ─── known-answer vector pinned against the reference implementation ──────────
// 2-of-3, signer set [1,2]. REGENERATE (never hand-edit) from the reference
// implementation's known-answer generator and paste the printed block below.
//
// This is the ONLY check here that can catch a divergence from the reference implementation. The
// simulation above is self-consistent — it feeds its own shares through our own
// aggregate()/verify(), so it stays green when BOTH sides compute the same
// WRONG challenge. That is not hypothetical: a domain-separated `…/chal` tag
// survived here after the reference implementation dropped it, and the
// SDK rejected every signature the live fleet produced until the e2e cert
// caught it.
{
  const bareHex = (b: Uint8Array): string =>
    Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')
  // ─── BEGIN generated FROST KAT
  const msg = utf8ToBytes('keykeeper frost kat v1')
  const gpk = hexToBytes('0x9f005c4c06ca1f9df6e2f48313ad15784b1a2209e4867136aa24e76b15b97598')
  const katCommitments: FrostCommitment[] = [
    {
      identifier: 1,
      hiding: hexToBytes('0x6a0de00cae4bffbc14dae912ed25b42daee8dfc95adc86a868341f59232f2bf6'),
      binding: hexToBytes('0x7df559430d23032e1b4b8e002b8e4057a63977e2a70f2e4e0ba2bacd1adaacf2'),
    },
    {
      identifier: 2,
      hiding: hexToBytes('0x2960633d05a0322ae230a1c6ea71bdd3a9715a0725d1727338b11ea1dd87b7d4'),
      binding: hexToBytes('0x0689dbe412ca547243cf8f0f75e7a2f995ae03576664ca9aad0ceaa8ef869837'),
    },
  ]
  const katShares: FrostShare[] = [
    {
      identifier: 1,
      z: hexToBytes('0xf098cf1780ec272da47d39a52d2e280a80112abc02183ede09a0756857c6e606'),
      verifyingShare: hexToBytes('0x840b827363bc376c19a05b64dc3c83e65c1d35411df2b2ee0fbc601ab9a8943c'),
    },
    {
      identifier: 2,
      z: hexToBytes('0x8cf2cf5c440608c121ee799259b5a9bf111842d2dbc362a1147dcdbda6a4f902'),
      verifyingShare: hexToBytes('0x50d2ac4917230d97877d33c2f62936fa0b0483edabd309ead100e68d8a39205f'),
    },
  ]
  const expR = 'e6c87db4f675206928541eda9666d1f9a38a2af03b3eb9449331134ece597e19'
  const expZ = '7c8b9f74c4f22feec56bb33787e3d1c991296c8ededba07f1e1d4326fe6ae009'
  // ─── END generated FROST KAT

  const sig = aggregate(msg, gpk, katCommitments, katShares)
 ok('KAT: aggregated R matches the reference implementation vector', bareHex(sig.r) === expR)
 ok('KAT: aggregated z matches the reference implementation vector', bareHex(sig.z) === expZ)
 ok('KAT: verify() accepts the reference implementation vector', verify(gpk, msg, sig) === true)

  // THE oracle. RFC 9591's challenge IS the RFC 8032 one, so the 64-byte
  // R‖z aggregate must satisfy a STOCK Ed25519 verifier — the same check sshd
  // performs. Unlike everything above, this cannot be satisfied by a
  // self-consistent-but-wrong challenge, because noble computes it
  // independently. If someone reintroduces a domain tag, this line fails.
  const stockSig = new Uint8Array(64)
  stockSig.set(sig.r, 0)
  stockSig.set(sig.z, 32)
  ok('KAT: a STOCK Ed25519 verifier accepts the aggregate (RFC 8032 compatibility)',
     ed25519.verify(stockSig, msg, gpk) === true)

  // Negative control: the oracle must actually be able to fail.
  const tampered = new Uint8Array(stockSig)
  // `noUncheckedIndexedAccess` types tampered[0] as possibly-undefined; the
  // array is a fixed 64 bytes we just built, so read-modify-write explicitly.
  tampered.set([(tampered[0] ?? 0) ^ 0x01], 0)
  ok('KAT: the stock verifier rejects a tampered signature',
     ed25519.verify(tampered, msg, gpk) === false)
}

if (failures.length > 0) {
  console.error(`✗ frost.crypto: ${failures.length} failed:`)
  for (const ferr of failures) console.error('   - ' + ferr)
  process.exit(1)
}
console.log(`✓ frost.crypto: ${passed} checks passed`)
