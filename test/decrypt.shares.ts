// Threshold partial-decrypt (share path) conformance — offline round-trip.
//
// Trusted-dealer Shamir-shares a master key, has each "node" produce its partial
// decryption D_i = sk_i·U and verifying share, then checks that
// combineDecryptShares() reconstructs the plaintext WITHOUT assembling the key,
// agrees with the assemble-then-decryptWithMasterKey path, passes pairing
// verification, and aborts on bad/duplicate shares.
//
// Run: tsx test/decrypt.shares.ts — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {concatBytes} from '@noble/hashes/utils'
import {
  encrypt,
  combineDecryptShares,
  verifyDecryptShare,
  decryptWithMasterKey,
  scalarToLe,
  type DecryptShare,
} from '../src/crypto/kem.ts'

const G1 = bls12_381.G1.ProjectivePoint
const G2 = bls12_381.G2.ProjectivePoint
const ORDER = bls12_381.fields.Fr.ORDER

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean) {
  if (cond) passed++
  else failures.push(name)
}
function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i])
}

const modf = (n: bigint): bigint => ((n % ORDER) + ORDER) % ORDER

// ─── trusted-dealer keygen: f(x) = msk + a1·x  (2-of-3) ─────────────────────────
const msk = modf(0x2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfen)
const a1 = modf(0x1a2b3c4d5e6f70819021324354657687a9bacbdcedfe0f1023344556677889900n)
const f = (x: bigint): bigint => modf(msk + modf(a1 * x))

const ids = [1, 2, 3]
const skBy = new Map(ids.map(i => [i, f(BigInt(i))]))

// mpk = msk·g2 (the slot's master public key, 96B compressed G2)
const mpkBytes = G2.BASE.multiply(msk).toRawBytes(true)

const enc = new TextEncoder()
const identity = enc.encode('0x' + 'cd'.repeat(32))
const plaintext = enc.encode('only k-of-n keykeepers can recover this 🔓')

// encrypt to the master public key
const ct = encrypt(mpkBytes, identity, plaintext)
const U = G2.fromHex(ct.u)

// each node's partial decryption + verifying share
function shareFor(id: number): DecryptShare {
  const sk = skBy.get(id)!
  const di = U.multiply(sk).toRawBytes(true) // D_i = sk_i·U  (96B G2)
  const verifyingShare = concatBytes(
    G2.BASE.multiply(sk).toRawBytes(true), // sk_i·g2  (96B G2)
    G1.BASE.multiply(sk).toRawBytes(true), // sk_i·g1  (48B G1)
  )
  return {id, decryptionShare: di, verifyingShare}
}

const subset = [1, 2].map(shareFor)

// 1. combine reconstructs the plaintext (no key assembly).
{
  const out = combineDecryptShares(subset, ct, identity)
  ok('combine: recovers plaintext from k shares', bytesEq(out, plaintext))
}

// 2. agrees with the assemble-then-decrypt path.
{
  const viaMsk = decryptWithMasterKey(scalarToLe(msk), ct, identity)
  const viaShares = combineDecryptShares([1, 3].map(shareFor), ct, identity)
  ok('combine: matches decryptWithMasterKey', bytesEq(viaMsk, viaShares))
}

// 3. a different k-subset yields the same plaintext (Lagrange independence).
{
  const out = combineDecryptShares([2, 3].map(shareFor), ct, identity)
  ok('combine: subset {2,3} agrees', bytesEq(out, plaintext))
}

// 4. pairing verification accepts good shares, rejects a tampered one.
{
  ok('verifyDecryptShare: accepts a valid share', verifyDecryptShare(subset[0]!, ct.u) === true)
  const bad: DecryptShare = {...subset[0]!, decryptionShare: shareFor(2).decryptionShare}
  ok('verifyDecryptShare: rejects a mismatched share', verifyDecryptShare(bad, ct.u) === false)
}

// 5. combine with verify=true aborts on a bad share, naming nobody silently.
{
  const tampered: DecryptShare[] = [{...subset[0]!, decryptionShare: shareFor(3).decryptionShare}, subset[1]!]
  let threw = false
  try {
    combineDecryptShares(tampered, ct, identity, {verify: true})
  } catch {
    threw = true
  }
  ok('combine: verify=true rejects an invalid share', threw)
}

// 6. duplicate identifiers are rejected.
{
  let threw = false
  try {
    combineDecryptShares([subset[0]!, subset[0]!], ct, identity)
  } catch {
    threw = true
  }
  ok('combine: rejects duplicate identifiers', threw)
}

if (failures.length > 0) {
  console.error(`✗ decrypt.shares: ${failures.length} failed:`)
  for (const ferr of failures) console.error('   - ' + ferr)
  process.exit(1)
}
console.log(`✓ decrypt.shares: ${passed} checks passed`)
