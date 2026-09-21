// Lagrange MSK assembly conformance: any k-of-n shard subset must
// interpolate to the same master secret (the polynomial's constant term),
// and duplicate identifiers must be rejected.
//
// Run: tsx test/assemble.lagrange.ts — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {assembleKey, scalarToLe, type Shard} from '../src/crypto/kem.ts'

const {Fr} = bls12_381.fields

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean) {
  if (cond) passed++
  else failures.push(name)
}
function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i])
}

// Secret-sharing polynomial of degree k-1 = 1 (so k=2 reconstructs):
//   f(x) = a0 + a1·x   (over Fr).  The threshold secret is a0 = f(0).
const a0 = 7777777777n
const a1 = 1234567n
const f = (x: bigint): bigint => Fr.add(a0, Fr.mul(a1, x % Fr.ORDER))

// n = 3 shares at ids 1,2,3.
const shares: Shard[] = [1, 2, 3].map(i => ({
  id: i,
  bytes: scalarToLe(f(BigInt(i))),
}))
const expected = scalarToLe(a0)

// Every 2-of-3 subset must reconstruct a0.
for (const [i, j] of [
  [0, 1],
  [0, 2],
  [1, 2],
] as const) {
  const msk = assembleKey([shares[i]!, shares[j]!])
  ok(`assemble: subset (${shares[i]!.id},${shares[j]!.id}) → a0`, bytesEq(msk, expected))
}

// All 3 also reconstruct a0 (over-determined still yields the constant term).
ok('assemble: full set → a0', bytesEq(assembleKey(shares), expected))

// Duplicate identifier must throw.
{
  let threw = false
  try {
    assembleKey([shares[0]!, shares[0]!])
  } catch {
    threw = true
  }
  ok('assemble: duplicate id rejected', threw)
}

// Empty set must throw.
{
  let threw = false
  try {
    assembleKey([])
  } catch {
    threw = true
  }
  ok('assemble: empty set rejected', threw)
}

if (failures.length > 0) {
  console.error(`✗ assemble.lagrange: ${failures.length} failed:`)
  for (const fl of failures) console.error('   - ' + fl)
  process.exit(1)
}
console.log(`✓ assemble.lagrange: ${passed} checks passed`)
