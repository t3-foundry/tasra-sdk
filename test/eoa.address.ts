// EOA address derivation — offline known-answer test for addressFromEoaPubkey.
// Uses the canonical secp256k1 → Ethereum address vectors (private keys 1/2/3).
//
// Run: tsx test/eoa.address.ts — exits non-zero on any failure.

import {secp256k1} from '@noble/curves/secp256k1'
import {hexToBytes} from '@noble/hashes/utils'
import {addressFromEoaPubkey} from '../src/signing/ecdsa.ts'

let passed = 0
const failures: string[] = []
const ok = (name: string, cond: boolean) => {
  if (cond) passed++
  else failures.push(name)
}

// [private key (32-byte hex), expected EIP-55 checksummed address]
const vectors: Array<[string, string]> = [
  ['0000000000000000000000000000000000000000000000000000000000000001', '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf'],
  ['0000000000000000000000000000000000000000000000000000000000000002', '0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF'],
  ['0000000000000000000000000000000000000000000000000000000000000003', '0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69'],
]

for (const [privHex, expected] of vectors) {
  const priv = hexToBytes(privHex)
  const compressed = secp256k1.getPublicKey(priv, true) // 33B
  const uncompressed = secp256k1.getPublicKey(priv, false) // 65B
  ok(`compressed (33B) → ${expected}`, compressed.length === 33 && addressFromEoaPubkey(compressed) === expected)
  ok(`uncompressed (65B) → ${expected}`, uncompressed.length === 65 && addressFromEoaPubkey(uncompressed) === expected)
}

// The result is EIP-55 mixed-case, not a lowercased address.
const a0 = addressFromEoaPubkey(secp256k1.getPublicKey(hexToBytes(vectors[0]![0]), true))
ok('returns EIP-55 mixed-case (not lowercased)', a0 !== vectors[0]![1].toLowerCase() && a0.toLowerCase() === vectors[0]![1].toLowerCase())

if (failures.length > 0) {
  console.error(`✗ eoa.address: ${failures.length} failed:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ eoa.address: ${passed} checks passed`)
