// Crypto round-trip conformance: KEM encrypt→decrypt, AEAD failure on a
// wrong identity, and envelope wire-format (v0x01 + v0x02) round-trips.
//
// Run: tsx test/crypto.roundtrip.ts  — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {encrypt, decryptWithMasterKey, scalarToLe} from '../src/crypto/kem.ts'
import {encryptEnvelope, toBytes, fromBytes, base64Encode, base64Decode, MAX_PLAINTEXT_LEN} from '../src/crypto/envelope.ts'
import {buildTasraText, parseTasraPost} from '../src/crypto/detect.ts'

const G2 = bls12_381.G2

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean) {
  if (cond) passed++
  else failures.push(name)
}
function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i])
}

// Deterministic keypair: msk scalar → mpk = msk·G2.
const mskScalar = 0x123456789abcdefn
const mskBytes = scalarToLe(mskScalar)
const mpkBytes = G2.ProjectivePoint.BASE.multiply(mskScalar).toRawBytes(true)

const enc = new TextEncoder()
const dec = new TextDecoder()
const identity = enc.encode('slot-identity-aad')
const plaintext = enc.encode('only members can read this 🔐')

// 1. KEM round-trip.
{
  const ct = encrypt(mpkBytes, identity, plaintext)
  const out = decryptWithMasterKey(mskBytes, ct, identity)
  ok('kem: round-trip plaintext matches', bytesEq(out, plaintext))
  ok('kem: ciphertext U is 96 bytes (compressed G2)', ct.u.length === 96)
  ok('kem: nonce is 12 bytes', ct.nonce.length === 12)
  ok('kem: aeadCt = plaintext + 16-byte tag', ct.aeadCt.length === plaintext.length + 16)

  // 2. Wrong identity (AAD) must fail authentication.
  let threw = false
  try {
    decryptWithMasterKey(mskBytes, ct, enc.encode('different-aad'))
  } catch {
    threw = true
  }
  ok('kem: wrong identity fails AEAD auth', threw)

  // Wrong key must also fail.
  let threwKey = false
  try {
    decryptWithMasterKey(scalarToLe(mskScalar + 1n), ct, identity)
  } catch {
    threwKey = true
  }
  ok('kem: wrong msk fails AEAD auth', threwKey)
}

// 3. Envelope v0x02 (epoch-carrying) round-trip.
{
  const slotId = new Uint8Array(32).fill(0xab)
  const env = encryptEnvelope(slotId, mpkBytes, identity, plaintext, 7n)
  const wire = toBytes(env)
  const back = fromBytes(wire)
  ok('env v2: version byte 0x02', wire[0] === 0x02)
  ok('env v2: epoch preserved', back.epoch === 7n)
  ok('env v2: slotId preserved', bytesEq(back.slotId, slotId))
  const out = decryptWithMasterKey(mskBytes, back.ciphertext, back.identity)
  ok('env v2: decrypts to plaintext', bytesEq(out, plaintext))
}

// 4. Envelope v0x01 (no epoch) round-trip.
{
  const slotId = new Uint8Array(32).fill(0xcd)
  const env = encryptEnvelope(slotId, mpkBytes, identity, plaintext)
  const wire = toBytes(env)
  const back = fromBytes(wire)
  ok('env v1: version byte 0x01', wire[0] === 0x01)
  ok('env v1: epoch is null', back.epoch === null)
  const out = decryptWithMasterKey(mskBytes, back.ciphertext, back.identity)
  ok('env v1: decrypts to plaintext', bytesEq(out, plaintext))
  ok('env v1: roundtripped plaintext', dec.decode(out) === dec.decode(plaintext))
}

// 5. Large payloads through the wire form. Encoding once spread every byte into one
// `String.fromCharCode` call and threw RangeError past ~124 KiB.
{
  const big = new Uint8Array(MAX_PLAINTEXT_LEN)
  for (let i = 0; i < big.length; i++) big[i] = (i * 31 + 7) & 0xff
  const slotId = new Uint8Array(32).fill(0xef)
  const env = encryptEnvelope(slotId, mpkBytes, identity, big, 3n)
  let text = ''
  let threw = false
  try {
    text = buildTasraText(toBytes(env))
  } catch {
    threw = true
  }
  ok('wire: largest plaintext (1 MiB - 16) encodes without throwing', !threw)
  const parsed = parseTasraPost(text)
  ok('wire: largest envelope parses back', parsed !== null)
  if (parsed) {
    const out = decryptWithMasterKey(mskBytes, parsed.ciphertext, parsed.identity)
    ok('wire: largest plaintext decrypts intact', bytesEq(out, big))
  }
  // One byte more cannot fit an envelope: refused up front, never a clamped, unparseable wire.
  let refused = false
  try {
    encryptEnvelope(slotId, mpkBytes, identity, new Uint8Array(MAX_PLAINTEXT_LEN + 1))
  } catch {
    refused = true
  }
  ok('wire: plaintext past the cap is refused by encryptEnvelope', refused)
  let refusedBytes = false
  try {
    toBytes({...env, ciphertext: {...env.ciphertext, aeadCt: new Uint8Array(MAX_PLAINTEXT_LEN + 17)}})
  } catch {
    refusedBytes = true
  }
  ok('wire: an oversized hand-built envelope is refused by toBytes', refusedBytes)
  // An epoch past 2^63 - 1 would be written as a negative number that no parser accepts.
  let refusedEpoch = false
  try {
    encryptEnvelope(slotId, mpkBytes, identity, new Uint8Array(1), 1n << 63n)
  } catch {
    refusedEpoch = true
  }
  ok('envelope: an epoch past 2^63 - 1 is refused by encryptEnvelope', refusedEpoch)
  let refusedEpochBytes = false
  try {
    toBytes({...env, epoch: 1n << 63n})
  } catch {
    refusedEpochBytes = true
  }
  ok('envelope: an epoch past 2^63 - 1 is refused by toBytes', refusedEpochBytes)
  const largest = fromBytes(toBytes({...env, epoch: (1n << 63n) - 1n}))
  ok('envelope: the largest epoch round-trips', largest.epoch === (1n << 63n) - 1n)
  // Chunk boundaries and sizes on both sides of the old limit match Node's encoder exactly.
  for (const n of [0, 1, 2, 3, 0x7fff, 0x8000, 0x8001, 3 * 0x8000 + 5, 200 * 1024]) {
    const bytes = big.subarray(0, n)
    const b64 = base64Encode(bytes)
    ok(`base64: ${n} bytes matches Buffer`, b64 === Buffer.from(bytes).toString('base64'))
    ok(`base64: ${n} bytes round-trips`, bytesEq(base64Decode(b64), bytes))
  }
}

if (failures.length > 0) {
  console.error(`✗ crypto.roundtrip: ${failures.length} failed:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ crypto.roundtrip: ${passed} checks passed`)
