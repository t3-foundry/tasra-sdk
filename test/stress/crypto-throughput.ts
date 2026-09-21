// Stress: client-side crypto throughput (no fleet needed). Measures the raw
// ops/sec the SDK sustains for the operations that run in-process: envelope
// ENCRYPT, ENCRYPT→DECRYPT round-trip, and Lagrange shard ASSEMBLY. An HTTP load
// generator cannot exercise the noble crypto, so this is where "how fast can we
// encrypt/decrypt" lives.
//
// Run: tsx test/stress/crypto-throughput.ts   (KK_CRYPTO_ITERS=2000  KK_K=3  KK_N=5)

import {randomBytes} from 'node:crypto'
import {bls12_381} from '@noble/curves/bls12-381'
import {Suite, metric} from '../fleet/_assert.ts'
import {assembleKey, decryptWithMasterKey, leToScalar, scalarToLe, type Shard} from '../../src/crypto/kem.ts'
import {encryptEnvelope, fromBytes, toBytes} from '../../src/crypto/envelope.ts'

const G2 = bls12_381.G2
const Fr = bls12_381.fields.Fr
const ITERS = Number(process.env.KK_CRYPTO_ITERS || 2000)
const K = Number(process.env.KK_K || 3)
const N = Number(process.env.KK_N || 5)
const s = new Suite('stress: client-side crypto throughput')

// A uniform non-zero scalar in [1, Fr.ORDER). leToScalar rejects non-canonical
// bytes, so reduce the raw random bytes mod the field order ourselves.
function randScalar(): bigint {
  const b = randomBytes(32)
  let x = 0n
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]!) // little-endian
  return Fr.create(x) || 1n
}

function bench(label: string, iters: number, fn: () => void): number {
  for (let i = 0; i < Math.min(50, iters); i++) fn() // warm up
  const t0 = process.hrtime.bigint()
  for (let i = 0; i < iters; i++) fn()
  const ms = Number(process.hrtime.bigint() - t0) / 1e6
  const ops = (iters / ms) * 1000
  s.info(`${label}: ${ops.toFixed(0)} ops/s  (${(ms / iters).toFixed(3)} ms/op, ${iters} iters)`)
  metric(`crypto: ${label}`, Math.round(ops), 'ops/s')
  return ops
}

// Deterministic-ish keypair: msk scalar → mpk = msk·G2.
const sk = randScalar()
const mskBytes = scalarToLe(sk)
const mpkBytes = G2.ProjectivePoint.BASE.multiply(sk).toRawBytes(true)

const enc = new TextEncoder()
const slotId = new Uint8Array(randomBytes(32))
const identity = enc.encode('throughput-bench')
const plaintext = enc.encode('a representative chat message of moderate length 🔐')

// 1. ENCRYPT
const encOps = bench('encrypt', ITERS, () => {
  encryptEnvelope(slotId, mpkBytes, identity, plaintext, 0n)
})

// 2. ENCRYPT → serialize → parse → DECRYPT (full round-trip)
const rtOps = bench('encrypt+decrypt round-trip', ITERS, () => {
  const env = encryptEnvelope(slotId, mpkBytes, identity, plaintext, 0n)
  const back = fromBytes(toBytes(env))
  decryptWithMasterKey(mskBytes, back.ciphertext, back.identity)
})

// 3. Lagrange ASSEMBLY of k shards (the per-message client cost of "using a key")
// Build a degree-(k-1) polynomial with constant term = sk; shard i = f(i).
const coeffs = [sk, ...Array.from({length: K - 1}, () => randScalar())]
const f = (x: bigint) => coeffs.reduce((acc, c, j) => Fr.add(acc, Fr.mul(c, Fr.pow(x, BigInt(j)))), 0n)
const allShards: Shard[] = Array.from({length: N}, (_, i) => ({id: i + 1, bytes: scalarToLe(f(BigInt(i + 1)))}))
const subset = allShards.slice(0, K)
// correctness sanity: assembled constant term == sk
s.ok('assembled key == secret (Lagrange correctness)', leToScalar(assembleKey(subset)) === sk)
const asmOps = bench(`assemble ${K}-of-${N} shards`, ITERS, () => {
  assembleKey(subset)
})

s.ok('encrypt throughput > 0', encOps > 0)
s.ok('round-trip throughput > 0', rtOps > 0)
s.ok('assemble throughput > 0', asmOps > 0)

s.done()
