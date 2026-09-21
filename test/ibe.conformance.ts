// BF-IBE cross-language conformance harness.
//
// Runs test/ibe-vectors.json through the shipped functions in src/crypto/ibe.ts. The
// vectors were computed by the reference implementation, not by this code, so the suite
// can only pass by being right — a port checked against itself passes when both halves
// are wrong.
//
// The deterministic-encrypt leg is load-bearing: reproducing the vector's exact
// ciphertext for its fixed `r` proves this encrypt is decryptable by the reference
// implementation, without needing it present.

import {readFileSync} from 'node:fs'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'

import {
  ibeEncryptWithScalar,
  ibeEncrypt,
  ibeHashIdentityToG1,
  ibeSharedGtBytes,
  ibeVerifyShare,
  ibeCombineExtract,
  ibeCombineDecrypt,
  ibeDecryptWithKey,
  type IbeDecryptionShare,
} from '../src/crypto/ibe.ts'
import {leToScalar} from '../src/crypto/kem.ts'
import {bls12_381} from '@noble/curves/bls12-381'

interface Vectors {
  suite: {hash_to_g1_dst: string; domain: string}
  threshold: {k: number; n: number}
  msk_le: string
  mpk: string
  identity: string
  plaintext: string
  r_le: string
  q_id: string
  gt_shared: string
  ciphertext: {u: string; nonce: string; aead_ct: string}
  shares: {identifier: number; d_i: string}[]
  verifying_shares: {identifier: number; g2: string; g1: string}[]
  tamper: {identifier: number; d_i: string}
}

const here = dirname(fileURLToPath(import.meta.url))
const localPath = join(here, 'ibe-vectors.json')
const localRaw = readFileSync(localPath, 'utf8')
const v = JSON.parse(localRaw) as Vectors

// test/ibe-vectors.json is vendored: it is the reference this suite runs against.
// Refreshing it is a manual step (see CONTRIBUTING.md) — nothing here detects a
// change made on the producing side.

const unhex = (s: string) => Uint8Array.from(Buffer.from(s.slice(2), 'hex'))
const hx = (b: Uint8Array) => '0x' + Buffer.from(b).toString('hex')

let passed = 0
const failures: string[] = []
function check(name: string, cond: boolean, detail = '') {
  if (cond) passed++
  else failures.push(`${name}${detail ? `: ${detail}` : ''}`)
}

const identity = new TextEncoder().encode(v.identity)
const mpk = unhex(v.mpk)
const plaintext = unhex(v.plaintext)
const r = leToScalar(unhex(v.r_le))
const vsMap = new Map(v.verifying_shares.map(e => [e.identifier, unhex(e.g2)]))
const shares: IbeDecryptionShare[] = v.shares.map(s => ({
  identifier: s.identifier,
  value: unhex(s.d_i),
}))
const ct = {u: unhex(v.ciphertext.u), nonce: unhex(v.ciphertext.nonce), aeadCt: unhex(v.ciphertext.aead_ct)}

// ── 1. intermediates: hash-to-curve suite/DST, then the Fp12 byte layout ─────
check('q_id (hash-to-G1 suite + DST)', hx(ibeHashIdentityToG1(identity)) === v.q_id, hx(ibeHashIdentityToG1(identity)))
check('gt_shared (Fp12 byte layout)', hx(ibeSharedGtBytes(mpk, identity, r)) === v.gt_shared)

// ── 2. deterministic encrypt reproduces the reference implementation's exact ciphertext ──────────────
{
  const got = ibeEncryptWithScalar(mpk, identity, plaintext, r)
  check('ciphertext.u', hx(got.u) === v.ciphertext.u)
  check('ciphertext.nonce', hx(got.nonce) === v.ciphertext.nonce)
  check('ciphertext.aead_ct (KDF + AEAD framing)', hx(got.aeadCt) === v.ciphertext.aead_ct)
}

// ── 3. every real share verifies; the tampered one is REFUSED, by name ───────
for (const s of shares) {
  try {
    ibeVerifyShare(vsMap, identity, s)
    passed++
  } catch (e) {
    failures.push(`share ${s.identifier} should verify: ${e instanceof Error ? e.message : e}`)
  }
}
{
  let threw = ''
  try {
    ibeVerifyShare(vsMap, identity, {identifier: v.tamper.identifier, value: unhex(v.tamper.d_i)})
  } catch (e) {
    threw = e instanceof Error ? e.message : String(e)
  }
  check(
    'tampered share refused, naming the node',
    threw.includes(`${v.tamper.identifier}`),
    threw || 'no error thrown — identifiable abort is vacuous',
  )
}

// ── 4. combine: any k of n subsets decrypt the reference implementation's ciphertext ─────────────────
for (const subset of [[0, 1], [0, 2], [1, 2], [0, 1, 2]]) {
  const picked = subset.map(i => shares[i]!)
  try {
    const out = ibeCombineDecrypt(vsMap, picked, ct, identity)
    check(`combine-decrypt shares [${subset}]`, hx(out) === v.plaintext)
  } catch (e) {
    failures.push(`combine-decrypt [${subset}]: ${e instanceof Error ? e.message : e}`)
  }
}

// ── 5. msk cross-check: sk_ID = msk·Q_ID equals the Lagrange combination ─────
{
  const msk = leToScalar(unhex(v.msk_le))
  const qId = bls12_381.G1.ProjectivePoint.fromHex(ibeHashIdentityToG1(identity))
  const skDirect = qId.multiply(msk).toRawBytes(true)
  const skCombined = ibeCombineExtract(vsMap, shares.slice(0, 2), identity)
  check('sk_ID: direct msk·Q_ID == Lagrange-combined shares', hx(skDirect) === hx(skCombined))
  const out = ibeDecryptWithKey(skCombined, ct, identity)
  check('extracted-key decrypt (custody path)', hx(out) === v.plaintext)
}

// ── 6. self round-trip with a RANDOM r against the same key material ─────────
{
  const msg = new TextEncoder().encode('fresh message, fresh r')
  const fresh = ibeEncrypt(mpk, identity, msg)
  const out = ibeCombineDecrypt(vsMap, shares.slice(1), fresh, identity)
  check('random-r encrypt → combine-decrypt round-trip', hx(out) === hx(msg))
}

// ─── report ──────────────────────────────────────────────────────────────────
const total = 2 + 3 + v.shares.length + 1 + 4 + 2 + 1
if (failures.length > 0) {
  console.error(`IBE conformance: ${failures.length} FAILED of ${total}`)
  for (const f of failures) console.error(`  ✗ ${f}`)
  process.exit(1)
}
console.log(`IBE conformance: ${passed}/${total} passed (the reference implementation-generated vectors, shipped functions)`)
