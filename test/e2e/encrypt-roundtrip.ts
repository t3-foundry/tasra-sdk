// E2E headline: the full client capability against the REAL fleet.
//
//   verify (mint JWT) → fetch MPK → fetch k-of-n shards → Lagrange-assemble MSK
//   → encrypt an envelope → serialize → decrypt → plaintext matches.
//
// Plus the security invariants: the assembled secret key matches the slot's
// PUBLISHED public key (msk·G2 == mpk), a tampered ciphertext fails AEAD, and a
// wrong AAD fails. This is the one suite that exercises every moving part.
//
// Run: tsx test/e2e/encrypt-roundtrip.ts

import {bls12_381} from '@noble/curves/bls12-381'
import {Suite, bytesEq} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig, mintEngineeringJwt} from '../fleet/_fleet.ts'
import {fetchAndAssembleKey, fetchMpk} from '../../src/keys/node-client.ts'
import {decryptWithMasterKey, leToScalar} from '../../src/crypto/kem.ts'
import {encryptEnvelope, fromBytes, toBytes} from '../../src/crypto/envelope.ts'
import {buildTasraText, parseTasraPost} from '../../src/crypto/detect.ts'
import {hexToBytes} from '../../src/crypto/hex.ts'

const G2 = bls12_381.G2
const cfg = loadFleetConfig()
const s = new Suite('e2e: encrypt/decrypt round-trip (real shards)')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}
if (!cfg.slotId) {
  s.ok('demo slot id present', false, 'set KK_SLOT_ID or run make fleet-up')
  s.done()
  process.exit(1)
}

const committee = await discoverCommittee(cfg, cfg.slotId)
s.ok('committee discovered', committee.length >= 2, `found ${committee.length}`)

// 1. Mint a real JWT (DCQL-gated) and fetch the slot's public key.
const jwt = await mintEngineeringJwt(cfg)
s.ok('verifier minted a JWT for the Engineering VP', !!jwt.token)

const {mpkBytes, epoch} = await fetchMpk(committee[0]!, cfg.slotId)
s.ok('fetched MPK (96-byte compressed G2)', mpkBytes.length === 96, `len=${mpkBytes.length}`)
s.info(`epoch ${epoch}`)

// 2. Fan out to k-of-n nodes and Lagrange-assemble the master secret key.
const msk = await fetchAndAssembleKey({urls: cfg.nodeUrls, jwt: jwt.token}, cfg.slotId)
s.ok('assembled a 32-byte MSK from real shards', msk.length === 32, `len=${msk.length}`)

// 3. The assembled secret must match the PUBLISHED public key: msk·G2 == mpk.
//    This is the cryptographic proof that the shards reconstruct the right key.
const mskScalar = leToScalar(msk)
const derivedMpk = G2.ProjectivePoint.BASE.multiply(mskScalar).toRawBytes(true)
s.ok('assembled MSK matches the slot public key (msk·G2 == mpk)', bytesEq(derivedMpk, mpkBytes))

// 4. Encrypt → serialize → parse → decrypt round-trip.
const enc = new TextEncoder()
const dec = new TextDecoder()
const slotId = hexToBytes(cfg.slotId)
const identity = enc.encode(`e2e-${cfg.slotId.slice(0, 10)}`)
const plaintext = enc.encode('only Engineering members can read this 🔐')

const env = encryptEnvelope(slotId, mpkBytes, identity, plaintext, BigInt(epoch))
const wire = toBytes(env)
const post = buildTasraText(wire)
s.ok('envelope wraps to a [KK] transport string', post.startsWith('[KK]'))

const parsed = parseTasraPost(post)
s.ok('[KK] string parses back to an envelope', parsed !== null)
if (parsed) {
  s.ok('parsed slotId preserved', bytesEq(parsed.slotId, slotId))
  const out = decryptWithMasterKey(msk, parsed.ciphertext, parsed.identity)
  s.ok('decrypts to the original plaintext', bytesEq(out, plaintext))
  s.eq('plaintext text matches', dec.decode(out), dec.decode(plaintext))
}

// 5. Security invariants: tamper + wrong AAD must fail authentication.
{
  const bad = fromBytes(wire)
  bad.ciphertext.aeadCt[0]! ^= 0xff // flip a ciphertext byte
  let threw = false
  try {
    decryptWithMasterKey(msk, bad.ciphertext, bad.identity)
  } catch {
    threw = true
  }
  s.ok('tampered ciphertext fails AEAD auth', threw)
}
{
  let threw = false
  try {
    decryptWithMasterKey(msk, env.ciphertext, enc.encode('wrong-identity'))
  } catch {
    threw = true
  }
  s.ok('wrong identity (AAD) fails AEAD auth', threw)
}

s.done()
