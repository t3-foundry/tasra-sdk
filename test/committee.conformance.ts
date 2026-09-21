// compound-token conformance + round-trip harness.
//
// Pins the TypeScript committee module (src/committee/token.ts) against vectors computed from the
// the reference implementation: committee selection,
// the canonical token hash, the keeper op-attestation hash, and the verifier-set Merkle leaf.
// A divergence is a silent-authorization bug. Also round-trips a real ed25519 quorum through
// assemble → decode → verifyCompoundToken (and asserts tamper detection).
//
// Run:  tsx test/committee.conformance.ts   — exits non-zero on any mismatch.

import {readFileSync} from 'node:fs'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {ed25519} from '@noble/curves/ed25519'
import {keccak_256} from '@noble/hashes/sha3'

import {
  selectVerifierCommittee,
  compoundTokenHash,
  opAttestationHash,
  clientBindingHash,
  verifierLeaf,
  verifyMerkleProof,
  merkleRoot,
  merkleProof,
  verifyCompoundToken,
  assembleCompoundToken,
  decodeCompoundToken,
  type CompoundTokenPayload,
  type CommitteeSignature,
  type VerifierSet,
} from '../src/committee/token.ts'
import {hexToBytes, bytesToHex} from '../src/crypto/hex.ts'

interface TokenVector {
  token_type: 'JWT' | 'refresh'
  seed: string
  epoch: number
  slot_id: string
  vp_hash: string
  holder_hash: string
  rule_hash: string
  identity_hash?: string
  verifier_indexes: number[]
  iat: number
  exp: number
  signing_hash: string
}

interface Vectors {
  selection: {slot_id: string; epoch: number; seed: string; registry_size: number; count: number; indexes: number[]}[]
  token: TokenVector
  /** the identity-scoped variant — pins the presence-byte encoding. */
  token_scoped: TokenVector & {identity_hash: string}
  op_attestation: {chain_id: number; op_id: string; slot_id: string; token_hash: string; hash: string}
  verifier_leaf: {index: number; operator: string; pubkey: string; leaf: string}
  client_binding: {slot_id: string; token_hash: string; hash: string}
}

const here = dirname(fileURLToPath(import.meta.url))
const v = JSON.parse(readFileSync(join(here, 'committee-token-vectors.json'), 'utf8')) as Vectors

let passed = 0
const failures: string[] = []

function check(name: string, cond: boolean, detail = '') {
  if (cond) passed++
  else failures.push(`${name}${detail ? `: ${detail}` : ''}`)
}

// ─── 1. Committee selection ─────────────────────────────────────────────
for (const row of v.selection) {
  const got = selectVerifierCommittee(hexToBytes(row.slot_id), row.epoch, hexToBytes(row.seed), row.registry_size, row.count)
  check(
    `selection ${row.registry_size}/${row.count}`,
    got.length === row.indexes.length && got.every((x, i) => x === row.indexes[i]),
    `got [${got}] want [${row.indexes}]`,
  )
}

// ─── 2. Canonical token hash ────────────────────────────────────────────
function payloadOf(t: TokenVector): CompoundTokenPayload {
  return {
    tokenType: t.token_type,
    seed: hexToBytes(t.seed),
    epoch: t.epoch,
    slotId: hexToBytes(t.slot_id),
    vpHash: hexToBytes(t.vp_hash),
    holderHash: hexToBytes(t.holder_hash),
    ruleHash: hexToBytes(t.rule_hash),
    ...(t.identity_hash !== undefined ? {identityHash: hexToBytes(t.identity_hash)} : {}),
    // Vectors use the default Unbound (0x00) — the binding byte is always present in
    // canonical_bytes via the `?? 0x00` fallback.
    verifierIndexes: t.verifier_indexes,
    iat: t.iat,
    exp: t.exp,
  }
}
{
  const t = v.token
  const payload = payloadOf(t)
  check('token signing_hash', bytesToHex(compoundTokenHash(payload)) === t.signing_hash, bytesToHex(compoundTokenHash(payload)))
}
// The identity-scoped variant pins the presence-byte encoding — a None-only
// vector would leave the Some branch unpinned, and the two hashes must differ.
{
  const t = v.token_scoped
  const payload = payloadOf(t)
  check('scoped token signing_hash', bytesToHex(compoundTokenHash(payload)) === t.signing_hash, bytesToHex(compoundTokenHash(payload)))
  check('scoped token hash differs from unscoped', t.signing_hash !== v.token.signing_hash)
}

// ─── 3. Keeper op-attestation hash ──────────────────────────────────────
{
  const o = v.op_attestation
  const got = bytesToHex(opAttestationHash(o.chain_id, hexToBytes(o.op_id), hexToBytes(o.slot_id), hexToBytes(o.token_hash)))
  check('op_attestation hash', got === o.hash, got)
}

// ─── 4. Verifier-set Merkle leaf ────────────────────────────────────────
{
  const l = v.verifier_leaf
  const got = bytesToHex(verifierLeaf(l.index, hexToBytes(l.operator), hexToBytes(l.pubkey)))
  check('verifier_leaf', got === l.leaf, got)
}

// ─── 4b. Client request-binding hash ─────────────────────────
{
  const c = v.client_binding
  const got = bytesToHex(clientBindingHash(hexToBytes(c.slot_id), hexToBytes(c.token_hash)))
  check('client_binding hash', got === c.hash, got)
}

// ─── 5. Merkle proof round-trip (sorted-pair) ───────────────────────────
{
  // Build a 5-leaf tree, prove index 2, verify; tamper → reject.
  const leaves = [0, 1, 2, 3, 4].map(i => verifierLeaf(i, new Uint8Array(20).fill(i), new Uint8Array(32).fill(i + 1)))
  const hashPair = (a: Uint8Array, b: Uint8Array) => {
    // local reference of the sorted-pair combine to build a root + proof for the test
    const cmp = (x: Uint8Array, y: Uint8Array) => {
      for (let i = 0; i < 32; i++) if (x[i] !== y[i]) return x[i]! < y[i]! ? -1 : 1
      return 0
    }
    const [lo, hi] = cmp(a, b) <= 0 ? [a, b] : [b, a]
    const out = new Uint8Array(64)
    out.set(lo, 0)
    out.set(hi, 32)
    return keccak_256(out)
  }
  // level 0 -> 1: (0,1)(2,3)(4)
  const l01 = hashPair(leaves[0]!, leaves[1]!)
  const l23 = hashPair(leaves[2]!, leaves[3]!)
  const l4 = leaves[4]!
  // level 1 -> 2: (l01,l23)(l4)
  const l0123 = hashPair(l01, l23)
  // level 2 -> root: (l0123, l4)
  const root = hashPair(l0123, l4)
  // proof for index 2: sibling leaves[3], then l01, then l4
  const proof = [leaves[3]!, l01, l4]
  check('merkle proof verifies', verifyMerkleProof(leaves[2]!, proof, root))
  check('merkle proof rejects tampered leaf', !verifyMerkleProof(leaves[1]!, proof, root))

  // The build helpers (merkleRoot / merkleProof) must reproduce the hand-computed
  // reference tree exactly — pins them to the on-chain/the reference implementation sorted-pair convention.
  check('merkleRoot matches the hand-built root', bytesToHex(merkleRoot(leaves)!) === bytesToHex(root))
  check(
    'merkleProof(index 2) equals the hand-built proof',
    JSON.stringify(merkleProof(leaves, 2)!.map(bytesToHex)) === JSON.stringify(proof.map(bytesToHex)),
  )
  const builtRoot = merkleRoot(leaves)!
  let allVerify = true
  for (let i = 0; i < leaves.length; i++) {
    if (!verifyMerkleProof(leaves[i]!, merkleProof(leaves, i)!, builtRoot)) allVerify = false
  }
  check('every merkleProof verifies against merkleRoot (odd + even indexes)', allVerify)
  check('merkleProof out of range → null', merkleProof(leaves, 5) === null)
}

// ─── 6. ed25519 quorum round-trip (assemble → decode → verify) ──────────
{
  const REGISTRY = 16
  const COMMITTEE = 3
  const QUORUM = 3
  const vpHash = new Uint8Array(32).fill(0xab)
  const holderHash = new Uint8Array(32).fill(0xbc)
  const seed = new Uint8Array(32).fill(0x11)
  const slotRule = new Uint8Array(32).fill(0x55)

  // Deterministic verifier keys for the whole registry.
  const priv: Uint8Array[] = []
  const pubkeys = new Map<number, Uint8Array>()
  for (let i = 0; i < REGISTRY; i++) {
    const sk = new Uint8Array(32)
    sk[0] = i + 1
    sk[1] = 0xa5
    priv.push(sk)
    pubkeys.set(i, ed25519.getPublicKey(sk))
  }
  const set: VerifierSet = {registrySize: REGISTRY, pubkeys}

  const indexes = selectVerifierCommittee(new Uint8Array(32).fill(0x22), 7, seed, REGISTRY, COMMITTEE)
  const payload: CompoundTokenPayload = {
    tokenType: 'JWT',
    seed,
    epoch: 7,
    slotId: new Uint8Array(32).fill(0x22),
    vpHash,
    holderHash,
    ruleHash: slotRule,
    verifierIndexes: indexes,
    iat: 1000,
    exp: 2000,
  }
  const hash = compoundTokenHash(payload)
  const sigs: CommitteeSignature[] = indexes.map(i => ({verifierIndex: i, signature: ed25519.sign(hash, priv[i]!)}))

  // assemble → JSON → decode round-trips, and the full quorum verifies.
  const wire = assembleCompoundToken(payload, sigs)
  const decoded = decodeCompoundToken(JSON.parse(JSON.stringify(wire)))
  try {
    const res = verifyCompoundToken({token: decoded, set, committee: COMMITTEE, quorum: QUORUM, now: 1500, leeway: 30, slotRuleHash: slotRule})
    check('quorum round-trip verifies', res.verifiedSigners.length === 3)
  } catch (e) {
    check('quorum round-trip verifies', false, e instanceof Error ? e.message : String(e))
  }

  // sub-quorum is rejected.
  const subWire = assembleCompoundToken(payload, sigs.slice(0, 2))
  let subRejected = false
  try {
    verifyCompoundToken({token: decodeCompoundToken(subWire), set, committee: COMMITTEE, quorum: QUORUM, now: 1500, leeway: 30, slotRuleHash: slotRule})
  } catch {
    subRejected = true
  }
  check('sub-quorum rejected', subRejected)

  // rule mismatch is rejected.
  let ruleRejected = false
  try {
    verifyCompoundToken({token: decoded, set, committee: COMMITTEE, quorum: QUORUM, now: 1500, leeway: 30, slotRuleHash: new Uint8Array(32).fill(0x66)})
  } catch {
    ruleRejected = true
  }
  check('rule-mismatch rejected', ruleRejected)

  // a forged signature is rejected.
  const forged = [...sigs]
  forged[0] = {verifierIndex: indexes[0]!, signature: new Uint8Array(64)}
  let forgeRejected = false
  try {
    verifyCompoundToken({token: decodeCompoundToken(assembleCompoundToken(payload, forged)), set, committee: COMMITTEE, quorum: QUORUM, now: 1500, leeway: 30, slotRuleHash: slotRule})
  } catch {
    forgeRejected = true
  }
  check('forged-signature rejected', forgeRejected)

  // expired token is rejected.
  let expRejected = false
  try {
    verifyCompoundToken({token: decoded, set, committee: COMMITTEE, quorum: QUORUM, now: 9000, leeway: 30, slotRuleHash: slotRule})
  } catch {
    expRejected = true
  }
  check('expired rejected', expRejected)
}

const total = passed + failures.length
if (failures.length > 0) {
  console.error(`committee conformance: ${passed}/${total} passed\n`)
  for (const f of failures) console.error('  FAIL:', f)
  process.exit(1)
}
console.log(`committee conformance: ${passed}/${total} passed`)
