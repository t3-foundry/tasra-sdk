// High-level committee orchestration — offline test of requestCommitteeToken() and
// buildVerifierProofs() against a mocked chain + verifier fleet. Asserts the one-call flow
// reads seed/policy, gathers a quorum, assembles a valid token, and (when the verifier
// directory carries operator+pubkey and an anchored snapshot matches) attaches trustless
// verifier-set inclusion proofs. The token crypto is pinned in committee.conformance.ts.
//
// Run: tsx test/committee.request.ts — exits non-zero on any failure.

import {ed25519} from '@noble/curves/ed25519'
import {
  selectVerifierCommittee,
  compoundTokenHash,
  clientBindingHash,
  decodeCompoundToken,
  verifierLeaf,
  merkleRoot,
  verifyMerkleProof,
  type CompoundTokenPayload,
} from '../src/committee/token.ts'
import {hexToBytes} from '../src/crypto/hex.ts'
import {
  requestCommitteeToken,
  buildVerifierProofs,
  ed25519ClientSigner,
  type CommitteeChainReads,
  type CommitteeVerifier,
} from '../src/committee/request.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean) {
  if (cond) passed++
  else failures.push(name)
}
const bareHex = (b: Uint8Array): string => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')
const fill = (n: number, v: number): Uint8Array => new Uint8Array(n).fill(v)

// ─── scenario ───────────────────────────────────────────────────────────────
const registrySize = 5
const committee = 3
const quorum = 2
const seed = fill(32, 0xab)
const slotId = fill(32, 0xcd)
const vpHash = fill(32, 0x11)
const holderHash = fill(32, 0x1a)
const ruleHash = fill(32, 0x22)
const epoch = 7
const NOW = 1_000_000
const TTL = 300
const iat = NOW - 5
const exp = NOW + TTL

const secrets = Array.from({length: registrySize}, (_, i) => fill(32, 0x40 + i))
const pubkeys = secrets.map(s => ed25519.getPublicKey(s))
const operators = Array.from({length: registrySize}, (_, i) => fill(20, 0x50 + i))
const drawn = selectVerifierCommittee(slotId, epoch, seed, registrySize, committee)

// Full verifier directory (index→url + operator + pubkey → enables proofs).
const dir: CommitteeVerifier[] = Array.from({length: registrySize}, (_, i) => ({
  index: i,
  url: `http://verifier-${i}`,
  operator: '0x' + bareHex(operators[i]!),
  pubkey: '0x' + bareHex(pubkeys[i]!),
}))
const leaves = Array.from({length: registrySize}, (_, i) => verifierLeaf(i, operators[i]!, pubkeys[i]!))
const root = merkleRoot(leaves)!

// The token payload the drawn verifiers sign (deterministic via NOW).
const payload: CompoundTokenPayload = {
  tokenType: 'JWT', seed, epoch, slotId, vpHash, holderHash, ruleHash, verifierIndexes: drawn, iat, exp,
}
const tokenHash = compoundTokenHash(payload)

// ─── mock chain reads ─────────────────────────────────────────────────────────
function chainReads(withSnapshot: boolean): CommitteeChainReads {
  return {
    seed: async () => ('0x' + bareHex(seed)) as `0x${string}`,
    epoch: async () => BigInt(epoch),
    verifierPolicy: async () => [committee, quorum] as const,
    ...(withSnapshot
      ? {snapshot: async () => ({root: ('0x' + bareHex(root)) as `0x${string}`, size: registrySize})}
      : {}),
  }
}

// ─── mock verifier fleet ──────────────────────────────────────────────────────
const realFetch = globalThis.fetch
function installFleet() {
  globalThis.fetch = (async (url: string) => {
    const m = /verifier-(\d+)/.exec(String(url))
    const idx = m ? Number(m[1]) : -1
    if (!drawn.includes(idx)) {
      return {ok: false, status: 403, text: async () => 'not selected'} as unknown as Response
    }
    const signature = ed25519.sign(tokenHash, secrets[idx]!)
    return {
      ok: true,
      status: 200,
      json: async () => ({
        verifier_index: idx,
        token_hash: bareHex(tokenHash),
        vp_hash: bareHex(vpHash),
        holder_hash: bareHex(holderHash),
        rule_hash: bareHex(ruleHash),
        signature: bareHex(signature),
        committee_indexes: drawn,
      }),
    } as unknown as Response
  }) as typeof globalThis.fetch
}

try {
  // ── buildVerifierProofs (pure) ──────────────────────────────────────────────
  {
    const proofs = buildVerifierProofs(dir, registrySize, drawn, root)
    ok('proofs built for the full directory', !!proofs && proofs.length === drawn.length)
    let allVerify = true
    for (const p of proofs ?? []) {
      const leaf = verifierLeaf(p.verifierIndex, operators[p.verifierIndex]!, pubkeys[p.verifierIndex]!)
      if (!verifyMerkleProof(leaf, p.proof.map(hexToBytes), root)) allVerify = false
    }
    ok('every built proof verifies against the anchored root', allVerify)

    // Fail-closed cases → undefined (never a wrong proof).
    ok('root mismatch → undefined', buildVerifierProofs(dir, registrySize, drawn, fill(32, 0xff)) === undefined)
    const partial = dir.slice(0, registrySize - 1) // missing the last index
    ok('partial directory → undefined', buildVerifierProofs(partial, registrySize, drawn) === undefined)
    const noKeys = dir.map(v => ({index: v.index, url: v.url}))
    ok('missing operator/pubkey → undefined', buildVerifierProofs(noKeys, registrySize, drawn) === undefined)
  }

  // ── requestCommitteeToken: full path with trustless proofs ──────────────────
  {
    installFleet()
    const res = await requestCommitteeToken({
      chain: chainReads(true),
      verifiers: dir,
      slotId: '0x' + bareHex(slotId),
      holder: 'did:example:alice',
      credentials: ['vc-jwt'],
      holderProof: 'holder-proof-jws',
      nowSecs: NOW,
      ttlSecs: TTL,
    })
    ok('resolved committee/quorum from policy', res.committee === committee && res.quorum === quorum)
    ok('registrySize from the anchored snapshot', res.registrySize === registrySize)
    ok('token carries the committee draw', JSON.stringify(res.token.verifier_indexes) === JSON.stringify(drawn))
    ok('token has ≥ quorum signatures', res.token.signatures.length >= quorum)
    ok('trustless proofs attached for the signer set', !!res.verifierProofs && res.verifierProofs.length === res.token.signatures.length)
  }

  // ── requestCommitteeToken: client request signature ──────────────
  {
    installFleet()
    const signer = ed25519ClientSigner(fill(32, 0x77))
    const res = await requestCommitteeToken({
      chain: chainReads(true), verifiers: dir, slotId: '0x' + bareHex(slotId), holder: 'did:example:alice', credentials: ['vc-jwt'], holderProof: 'holder-proof-jws',
      nowSecs: NOW, ttlSecs: TTL, clientSigner: signer,
    })
    ok('client signature + pubkey returned', !!res.clientSignature && !!res.clientPubkey)
    // Must verify over clientBindingHash(slotId, tokenHash) under the holder key.
    const tokenHash = compoundTokenHash(decodeCompoundToken(res.token))
    const binding = clientBindingHash(slotId, tokenHash)
    ok(
      'client signature verifies over the request binding',
      ed25519.verify(res.clientSignature!, binding, res.clientPubkey!),
    )
    const noSig = await requestCommitteeToken({
      chain: chainReads(true), verifiers: dir, slotId: '0x' + bareHex(slotId), holder: 'did:example:alice', credentials: ['vc-jwt'], holderProof: 'holder-proof-jws', nowSecs: NOW,
    })
    ok('no clientSigner → no client signature', noSig.clientSignature === undefined)
  }

  // ── requestCommitteeToken: no operator/pubkey → proofs omitted (config fallback) ─
  {
    installFleet()
    const res = await requestCommitteeToken({
      chain: chainReads(false), // no snapshot → registrySize = directory length
      verifiers: dir.map(v => ({index: v.index, url: v.url})), // index+url only
      slotId: '0x' + bareHex(slotId),
      holder: 'did:example:alice',
      credentials: ['vc-jwt'],
      holderProof: 'holder-proof-jws',
      nowSecs: NOW,
      ttlSecs: TTL,
    })
    ok('token still assembles without proofs', res.token.signatures.length >= quorum)
    ok('verifierProofs undefined when keys/snapshot absent', res.verifierProofs === undefined)
  }

  // ── requestCommitteeToken: a slot with no verifierPolicy throws ──────────────
  {
    const noPolicy: CommitteeChainReads = {...chainReads(false), verifierPolicy: async () => [0, 0] as const}
    let threw = false
    try {
      await requestCommitteeToken({
        chain: noPolicy, verifiers: dir, slotId: '0x' + bareHex(slotId), holder: 'did:example:alice', credentials: ['vc-jwt'], holderProof: 'holder-proof-jws', nowSecs: NOW,
      })
    } catch {
      threw = true
    }
    ok('throws when the slot has no verifierPolicy', threw)
  }
} finally {
  globalThis.fetch = realFetch
}

if (failures.length > 0) {
  console.error(`✗ committee.request: ${failures.length} failed:`)
  for (const ferr of failures) console.error('   - ' + ferr)
  process.exit(1)
}
console.log(`✓ committee.request: ${passed} checks passed`)
