// Committee-mode orchestration — offline integration test with a mocked verifier
// fleet. Simulates n verifiers that ed25519-sign the canonical token hash for the
// per-request draw, runs gatherCommitteeToken() against them, and asserts the
// assembled token passes verifyCompoundToken(). Exercises committee discovery,
// quorum collection, the canonical-hash self-check, and wire assembly — without
// a live network. (The token crypto itself is pinned in committee.conformance.ts.)
//
// Run: tsx test/committee.flow.ts — exits non-zero on any failure.

import {ed25519} from '@noble/curves/ed25519'
import {
  selectVerifierCommittee,
  compoundTokenHash,
  decodeCompoundToken,
  verifyCompoundToken,
  type CompoundTokenPayload,
  type VerifierSet,
} from '../src/committee/token.ts'
import {gatherCommitteeToken} from '../src/committee/client.ts'

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
const iat = 1000
const exp = 100_000

// verifier keypairs (deterministic)
const secrets = Array.from({length: registrySize}, (_, i) => fill(32, 0x40 + i))
const pubkeys = secrets.map(s => ed25519.getPublicKey(s))

const drawn = selectVerifierCommittee(slotId, epoch, seed, registrySize, committee)

const payload: CompoundTokenPayload = {
  tokenType: 'JWT',
  seed,
  epoch,
  slotId,
  vpHash,
  holderHash,
  ruleHash,
  verifierIndexes: drawn,
  iat,
  exp,
}
const tokenHash = compoundTokenHash(payload)

// ─── mock verifier fleet ──────────────────────────────────────────────────────
// URLs are http://verifier-<index>; only drawn verifiers reply 200.
const realFetch = globalThis.fetch
function installFleet(onlineSigners: Set<number>) {
  globalThis.fetch = (async (url: string) => {
    const m = /verifier-(\d+)/.exec(String(url))
    const idx = m ? Number(m[1]) : -1
    if (!drawn.includes(idx) || !onlineSigners.has(idx)) {
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

const verifiers = Array.from({length: registrySize}, (_, i) => ({index: i, url: `http://verifier-${i}`}))
const authorize = {
  dcqlRule: 'rule', holder: 'did:example:alice', credentials: ['vc-jwt'],
  holderProof: 'holder-proof-jws',
  tokenType: 'JWT' as const, seed, epoch, slotId, registrySize, committee, iat, exp,
}
const verifierSet: VerifierSet = {registrySize, pubkeys: new Map(pubkeys.map((p, i) => [i, p]))}

try {
  // happy path: all drawn verifiers online → token assembles and verifies.
  {
    installFleet(new Set(drawn))
    const token = await gatherCommitteeToken({verifiers, authorize, quorum})
    ok('gather: verifier_indexes equal the draw', JSON.stringify(token.verifier_indexes) === JSON.stringify(drawn))
    ok('gather: collected ≥ quorum signatures', token.signatures.length >= quorum)
    ok('gather: every signer is in the committee', token.signatures.every(s => drawn.includes(s.verifier_index)))

    const decoded = decodeCompoundToken(token)
    let verifiedOk = false
    try {
      const v = verifyCompoundToken({token: decoded, set: verifierSet, committee, quorum, now: 5000, leeway: 60, slotRuleHash: ruleHash})
      verifiedOk = v.verifiedSigners.length >= quorum
    } catch {
      verifiedOk = false
    }
    ok('verify: assembled token passes verifyCompoundToken', verifiedOk)
  }

  // exactly quorum online → still succeeds.
  {
    installFleet(new Set(drawn.slice(0, quorum)))
    const token = await gatherCommitteeToken({verifiers, authorize, quorum})
    ok('gather: succeeds at exactly quorum', token.signatures.length === quorum)
  }

  // below quorum → throws.
  {
    installFleet(new Set(drawn.slice(0, quorum - 1)))
    let threw = false
    try {
      await gatherCommitteeToken({verifiers, authorize, quorum})
    } catch {
      threw = true
    }
    ok('gather: throws when quorum is not met', threw)
  }

  // per-verifier holder proofs: each verifier must receive ITS OWN proof (a single proof
  // is spent by the first verifier to consume its nonce; the rest would 401).
  {
    installFleet(new Set(drawn))
    const inner = globalThis.fetch
    const seen = new Map<number, string>()
    globalThis.fetch = (async (url: string, init?: {body?: string}) => {
      const idx = Number(/verifier-(\d+)/.exec(String(url))?.[1] ?? -1)
      const sent = JSON.parse(init?.body ?? '{}') as {holder_proof?: string}
      if (sent.holder_proof) seen.set(idx, sent.holder_proof)
      return inner(url, init as RequestInit)
    }) as typeof globalThis.fetch
    const token = await gatherCommitteeToken({
      verifiers,
      authorize,
      quorum,
      holderProofFor: v => `proof-for-${v.index}@${v.url}`,
    })
    ok('gather (per-verifier proofs): token still assembles', token.signatures.length >= quorum)
    ok('gather (per-verifier proofs): every candidate got its own proof', verifiers.every(v => seen.get(v.index) === `proof-for-${v.index}@${v.url}`))
    ok('gather (per-verifier proofs): no two verifiers received the same proof', new Set(seen.values()).size === seen.size)
  }
} finally {
  globalThis.fetch = realFetch
}

if (failures.length > 0) {
  console.error(`✗ committee.flow: ${failures.length} failed:`)
  for (const ferr of failures) console.error('   - ' + ferr)
  process.exit(1)
}
console.log(`✓ committee.flow: ${passed} checks passed`)
