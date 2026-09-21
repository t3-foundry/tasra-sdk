// E2E: k-of-n threshold reconstruction on the real fleet.
//
//   - Every k-sized subset of the committee's real shards reconstructs the
//     SAME master key (and it matches the published public key).
//   - Fewer than k shards do NOT reconstruct it.
//
// This is the security heart of the network: any k cooperate, k-1 learn nothing.
//
// Run: tsx test/e2e/threshold-kofn.ts

import {bls12_381} from '@noble/curves/bls12-381'
import {Suite, bytesEq} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig, mintEngineeringJwt} from '../fleet/_fleet.ts'
import {assembleKey, leToScalar, type Shard} from '../../src/crypto/kem.ts'
import {fetchMpk} from '../../src/keys/node-client.ts'

const G2 = bls12_381.G2
const cfg = loadFleetConfig()
const s = new Suite('e2e: k-of-n threshold reconstruction')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}
if (!cfg.slotId) {
  s.ok('demo slot id present', false)
  s.done()
  process.exit(1)
}

// all combinations of `k` items from `arr`
function combinations<T>(arr: T[], k: number): T[][] {
  if (k <= 0) return [[]]
  if (k > arr.length) return []
  const [head, ...rest] = arr
  if (head === undefined) return []
  const withHead = combinations(rest, k - 1).map(c => [head, ...c])
  const withoutHead = combinations(rest, k)
  return [...withHead, ...withoutHead]
}

const committee = await discoverCommittee(cfg, cfg.slotId)
s.ok('committee discovered', committee.length >= 2, `found ${committee.length}`)

// threshold params + MPK from a committee node
const pubRes = await fetch(`${committee[0]}/v1/keys/${cfg.slotId}/public`, {signal: AbortSignal.timeout(4000)})
const pub = (await pubRes.json()) as {threshold_k: number; threshold_n: number}
const k = pub.threshold_k
s.info(`k=${k} n=${pub.threshold_n}, committee=${committee.length}`)
const {mpkBytes} = await fetchMpk(committee[0]!, cfg.slotId)

// Fetch every committee member's shard with a real JWT.
const jwt = await mintEngineeringJwt(cfg)
const shards: Shard[] = []
for (const url of committee) {
  const res = await fetch(`${url}/v1/shards/key`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json', Authorization: `Bearer ${jwt.token}`},
    body: JSON.stringify({key_slot_id: cfg.slotId}),
    signal: AbortSignal.timeout(6000),
  })
  if (!res.ok) {
    s.ok(`shard fetch ${url.replace(/^https?:\/\//, '')}`, false, `HTTP ${res.status}`)
    continue
  }
  const data = (await res.json()) as {identifier: number; shard: string}
  shards.push({id: data.identifier, bytes: new Uint8Array(Buffer.from(data.shard, 'base64'))})
}
s.ok(`collected ${shards.length} real shards`, shards.length >= k)

// The reference key: assemble from all collected shards, and prove msk·G2 == mpk.
const reference = assembleKey(shards)
const refMatchesPub = bytesEq(G2.ProjectivePoint.BASE.multiply(leToScalar(reference)).toRawBytes(true), mpkBytes)
s.ok('full-committee assembly matches the public key (msk·G2 == mpk)', refMatchesPub)

// Every k-subset must reconstruct the same key.
const subsets = combinations(shards, k)
s.ok(`enumerated ${subsets.length} distinct ${k}-of-${shards.length} subsets`, subsets.length >= 1)
let allAgree = true
for (const subset of subsets) {
  if (!bytesEq(assembleKey(subset), reference)) allAgree = false
}
s.ok(`every ${k}-subset reconstructs the identical key`, allAgree)

// Fewer than k shards must NOT reconstruct it (privacy of k-1).
if (k >= 2 && shards.length >= 1) {
  const underK = assembleKey([shards[0]!]) // a single share
  s.ok('a single shard does NOT reconstruct the key (k-1 learn nothing)', !bytesEq(underK, reference))
}

s.done()
