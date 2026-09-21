// E2E: SLOT LIFECYCLE on the prod fleet — list, get, mode-filter, rotate.
//
// A sovereign client creates a BLS slot (commit-reveal); we read it back via
// /v1/keys (list + mode filter) and /v1/keys/:id, then rotate it through the chain owner API
// and assert the committee re-keys to a higher epoch.
//
// Operator JWT authorizes administrative reads; the creator signs rotation on chain. Run: tsx test/e2e/slot-lifecycle.ts

import {parseEther} from 'viem'
import {Suite} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig, mintLocalJwt, provisionRule} from '../fleet/_fleet.ts'
import {createTasraWriteClient, generateClientKey} from '../../src/chain/write.ts'
import {WALLET_RULE as SLOT_DCQL_RULE} from '../fleet/_wallet.ts'
import {httpFaucet} from '../../src/slots/faucet.ts'

type KeySummary = {key_slot_id: string; threshold_k: number; threshold_n: number; epoch: number; group_public_key?: string; mode: string; dcql_rule?: string}

const cfg = loadFleetConfig()
const s = new Suite('e2e: slot lifecycle (list/get/rotate)')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}

const client = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: generateClientKey(), chainId: cfg.chainId})
try {
  await httpFaucet(cfg.faucetUrl).fund(client.address)
} catch {
  const funder = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: cfg.deployPk as `0x${string}`, chainId: cfg.chainId})
  await funder.sendEth(client.address, parseEther('1'))
}
const {slotId, ruleSalt} = await client.createSlotCommitReveal({dcqlRule: SLOT_DCQL_RULE, k: 2, n: 3, mode: 'bls', tags: ['keykeeper'], onEpoch: (c, t) => s.info(`beacon ${c}→${t}`)})
s.ok('client created a BLS slot (commit-reveal)', /^0x[0-9a-f]{64}$/.test(slotId))

let committee: string[] = []
let ready = false
for (let i = 0; i < 45 && !ready; i++) {
  committee = await discoverCommittee(cfg, slotId)
  for (const u of committee) {
    const r = (await (await fetch(`${u}/v1/keys/${slotId}/public`)).json()) as {group_public_key?: string}
    if (r.group_public_key) {
      ready = true
      break
    }
  }
  if (!ready) await new Promise(r => setTimeout(r, 2000))
}
s.ok('committee DKG anchored the key', ready, `committee=${committee.length}`)

const jwt = mintLocalJwt(cfg)
const auth = {Authorization: `Bearer ${jwt}`}
const node = committee[0]!
const prov = await provisionRule(committee, slotId, SLOT_DCQL_RULE, ruleSalt, jwt)
s.ok('provisioned the rule + salt on the committee', prov.ok, prov.errors.join('; '))

// /v1/keys returns key_slot_id as bare hex (no 0x) — normalize before comparing.
const norm = (h: string) => h.replace(/^0x/i, '').toLowerCase()
const isMine = (k: KeySummary) => norm(k.key_slot_id) === norm(slotId)

// ── GET /v1/keys (list) ───────────────────────────────────────────────────────
const list = (await (await fetch(`${node}/v1/keys`, {headers: auth})).json()) as {keys: KeySummary[]}
const mine = list.keys?.find(isMine)
s.ok('our slot appears in /v1/keys', !!mine, `${list.keys?.length} slots listed`)
s.eq('listed slot mode is bls', mine?.mode ?? '', 'bls')

// ── GET /v1/keys/:id ──────────────────────────────────────────────────────────
const got = (await (await fetch(`${node}/v1/keys/${slotId}`, {headers: auth})).json()) as KeySummary
s.eq('get: threshold_k', got.threshold_k, 2)
s.eq('get: threshold_n', got.threshold_n, 3)
s.ok('get: has a 96-byte BLS group key', /^[0-9a-f]{192}$/i.test(got.group_public_key ?? ''))
const epoch0 = got.epoch
s.ok('get: epoch is set', Number.isInteger(epoch0), `epoch=${epoch0}`)

// ── mode filter ───────────────────────────────────────────────────────────────
const blsList = (await (await fetch(`${node}/v1/keys?mode=bls`, {headers: auth})).json()) as {keys: KeySummary[]}
s.ok('?mode=bls includes our slot', blsList.keys.some(isMine))
const frostList = (await (await fetch(`${node}/v1/keys?mode=frost`, {headers: auth})).json()) as {keys: KeySummary[]}
s.ok('?mode=frost excludes our (bls) slot', !frostList.keys.some(isMine))

// Rotate through the chain owner API, then require every assigned keeper to
// serve a fresh key at a later epoch. Allow the prior DKG finalize to drain.
await new Promise(resolve=>setTimeout(resolve,20000))
await client.rotateKey(slotId,'lifecycle rotation')
const deadline = Date.now()+180000
let rotated = false
while (Date.now()<deadline) {
  const keys = await Promise.all(committee.map(async url=>{
    const response = await fetch(`${url}/v1/keys/${slotId}`,{headers:auth,signal:AbortSignal.timeout(5000)})
    if (!response.ok) return null
    return await response.json() as KeySummary
  }))
  rotated = keys.length===3 && keys.every(key=>key && key.epoch>got.epoch && key.group_public_key && key.group_public_key!==got.group_public_key)
  if (rotated) break
  await new Promise(resolve=>setTimeout(resolve,2000))
}
s.ok('chain-owner rotation advances every committee member and changes the group key',rotated)
s.done()
