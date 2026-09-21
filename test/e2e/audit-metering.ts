// E2E: AUDIT + METERING on the prod fleet.
//
// A sovereign client creates a FROST slot, signs N times through one coordinator,
// then asserts that node's sign-audit log and the metering view (derived from
// sign_audit, the data accountants pull to bill) both reflect exactly those ops.
//
// audit + metering require the `audit:read` scope. JWT: locally-minted EdDSA.
// Run: tsx test/e2e/audit-metering.ts

import {randomBytes} from 'node:crypto'
import {parseEther} from 'viem'
import {Suite} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig, mintLocalJwt, provisionRule} from '../fleet/_fleet.ts'
import {authorizeWallet, WALLET_RULE as SLOT_DCQL_RULE} from '../fleet/_wallet.ts'
import {createTasraWriteClient, generateClientKey} from '../../src/chain/write.ts'
import {httpFaucet} from '../../src/slots/faucet.ts'

const cfg = loadFleetConfig()
const s = new Suite('e2e: audit + metering')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}

const SUBJECT = 'did:demo:audit-e2e'
const N = 4
const creatorKey = generateClientKey()
const client = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: creatorKey, chainId: cfg.chainId})
try {
  await httpFaucet(cfg.faucetUrl).fund(client.address)
} catch {
  const funder = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: cfg.deployPk as `0x${string}`, chainId: cfg.chainId})
  await funder.sendEth(client.address, parseEther('1'))
}
const {slotId, ruleSalt} = await client.createSlotCommitReveal({dcqlRule: SLOT_DCQL_RULE, k: 3, n: cfg.nodeUrls.length, mode: 'frost', tags: ['keykeeper'], onEpoch: (c, t) => s.info(`beacon ${c}→${t}`)})
s.ok('client created a FROST slot (commit-reveal)', /^0x[0-9a-f]{64}$/.test(slotId))

// wait for the key
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

const adminJwt = mintLocalJwt(cfg)
const prov = await provisionRule(committee, slotId, SLOT_DCQL_RULE, ruleSalt, adminJwt)
s.ok('provisioned the rule + salt on the committee', prov.ok, prov.errors.join('; '))

// JWT carries the sign scope + audit:read, under a known subject
const jwt = mintLocalJwt(cfg, {sub: SUBJECT, scope: ['admin', 'audit:read', 'EmployeeOf:dept=Engineering']})
const subjects = new Set<string>()
const sign = async (node: string, messageHex: string) => {
  const grant = await authorizeWallet(cfg,slotId,creatorKey,{action:'sign',message:Buffer.from(messageHex,'hex')})
  const response = await fetch(`${node}/v1/committee/sign`, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({committee_token:grant.compound_token,verifier_proofs:grant.verifier_proofs,message_hex:messageHex}),signal:AbortSignal.timeout(30000)})
  if (response.ok) subjects.add(grant.compound_token.vp_hash)
  return response
}

// find a coordinator that can sign, then do N signs on it (audit is per-node)
let coord = ''
for (const u of committee) {
  if ((await sign(u, randomBytes(32).toString('hex'))).ok) {
    coord = u
    break
  }
}
s.ok('found a sign coordinator', !!coord)
let signed = 1 // the probe sign above already counted on `coord`
for (let i = 1; i < N; i++) {
  if ((await sign(coord, randomBytes(32).toString('hex'))).ok) signed++
}
s.eq(`performed ${N} signs`, signed, N)

// ── audit log on the coordinator reflects the signs ───────────────────────────
const auth = {Authorization: `Bearer ${jwt}`}
const countRes = (await (await fetch(`${coord}/v1/audit/${slotId}/count`, {headers: auth})).json()) as {count?: number; total?: number}
const auditCount = countRes.count ?? countRes.total ?? 0
s.ok('audit count reflects the signs', auditCount >= N, `count=${auditCount}`)

const listRes = (await (await fetch(`${coord}/v1/audit/${slotId}`, {headers: auth})).json()) as {entries: Array<{subject: string; outcome: string; message_sha256: string}>}
s.ok('audit list returns entries', (listRes.entries?.length ?? 0) >= N, `entries=${listRes.entries?.length}`)
s.ok('audit entries name the served presentations and successful outcomes', listRes.entries.slice(0, N).every(e => subjects.has(e.subject) && e.outcome === 'success'))
s.ok('audit entries have distinct message digests', new Set(listRes.entries.map(e => e.message_sha256)).size >= N)

// ── metering (derived from sign_audit) reflects the retrievals ────────────────
const meter = (await (await fetch(`${coord}/v1/metering/${slotId}`, {headers: auth})).json()) as {total: number; by_subject: Array<{subject: string; count: number}>}
s.ok('metering total reflects the signs', meter.total >= N, `total=${meter.total}`)
const count = meter.by_subject?.filter(r => subjects.has(r.subject)).reduce((sum,r) => sum+r.count,0)
s.eq('metering attributes the operations to the served wallet presentations', count, N)

// unauthorized: a JWT WITHOUT audit:read must be denied
const noScope = mintLocalJwt(cfg, {sub: SUBJECT, scope: ['EmployeeOf:dept=Engineering']})
const denied = await fetch(`${coord}/v1/metering/${slotId}`, {headers: {Authorization: `Bearer ${noScope}`}})
s.ok('metering denied without audit:read scope', denied.status === 401 || denied.status === 403, `HTTP ${denied.status}`)

s.done()
