// E2E: GOVERNANCE partial-sign on the prod fleet (PlatformExecutor path).
//
// /v1/governance/partial-sign has each governance node serve its OWN partial BLS signature over a
// 32-byte action digest; k partials are aggregated off-node (by the platform-signer) into the
// threshold signature PlatformExecutor verifies. This suite validates the node-side contract.
//
// ⚠ THE GOVERNANCE KEY IS NOT A KEY SLOT, and this suite used to assume it was. It created a
// `bls` (BLS12-381) slot, waited for the committee to DKG it, and read the partials off that.
// Since the cutover the governance key lives on BN254 and arrives OUT OF BAND from the
// chainless ceremony (`tasra-cli ceremony`; the demo fleet provisions it at bootstrap): each
// node loads its share from `api.governance_key_path`, keepers deliberately do NOT run a DKG for
// the slot, and `/v1/keys/<id>/public` stays EMPTY for it forever. Waiting on that key here would
// hang until timeout and then read as a node fault.
//
// Consequences for this file, all of them load-bearing:
//   · use the fleet's provisioned governance slot (GOVERNANCE_SLOT_ID), do not create one;
//   · partials are 64-byte BN254 G1 points (128 hex), not 48-byte compressed BLS12-381 (96 hex);
//   · a `bls` slot must be REFUSED — serving governance from key-slot material is the confusion
//     the separation exists to prevent, so it is asserted rather than assumed.
//
// JWT: locally-minted EdDSA. Run: tsx test/e2e/governance.ts

import {keccak256, toHex} from 'viem'
import {Suite} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig, mintLocalJwt, provisionRule} from '../fleet/_fleet.ts'

const cfg = loadFleetConfig()
const s = new Suite('e2e: governance partial-sign')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}

if (!cfg.governanceSlotId) {
  s.info('no GOVERNANCE_SLOT_ID in the fleet env — bring the fleet up with GOVERNANCE_K>0')
  s.done()
  process.exit(0)
}

const K = 2
const slotId = cfg.governanceSlotId
s.ok('fleet published a governance slot id', /^0x[0-9a-f]{64}$/.test(slotId), slotId)

// The committee comes from the on-chain draw. Every keeper holds a share, so whichever nodes were
// drawn can reach k — but we ask the drawn set, because that is who a real coordinator would ask.
const committee = await discoverCommittee(cfg, slotId)
s.ok('governance slot has an assigned committee', committee.length > 0, `committee=${committee.length}`)
// ⚠ Stop here on an empty set — every check below addresses committee[0]. Letting it run is
// worse than useless: the rule re-assert passes VACUOUSLY (provisionRule over no keepers is an
// [].every()), and partial-sign then throws `Failed to parse URL from undefined/v1/...`, which
// kills the whole prod suite and buries the one check that named the cause. done() exits 1
// because the assertion above already recorded a failure.
if (committee.length === 0) s.done()

// Provision the rule preimage + its salt (the chain carries only the salted commitment).
// This is the FLEET's own slot — up.sh provisions it at bring-up, so this is a re-assert, not the
// primary path; it needs the governance slot's OWN rule + salt (chain.env GOVERNANCE_DCQL_RULE /
// GOVERNANCE_RULE_SALT). ⚠ Not the demo slot's pair: the demo rule is an SD-JWT membership query
// no bearer JWT satisfies, and partial-sign is JWT-authorized. Without the salt the keeper cannot
// reproduce ruleCommitment and refuses the rule, and the node then fails partial-sign closed — so an
// unprovisioned rule is reported HERE, not as an unexplained 403 below.
const adminJwt = mintLocalJwt(cfg)
if (cfg.governanceRule && cfg.governanceRuleSalt) {
  const prov = await provisionRule(committee, slotId, cfg.governanceRule, cfg.governanceRuleSalt, adminJwt)
  s.ok('governance slot rule + salt provisioned on the committee', prov.ok, prov.errors.join('; '))
} else {
  s.skip('re-provision the governance slot rule', 'no GOVERNANCE_DCQL_RULE / GOVERNANCE_RULE_SALT in chain.env — relying on the rule up.sh provisioned at bring-up')
}

// digest the PlatformExecutor would verify (32-byte keccak256)
const digest = keccak256(toHex('keykeeper-governance-action: setParam(quorumBps, 6000)'))

// ── partial-sign with the governance:sign scope ───────────────────────────────
const jwt = mintLocalJwt(cfg, {scope: ['governance:sign', 'EmployeeOf:dept=Engineering']})
const partials: Array<{identifier: number; partial: string; epoch: number}> = []
for (const u of committee) {
  const r = await fetch(`${u}/v1/governance/partial-sign`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json', Authorization: `Bearer ${jwt}`},
    body: JSON.stringify({key_slot_id: slotId, digest}),
    signal: AbortSignal.timeout(20000),
  })
  if (r.ok) partials.push((await r.json()) as {identifier: number; partial: string; epoch: number})
  else s.info(`${u} → HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`)
}
s.ok('a quorum of nodes produced partials', partials.length >= K, `partials=${partials.length}`)

// ⚠ Guard every shape assertion on a non-empty result. `[].every()` is TRUE and `new Set([]).size`
// equals `[].length`, so on an empty gather these all pass and the suite reports health it does
// not have — which is exactly how this file read "6 passed, 2 failed" while serving nothing.
const got = partials.length > 0
s.ok(
  'each partial is a 64-byte BN254 G1 point',
  got && partials.every(p => /^(0x)?[0-9a-f]{128}$/i.test(p.partial)),
  got ? partials.map(p => `${p.partial.replace(/^0x/, '').length / 2}B`).join(',') : 'no partials',
)
s.ok(
  'partials come from distinct signer identifiers',
  got && new Set(partials.map(p => p.identifier)).size === partials.length,
)
s.ok('partials are distinct G1 points', got && new Set(partials.map(p => p.partial.toLowerCase())).size === partials.length)
s.ok('partials share one epoch (same key version)', got && new Set(partials.map(p => p.epoch)).size === 1)

// ── a BLS12-381 key slot must be REFUSED ─────────────────────────────────────
// The demo slot is `bls` — key-slot material at ~128 bits feeding kem/ibe, whose signatures the
// chain does not verify. Serving a governance partial from it would produce a signature
// PlatformExecutor rejects, with nothing to say why.
// ⚠ Must ask a node that is ASSIGNED to the demo slot. The governance committee and the demo
// slot's committee are independent draws, so a governance node has no row for the demo slot and
// answers 404 — which would "pass" a refusal check while proving nothing about mode enforcement.
const blsCommittee = cfg.slotId ? await discoverCommittee(cfg, cfg.slotId) : []
if (blsCommittee.length > 0) {
  const wrongMode = await fetch(`${blsCommittee[0]}/v1/governance/partial-sign`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json', Authorization: `Bearer ${jwt}`},
    body: JSON.stringify({key_slot_id: cfg.slotId, digest}),
  })
  const body = await wrongMode.text()
  // Assert the REASON, not just the status: 400 alone could be a malformed-request path.
  s.ok(
    'partial-sign refuses a BLS12-381 key slot',
    wrongMode.status === 400 && /governance signing requires a BN254 governance slot/.test(body),
    `HTTP ${wrongMode.status}: ${body.slice(0, 160)}`,
  )
} else {
  s.info('no committee for the demo BLS slot — skipping the wrong-mode refusal check')
}

// ── scope gate: a token WITHOUT governance:sign is rejected ───────────────────
const noGov = mintLocalJwt(cfg, {scope: ['EmployeeOf:dept=Engineering', 'admin']})
const denied = await fetch(`${committee[0]}/v1/governance/partial-sign`, {
  method: 'POST',
  headers: {'Content-Type': 'application/json', Authorization: `Bearer ${noGov}`},
  body: JSON.stringify({key_slot_id: slotId, digest}),
})
s.ok('partial-sign rejects a token lacking governance:sign scope', denied.status === 401 || denied.status === 403, `HTTP ${denied.status}`)

s.done()
