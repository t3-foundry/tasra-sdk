// E2E: the slot-driven managed JWT client, exercised over the FULL production lifecycle.
//
//   1. CREATE the key slot on-chain (KeyRegistry.createKeySlotFiltered → contract draws a
//      committee → nodes auto-DKG → key anchored) — both a FROST (sign) and a BLS (decrypt)
//      slot, so nothing is pre-seeded.
//   2. The operation is requested → the client CHOOSES a verifier from the on-chain set,
//      that verifier validates the signed VC against the slot's DCQL and mints a JWT.
//   3. The JWT authorizes the operation at a keeper node:
//        • FROST sign THROUGH the managed session (verified as a real Ed25519 signature),
//        • BLS decrypt both ways — the managed local-assembly path AND the node-coordinated
//          threshold path (/v1/decrypt, key never reconstructed).
//   4. The chosen verifier's request counter is checked (proof it handled the request), and
//      the random verifier choice is shown to cover the whole set over many draws.
//
// Run: tsx test/e2e/slot-client-verifier.ts   (needs the fleet + a funded DEPLOY_PK)

import {randomBytes} from 'node:crypto'
import {keccak256, toHex, type Address, type Hex} from 'viem'
import {Suite} from '../fleet/_assert.ts'
import {clusterToHost, gate, issueVc, loadFleetConfig, mintLocalJwt, provisionRule, randomDidKeyHolder, SLOT_DCQL_RULE} from '../fleet/_fleet.ts'
import {frostVerify} from '../fleet/_crypto.ts'
import {createTasraChainClient, resolveVerifierDirectory} from '../../src/chain/index.ts'
import {resolveSlotKeeperUrls} from '../../src/chain/discovery.ts'
import {createTasraSlotClient, type ResolvedEndpoints} from '../../src/chain/slotClient.ts'
import {createTasraWriteClient} from '../../src/chain/write.ts'
import {decryptCustody} from '../../src/decryption/client.ts'
import {encryptEnvelope} from '../../src/crypto/envelope.ts'
import {hexToBytes} from '../../src/crypto/hex.ts'
import {verifierApi, parsePrometheus} from '../../src/chain/offchain.ts'
import {decodeJwtClaims} from '../../src/auth/verifier.ts'

const cfg = loadFleetConfig()
const s = new Suite('e2e: slot client — create → choose verifier → JWT → sign + decrypt')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}
if (!cfg.deployPk || !cfg.book.KeyRegistry || !cfg.book.NodeRegistry) {
  s.ok('deployer key + chain address book available', false, 'need DEPLOY_PK + KeyRegistry/NodeRegistry in chain.env')
  s.done()
  process.exit(1)
}

const chain = createTasraChainClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, chainId: cfg.chainId})
const {holder, signer} = randomDidKeyHolder()
const vc = issueVc(cfg, {holder, credentialType: 'EmployeeOf', claims: {dept: 'Engineering', employer: 'AcmeCorp'}})
const holderProof = {
  signer,
  audience: cfg.jwtIss,
}
const adminJwt = mintLocalJwt(cfg) // operator provisioning only (create + provision rule)
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))
const dec = (u: Uint8Array) => new TextDecoder().decode(u)

// keeper count from chain — FROST chain-DKG runs over ALL keepers, so n must equal it.
const ops = (await chain.readers.nodeRegistry.activeOperators()) as readonly Address[]
const KEEPER_TAG = keccak256(toHex('keykeeper'))
const keeperFlags = (await Promise.all(ops.map(op => chain.readers.nodeRegistry.hasTag(op, KEEPER_TAG)))) as boolean[]
const keeperCount = ops.filter((_, i) => keeperFlags[i]).length
s.info(`fleet: ${keeperCount} keepers`)

const writer = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: cfg.deployPk as Hex, chainId: cfg.chainId})

// Create a slot ON-CHAIN, wait for the drawn committee to anchor the key (DKG done), then
// provision the clear DCQL rule to that committee so operations authorize.
async function createOnchain(mode: 'frost' | 'bls', k: number, n: number): Promise<{slot: string; committee: string[]}> {
  const {slotId, ruleSalt} = await writer.createSlot({dcqlRule: SLOT_DCQL_RULE, k, n, mode, tags: ['keykeeper']})
  const deadline = Date.now() + 90_000
  let committee: string[] = []
  while (Date.now() < deadline) {
    committee = (await resolveSlotKeeperUrls(chain, slotId as `0x${string}`)).map(clusterToHost)
    if (committee.length) {
      const keys = await Promise.all(
        committee.map(u => fetch(`${u}/v1/keys/${slotId}/public`).then(r => (r.ok ? r.json() : null)).catch(() => null)),
      )
      if (keys.some((x: {group_public_key?: string} | null) => x?.group_public_key)) break
    }
    await sleep(1500)
  }
  s.ok(`${mode} slot created on-chain + DKG anchored (committee ${committee.length})`, committee.length > 0, slotId.slice(0, 12) + '…')
  const prov = await provisionRule(committee, slotId, SLOT_DCQL_RULE, ruleSalt, adminJwt)
  s.ok(`${mode} slot rule + salt provisioned on the committee`, prov.ok, prov.errors.join('; '))
  return {slot: slotId, committee}
}

const verifierUrls = (await resolveVerifierDirectory(chain)).map(v => clusterToHost(v.url))
async function vpJwtCount(base: string): Promise<number> {
  try {
    const m = parsePrometheus(await verifierApi.metrics(base))
    return Object.entries(m).filter(([k]) => k.includes('request_duration_seconds_count') && k.includes('endpoint="verify_vp_jwt"')).reduce((a, [, v]) => a + v, 0)
  } catch {
    return NaN
  }
}

let chosen: ResolvedEndpoints | undefined
const kk = createTasraSlotClient({chain, identity: holder, rewriteUrl: clusterToHost, onResolve: r => (chosen = r)})

// ── GAP 1+2: on-chain FROST slot, sign THROUGH the managed session ──────────────
{
  const {slot} = await createOnchain('frost', 3, keeperCount)
  const before = new Map(await Promise.all(verifierUrls.map(async u => [u, await vpJwtCount(u)] as const)))
  const session = await kk.openSession(slot, {vpJwt: {dcqlRule: SLOT_DCQL_RULE, credentials: [vc], holderProof}})
  s.info(`FROST: chose verifier ${chosen!.verifier} (of ${chosen!.verifierCount}) · committee[0]=${chosen!.nodes[0]}`)
  s.ok('FROST session JWT minted by the chosen verifier (sub = holder)', decodeJwtClaims(session.jwt)?.sub === holder)

  const msg = randomBytes(32)
  const sig = await session.sign(msg)
  s.ok('FROST sign THROUGH the slot client is a valid Ed25519 signature', frostVerify(sig.signature.r, sig.signature.z, sig.groupPublicKey, msg))

  const after = await vpJwtCount(chosen!.verifier)
  s.ok(`the chosen verifier handled the FROST request (verify_vp_jwt ${before.get(chosen!.verifier)} → ${after})`, Number.isFinite(after) && after > (before.get(chosen!.verifier) ?? NaN))
  await session.close()
}

// ── GAP 1+3: on-chain BLS slot, decrypt BOTH ways ───────────────────────────────
{
  const {slot, committee} = await createOnchain('bls', 3, Math.min(5, keeperCount))
  const session = await kk.openSession(slot, {vpJwt: {dcqlRule: SLOT_DCQL_RULE, credentials: [vc], holderProof}})
  s.info(`BLS: chose verifier ${chosen!.verifier} · committee=${committee.length}`)

  // (a) managed local-assembly path (key reconstructed client-side, lazy on first decrypt)
  const back = await session.decrypt(session.encrypt(new TextEncoder().encode('local-assembly')))
  s.ok('BLS managed decrypt round-trips (local key assembly)', dec(back) === 'local-assembly')

  // (b) node-coordinated threshold path (/v1/decrypt, key NEVER reconstructed) — same JWT.
  const peers: Array<{id: number; peerId: string}> = []
  for (const u of committee) {
    try {
      const info = (await (await fetch(`${u}/v1/info`)).json()) as {peer_id: string}
      const sr = await fetch(`${u}/v1/shards/key`, {method: 'POST', headers: {'Content-Type': 'application/json', Authorization: `Bearer ${session.jwt}`}, body: JSON.stringify({key_slot_id: slot})})
      if (!sr.ok) continue
      const {identifier} = (await sr.json()) as {identifier: number}
      peers.push({id: identifier, peerId: info.peer_id})
    } catch {
      /* skip */
    }
  }
  peers.sort((a, b) => a.id - b.id)
  s.ok(`resolved the BLS committee peer map (${peers.length})`, peers.length >= 3)

  const identity = new TextEncoder().encode('node-coordinated')
  const env = encryptEnvelope(hexToBytes(slot), session.mpkBytes, identity, new TextEncoder().encode('node-coordinated!'), BigInt(session.epoch))
  const out = await decryptCustody({
    nodeUrl: committee[0]!,
    jwt: session.jwt, // the JWT the chain-chosen verifier minted
    slotId: slot,
    ciphertext: env.ciphertext,
    identity,
    decryptingSet: peers.slice(0, 3).map(p => p.id),
    blsPeers: peers,
  })
  s.ok('BLS node-coordinated decrypt (/v1/decrypt, key never reconstructed) recovers plaintext', dec(out) === 'node-coordinated!')

  // ── GAP 4: the random verifier choice covers the whole on-chain set ───────────
  const tally = new Map<string, number>()
  for (let i = 0; i < 60; i++) {
    const ep = await kk.resolveEndpoints(slot)
    tally.set(ep.verifier, (tally.get(ep.verifier) ?? 0) + 1)
  }
  s.ok(
    `random verifier choice covers all ${verifierUrls.length} on-chain verifiers over 60 draws`,
    tally.size === verifierUrls.length,
    [...tally.entries()].map(([u, c]) => `${u.split(':').pop()}×${c}`).join(' '),
  )
  await session.close()
}

await kk.closeAll()
s.done()
