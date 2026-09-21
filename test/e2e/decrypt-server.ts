// E2E: BLS threshold server-side DECRYPT correctness on the prod fleet.
//
// A sovereign client creates a BLS slot (commit-reveal), encrypts an envelope to
// the slot's MPK locally, then asks the committee to threshold-decrypt it via
// /v1/decrypt (the server combines k partial decryptions) and asserts the
// recovered plaintext matches. Also exercises the BlsId→PeerId committee map.
//
// JWT: locally-minted EdDSA (verifier-independent). Run: tsx test/e2e/decrypt-server.ts

import {parseEther} from 'viem'
import {Suite, bytesEq} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig, mintLocalJwt, provisionRule} from '../fleet/_fleet.ts'
import {authorizeWallet, WALLET_RULE as SLOT_DCQL_RULE} from '../fleet/_wallet.ts'
import {decryptPayloadDigest} from '../../src/oid4vp/index.ts'
import {createTasraWriteClient, generateClientKey} from '../../src/chain/write.ts'
import {httpFaucet} from '../../src/slots/faucet.ts'
import {encryptEnvelope} from '../../src/crypto/envelope.ts'
import {hexToBytes} from '../../src/crypto/hex.ts'

const cfg = loadFleetConfig()
const s = new Suite('e2e: BLS server-side threshold decrypt')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}

const K = 2
const creatorKey = generateClientKey()
const client = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: creatorKey, chainId: cfg.chainId})
try {
  await httpFaucet(cfg.faucetUrl).fund(client.address)
} catch {
  const funder = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: cfg.deployPk as `0x${string}`, chainId: cfg.chainId})
  await funder.sendEth(client.address, parseEther('1'))
}
const {slotId, ruleSalt} = await client.createSlotCommitReveal({dcqlRule: SLOT_DCQL_RULE, k: K, n: 3, mode: 'bls', tags: ['keykeeper'], onEpoch: (c, t) => s.info(`beacon ${c}→${t}`)})
s.ok('client created a BLS slot (commit-reveal)', /^0x[0-9a-f]{64}$/.test(slotId))

// wait for the key
let committee: string[] = []
let mpkHex = ''
for (let i = 0; i < 45 && !mpkHex; i++) {
  committee = await discoverCommittee(cfg, slotId)
  for (const u of committee) {
    const r = (await (await fetch(`${u}/v1/keys/${slotId}/public`)).json()) as {group_public_key?: string}
    if (r.group_public_key) {
      mpkHex = r.group_public_key
      break
    }
  }
  if (!mpkHex) await new Promise(r => setTimeout(r, 2000))
}
s.ok('committee DKG anchored the BLS key', /^[0-9a-f]{192}$/i.test(mpkHex), `committee=${committee.length}`)

const adminJwt = mintLocalJwt(cfg)
const prov = await provisionRule(committee, slotId, SLOT_DCQL_RULE, ruleSalt, adminJwt)
s.ok('provisioned the rule + salt on the committee', prov.ok, prov.errors.join('; '))

// ── build the BlsId→PeerId committee map + a ciphertext ───────────────────────
// The BLS identifier is PUBLIC — read it from /v1/info (`node_identifier`, the value the
// node pins for exactly this bls_peers map), not from raw shard export. `/v1/shards/key`
// exports SECRET master-key material we don't need here, and since the client-sovereign
// custody gate it's denied by default on a group/credential slot — so a
// non-exportable slot like this one returns 403 and the map came up empty. `/v1/info` needs
// no export capability and no auth.
const peers: Array<{id: number; peer_id: string}> = []
for (const url of committee) {
  const info = (await (await fetch(`${url}/v1/info`)).json()) as {peer_id: string; node_identifier: number}
  peers.push({id: info.node_identifier, peer_id: info.peer_id})
}
peers.sort((a, b) => a.id - b.id)
s.ok('resolved committee BlsId→PeerId map', peers.length >= K, `peers=${peers.length}`)

const identity = 'decrypt-e2e'
const plaintext = new TextEncoder().encode('threshold-decrypt round-trip 🔐')
const env = encryptEnvelope(hexToBytes(slotId), hexToBytes(`0x${mpkHex}`), new TextEncoder().encode(identity), plaintext, 0n)
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64')
const grant = await authorizeWallet(cfg,slotId,creatorKey,{action:'decrypt',payloadDigest:decryptPayloadDigest(env.ciphertext.u,env.ciphertext.aeadCt)})

// ── /v1/decrypt: server combines k partials → plaintext ───────────────────────
async function decryptOn(node: string) {
  return fetch(`${node}/v1/committee/decrypt`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      committee_token:grant.compound_token,
      verifier_proofs:grant.verifier_proofs,
      ciphertext: {u: b64(env.ciphertext.u), nonce: b64(env.ciphertext.nonce), aead_ct: b64(env.ciphertext.aeadCt)},
      identity,
      decrypting_set: peers.map(p => p.id),
      bls_peers: peers,
    }),
    signal: AbortSignal.timeout(30000),
  })
}
// a committee node coordinates; some nodes can't coordinate, so try the committee
let res: Response | undefined
for (const u of committee) {
  const r = await decryptOn(u)
  if (r.ok) {
    res = r
    break
  }
}
s.ok('/v1/decrypt returned 200 on a coordinator', !!res, res ? '' : 'no committee node coordinated decrypt')
if (res) {
  const body = (await res.json()) as {plaintext?: string; plaintext_b64?: string}
  const recovered = body.plaintext ?? body.plaintext_b64 ?? ''
  const got = new Uint8Array(Buffer.from(recovered, 'base64'))
  s.ok('server-decrypted plaintext matches the original', bytesEq(got, plaintext), `got "${new TextDecoder().decode(got)}"`)
}

s.done()
