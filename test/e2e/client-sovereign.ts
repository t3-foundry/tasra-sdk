// E2E: the SOVEREIGN CLIENT journey — no relayer/provisioner.
//
//   1. client generates its own EVM account,
//   2. a FAUCET funds it (gas + TSRA),
//   3. the client SELF-SIGNS slot creation on-chain (createKeySlot is
//      permissionless + fee-less),
//   4. the drawn committee auto-DKGs the key,
//   5. the client provisions the clear DCQL rule + prepays the slot's metered
//      usage on Settlement with its TSRA,
//   6. the client OPERATES the slot: DCQL JWT → fetch k-of-n shards → assemble
//      MSK → encrypt → decrypt (and proves msk·G2 == the published key).
//
// Faucet: uses the real faucet service at KK_FAUCET if it's up; otherwise funds
// from the demo deployer as a stand-in (until the faucet service ships) so the
// whole flow validates today. Everything else is the real client doing its own
// on-chain writes.
//
// Run: tsx test/e2e/client-sovereign.ts

import {bls12_381} from '@noble/curves/bls12-381'
import {parseEther, type Hex} from 'viem'
import {Suite, bytesEq} from '../fleet/_assert.ts'
import {discoverCommittee, gate, loadFleetConfig, mintEngineeringJwt, mintLocalJwt, provisionRule, SLOT_DCQL_RULE} from '../fleet/_fleet.ts'
import {createTasraWriteClient, generateClientKey} from '../../src/chain/write.ts'
import {httpFaucet} from '../../src/slots/faucet.ts'
import {fetchAndAssembleKey, fetchMpk} from '../../src/keys/node-client.ts'
import {decryptWithMasterKey, leToScalar} from '../../src/crypto/kem.ts'
import {encryptEnvelope, fromBytes, toBytes} from '../../src/crypto/envelope.ts'
import {hexToBytes} from '../../src/crypto/hex.ts'

const G2 = bls12_381.G2
const cfg = loadFleetConfig()
const s = new Suite('e2e: sovereign client — faucet → self-create slot → operate')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}
if (!cfg.deployPk || !cfg.book.KeyRegistry || !cfg.book.TasraToken || !cfg.book.Settlement) {
  s.skip('suite', 'need chain.env (DEPLOY_PK + KeyRegistry/TasraToken/Settlement)')
  s.done()
  process.exit(0)
}

// 1. fresh sovereign client account (its own key)
const client = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: generateClientKey(), chainId: cfg.chainId})
s.info(`client account ${client.address}`)

// 2. FUND it — real faucet service if reachable, else deployer stand-in
let viaFaucet = false
try {
  const probe = await fetch(`${cfg.faucetUrl}/health`, {signal: AbortSignal.timeout(2000)})
  if (probe.ok) {
    await httpFaucet(cfg.faucetUrl).fund(client.address)
    viaFaucet = true
  }
} catch {
  /* faucet service not up */
}
if (!viaFaucet) {
  const funder = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: cfg.deployPk as Hex, chainId: cfg.chainId})
  await funder.sendEth(client.address, parseEther('1'))
  await funder.transferTsra(client.address, parseEther('5'))
}
s.info(`funded via ${viaFaucet ? 'faucet service' : 'deployer stand-in (faucet service not up)'}`)
s.ok('client has gas', (await client.ethBalance()) > 0n)
s.ok('client has TSRA', (await client.tsraBalance()) > 0n)

// 3. client SELF-SIGNS slot creation (no relayer)
const {slotId, txHash, ruleSalt} = await client.createSlot({dcqlRule: SLOT_DCQL_RULE, k: 2, n: 3, mode: 'bls', tags: ['keykeeper']})
s.ok('client self-created a slot on-chain', /^0x[0-9a-f]{64}$/.test(slotId), `tx ${txHash.slice(0, 12)}…`)

// 4. the drawn committee auto-DKGs — wait for the anchored key
let committee: string[] = []
let mpkHex = ''
for (let i = 0; i < 40 && !mpkHex; i++) {
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
s.ok('committee auto-DKG anchored the key', /^[0-9a-f]{192}$/i.test(mpkHex), `committee=${committee.length}`)

// 5. provision the clear DCQL rule + prepay the slot on Settlement
const adminJwt = mintLocalJwt(cfg)
const prov = await provisionRule(committee, slotId, SLOT_DCQL_RULE, ruleSalt, adminJwt)
s.ok('provisioned the rule + salt on the committee', prov.ok, prov.errors.join('; '))
const settleBefore = await client.settlementBalance(slotId)
await client.fundSlot(slotId, parseEther('1'))
const settleAfter = await client.settlementBalance(slotId)
s.ok('client prepaid the slot on Settlement with its TSRA', settleAfter - settleBefore === parseEther('1'), `${settleBefore} → ${settleAfter}`)

// 6. OPERATE the slot: DCQL JWT → shards → assemble MSK → encrypt/decrypt
const jwt = (await mintEngineeringJwt(cfg)).token
const {mpkBytes, epoch} = await fetchMpk(committee[0]!, slotId)
const msk = await fetchAndAssembleKey({urls: cfg.nodeUrls, jwt}, slotId)
s.ok('assembled MSK matches the slot public key (msk·G2 == mpk)', bytesEq(G2.ProjectivePoint.BASE.multiply(leToScalar(msk)).toRawBytes(true), mpkBytes))

const enc = new TextEncoder()
const identity = enc.encode('sovereign-e2e')
const plaintext = enc.encode('created AND operated by the client itself 🔐')
const back = fromBytes(toBytes(encryptEnvelope(hexToBytes(slotId), mpkBytes, identity, plaintext, BigInt(epoch))))
s.ok('encrypt → decrypt round-trip on the self-created slot', bytesEq(decryptWithMasterKey(msk, back.ciphertext, back.identity), plaintext))

s.done()
