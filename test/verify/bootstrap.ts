// VERIFY · REAL ECONOMIC ONBOARDING — the "no shortcuts" path, end to end.
//
// A brand-new user with nothing but a freshly generated key:
//   1. generates its own EVM account,
//   2. gets GAS from a faucet (real on-chain transfer; deployer stand-in if no
//      faucet service),
//   3. ACQUIRES TSRA THE PRODUCTION WAY — mints EURC and BUYS TSRA on the
//      sigmoid bonding curve (ADR-0027); no deployer TSRA hand-out,
//   4. self-creates a slot on-chain via the GRINDING-RESISTANT commit→reveal
//      path (ADR-0030; one-shot fallback only if the beacon isn't advancing),
//   5. the drawn committee auto-DKGs the key (waited for, anchored on-chain),
//   6. provisions the clear DCQL rule (ADR-0025) and PREPAYS the slot on
//      Settlement with the TSRA it just bought,
//   7. OPERATES the slot through the PRODUCTION credential path: an SD-JWT credential
//      → holder presentation → verifier quorum → custody decrypt.
//
// Every step is a real signed transaction or a real HTTP call against the live
// fleet — there are no mocks. Run standalone:  tsx test/verify/bootstrap.ts
// (it is also stage 2 of `npm run verify:all`).

import {formatEther, parseEther, parseUnits, type Hex} from 'viem'
import {Suite, bytesEq, metric} from '../fleet/_assert.ts'
import {
  discoverCommittee,
  gate,
  loadFleetConfig,
  mintLocalJwt,
  provisionRule,
} from '../fleet/_fleet.ts'
import {authorizeWallet, WALLET_RULE as SLOT_DCQL_RULE} from '../fleet/_wallet.ts'
import {decryptPayloadDigest} from '../../src/oid4vp/index.ts'
import {committeeDecrypt} from '../../src/committee/client.ts'
import {createTasraWriteClient, generateClientKey} from '../../src/chain/write.ts'
import {bondingCurveAbi} from '../../src/chain/abis/bondingCurve.ts'
import {mockEurcAbi} from '../../src/chain/abis/mockEurc.ts'
import {ensureGas} from './_faucet.ts'
import {fetchMpk} from '../../src/keys/node-client.ts'
import {type BlsPeer} from '../../src/decryption/client.ts'
import {encryptEnvelope, fromBytes, toBytes} from '../../src/crypto/envelope.ts'
import {hexToBytes} from '../../src/crypto/hex.ts'

const cfg = loadFleetConfig()
const s = new Suite('verify: real economic onboarding (account → faucet → buy TSRA → fund slot → operate)')

if (!(await gate(s, cfg))) {
  s.done()
  process.exit(0)
}
if (!cfg.deployPk || !cfg.book.KeyRegistry || !cfg.book.TasraToken || !cfg.book.Settlement) {
  s.ok('chain.env present (DEPLOY_PK + KeyRegistry/TasraToken/Settlement)', false, 'run `make fleet-up` so chain.env exists')
  s.done()
  process.exit(1)
}

const eurc = (cfg.book.MockEurc ?? (cfg.raw.EURC as Hex | undefined))
const curve = (cfg.book.BondingCurve ?? (cfg.raw.BONDING_CURVE as Hex | undefined))

// ── 1. fresh account ──────────────────────────────────────────────────────────
const creatorKey = generateClientKey()
const client = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: creatorKey, chainId: cfg.chainId})
s.info(`new account ${client.address}`)

// ── 2. faucet (gas) ───────────────────────────────────────────────────────────
const gas = await ensureGas(cfg, client.address, parseEther('1'))
s.info(`gas via ${gas.via}`)
s.ok('account funded with gas (real tx)', (await client.ethBalance()) > 0n)

// ── 3. acquire TSRA the production way: buy on the bonding curve ───────────────
if (eurc && curve) {
  const dec = (await client.pub.readContract({address: eurc, abi: mockEurcAbi, functionName: 'decimals'}))
  const spend = parseUnits('10000', dec) // 10,000 EURC
  await client.pub.waitForTransactionReceipt({hash: await client.wallet.writeContract({address: eurc, abi: mockEurcAbi, functionName: 'mint', args: [client.address, spend]})})
  await client.pub.waitForTransactionReceipt({hash: await client.wallet.writeContract({address: eurc, abi: mockEurcAbi, functionName: 'approve', args: [curve, spend]})})
  const tsra0 = await client.tsraBalance()
  const spot0 = (await client.pub.readContract({address: curve, abi: bondingCurveAbi, functionName: 'spotPrice'}))
  await client.pub.waitForTransactionReceipt({hash: await client.wallet.writeContract({address: curve, abi: bondingCurveAbi, functionName: 'buy', args: [spend, 0n]})})
  const tsraBought = (await client.tsraBalance()) - tsra0
  const spot1 = (await client.pub.readContract({address: curve, abi: bondingCurveAbi, functionName: 'spotPrice'}))
  s.ok('bought TSRA on the bonding curve with EURC (no deployer hand-out)', tsraBought > 0n, `+${formatEther(tsraBought)} TSRA for 10k EURC`)
  s.ok('curve spot price is non-decreasing after the buy (sigmoid)', spot1 >= spot0, `${formatEther(spot0)} → ${formatEther(spot1)}`)
  metric('tsra_bought', Number(formatEther(tsraBought)), 'TSRA')
} else {
  // No curve/EURC on this deployment — fall back to a real deployer transfer so
  // the rest of the flow still validates, but flag it loudly (it's a shortcut on
  // the ACQUISITION path only; the slot is still TSRA-funded for real).
  const funder = createTasraWriteClient({rpcUrl: cfg.rpcUrl, addresses: cfg.book, privateKey: cfg.deployPk as Hex, chainId: cfg.chainId})
  await funder.transferTsra(client.address, parseEther('5'))
  s.skip('buy TSRA on bonding curve', 'no BondingCurve/EURC in chain.env — used a deployer TSRA transfer instead')
}
s.ok('account now holds TSRA', (await client.tsraBalance()) > 0n, `${formatEther(await client.tsraBalance())} TSRA`)

// ── 4. self-create a slot on-chain (production commit→reveal)
const tCreate = Date.now()
const createPath = 'commit-reveal'
const created = await client.createSlotCommitReveal({dcqlRule:SLOT_DCQL_RULE,k:2,n:3,mode:'bls',tags:['keykeeper'],maxWaitMs:180000,onEpoch:(cur,t)=>s.info(`beacon epoch ${cur}/${t}…`)})
const {slotId,ruleSalt} = created
const createMs = Date.now() - tCreate
s.ok('account self-created a TSRA-funded slot on-chain', /^0x[0-9a-f]{64}$/.test(slotId), `${createPath}, ${(createMs / 1000).toFixed(1)}s`)
metric('slot_create_ms', createMs, 'ms', {path: createPath})

// ── 5. wait for the drawn committee's auto-DKG (anchored key) ──────────────────
const tDkg = Date.now()
let committee: string[] = []
let mpkHex = ''
const dkgDeadline = Date.now() + 120_000
while (!mpkHex && Date.now() < dkgDeadline) {
  committee = await discoverCommittee(cfg, slotId)
  for (const u of committee) {
    try {
      const r = (await (await fetch(`${u}/v1/keys/${slotId}/public`, {signal: AbortSignal.timeout(4000)})).json()) as {group_public_key?: string}
      if (r.group_public_key && /^[0-9a-f]{192}$/i.test(r.group_public_key)) {
        mpkHex = r.group_public_key
        break
      }
    } catch {
      /* node transiently unavailable */
    }
  }
  if (!mpkHex) await new Promise(r => setTimeout(r, 2000))
}
const dkgMs = Date.now() - tDkg
s.ok('committee auto-DKG anchored the slot key', /^[0-9a-f]{192}$/i.test(mpkHex), `committee=${committee.length}, ${(dkgMs / 1000).toFixed(1)}s`)
metric('dkg_wait_ms', dkgMs, 'ms')
if (!mpkHex) {
  s.done()
  process.exit(1)
}

// ── 6. provision the clear DCQL rule (ADR-0025) + prepay the slot with TSRA ────
const adminJwt = mintLocalJwt(cfg)
const prov = await provisionRule(committee, slotId, SLOT_DCQL_RULE, ruleSalt, adminJwt)
s.ok('provisioned the rule + salt on the committee', prov.ok, prov.errors.join('; '))
const settleBefore = await client.settlementBalance(slotId)
await client.fundSlot(slotId, parseEther('1'))
const settleAfter = await client.settlementBalance(slotId)
s.ok('prepaid the slot on Settlement with the TSRA it bought', settleAfter - settleBefore === parseEther('1'), `${formatEther(settleBefore)} → ${formatEther(settleAfter)} TSRA`)

// ── 7. operate via the PRODUCTION credential path (SD-JWT + holder proof) ──────────────
const {mpkBytes, epoch} = await fetchMpk(committee[0]!, slotId)
s.ok('fetched the anchored MPK (96-byte compressed G2)', mpkBytes.length === 96)

// A fresh commit-reveal slot is NOT exportable — raw shard export (`/v1/shards/key`) is refused
// for any slot not created with client-sovereign custody — so operate it the way production
// does: encrypt to the MPK, then decrypt through the keepers' k-of-n CUSTODY ceremony. The
// decrypting set + libp2p peers come from each committee member's public /v1/info.
const blsPeers: BlsPeer[] = []
for (const url of committee) {
  const info = (await (await fetch(`${url}/v1/info`)).json()) as {peer_id: string; node_identifier: number}
  blsPeers.push({id: info.node_identifier, peerId: info.peer_id})
}
blsPeers.sort((a, b) => a.id - b.id)
s.ok('resolved the committee peers for the custody decrypt', blsPeers.length >= 2, `${blsPeers.length} peers`)

const enc = new TextEncoder()
const identity = enc.encode('verify-onboarding')
const plaintext = enc.encode('onboarded, funded, and operated entirely by a fresh real account 🔐')
const back = fromBytes(toBytes(encryptEnvelope(hexToBytes(slotId), mpkBytes, identity, plaintext, BigInt(epoch))))
const grant = await authorizeWallet(cfg,slotId,creatorKey,{action:'decrypt',payloadDigest:decryptPayloadDigest(back.ciphertext.u,back.ciphertext.aeadCt)})
const out = await committeeDecrypt({
  nodeUrl: committee[0]!,
  committeeToken:grant.compound_token,
  verifierProofs:grant.verifierProofs,
  ciphertext: back.ciphertext,
  identity: back.identity,
  decryptingSet: blsPeers.map(p => p.id),
  blsPeers,
  ciphertextEpoch: epoch,
})
s.ok('encrypt → k-of-n custody decrypt round-trip on the new slot (production path, no export)', bytesEq(out, plaintext))

s.done()
