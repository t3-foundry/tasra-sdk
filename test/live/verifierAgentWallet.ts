// LIVE: the SDK wallet against a running Verifier Agent + verifier committee + keeper.
//
// The claim is byte-compatibility with the Hovi Wallet: the same verifier-agent session,
// JAR, did:web resolution, SD-JWT + KB-JWT, JWE `direct_post.jwt`, compound token and
// keeper sign that a Hovi-issued presentation produces.
//
//   1. issue an SD-JWT VC (P-256 did:key issuer, like Hovi Studio) to a fresh P-256 did:jwk holder
//   2. open a session on the verifier-agent with the slot creator's EIP-712 signature (the app side)
//   3. present it from the wallet side: fetch the JAR from the QR payload, verify it via did:web,
//      plan against the slot's rule, bind, encrypt, POST
//   4. await the compound token, check it binds the session's request_hash
//   5. FROST-sign on a committee keeper with that token
//
// Run against the demo fleet (values from your deployment):
//
//   KK_VERIFIER_AGENT_URL=http://127.0.0.1:8390 KK_CHAIN_ID=1337 KK_KEY_REGISTRY=0x… KK_CREATOR_PK=0x… \
//   KK_SLOT=0x… KK_VCT=tsrahealthtest KK_CLAIMS='{"organization":"Tasra Health"}' \
//   KK_KEEPER_URLS=http://127.0.0.1:8091,…,http://127.0.0.1:8099 npx tsx test/live/verifierAgentWallet.ts
//
// KK_ISSUER_KEY (0x-hex 32 bytes) pins the issuer; otherwise a fresh key is used (fine when the
// slot's rule does not pin `["iss"]`). KK_DID_WEB_INSECURE=1 allows http did:web on loopback.

import {p256} from '@noble/curves/p256'
import {privateKeyToAccount} from 'viem/accounts'
import {bytesToHex, hexToBytes} from '../../src/crypto/hex.js'
import {committeeSign} from '../../src/committee/client.js'
import {verify as verifyFrostSignature} from '../../src/crypto/frost.js'
import {
  awaitVerifierAgentResult,
  defaultKeyResolver,
  holderCnf,
  issueSdJwtVc,
  openVerifierAgentSession,
  p256DidKeyIssuer,
  parseSdJwt,
  presentToRequestUri,
  randomHolderKey,
  utf8,
} from '../../src/oid4vp/index.js'

const env = (k: string, d?: string): string => {
  const v = process.env[k] ?? d
  if (v === undefined) throw new Error(`missing env ${k}`)
  return v
}
const verifierAgentUrl = env('KK_VERIFIER_AGENT_URL', 'http://127.0.0.1:8390')
const chainId = Number(env('KK_CHAIN_ID', '1337'))
const keyRegistry = env('KK_KEY_REGISTRY') as `0x${string}`
const creator = privateKeyToAccount(env('KK_CREATOR_PK') as `0x${string}`)
const slotId = env('KK_SLOT') as `0x${string}`
const vct = env('KK_VCT', 'tsrahealthtest')
const claims = JSON.parse(env('KK_CLAIMS', '{"organization":"Tasra Health","group":"clinicians"}')) as Record<string, unknown>
// A committee member: `KK_KEEPER_URL`, or the first of `KK_KEEPER_URLS` (comma-separated) whose
// share-report says it holds a share of the slot.
const keeperUrls = process.env.KK_KEEPER_URL ? [process.env.KK_KEEPER_URL] : (process.env.KK_KEEPER_URLS ?? '').split(',').map(s => s.trim()).filter(Boolean)
const issuerKey = process.env.KK_ISSUER_KEY ? hexToBytes(process.env.KK_ISSUER_KEY) : p256.utils.randomPrivateKey()

const t0 = Date.now()
const step = (s: string) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1)}s] ${s}`)

// 1. issue
const issuer = p256DidKeyIssuer(issuerKey)
const holder = randomHolderKey()
const sdJwt = issueSdJwtVc({issuer, vct, claims, cnf: holderCnf(holder), ttlSecs: 3600})
step(`issued ${vct} from ${issuer.did.slice(0, 24)}… to ${holder.did.slice(0, 24)}… (${parseSdJwt(sdJwt).disclosures.length} disclosures)`)

// 2. the app opens a session
const message = utf8('hello from the SDK wallet')
const session = await openVerifierAgentSession({verifierAgentUrl, chainId, keyRegistry, slotId, action: 'sign', message, description: 'SDK wallet live gate', signer: creator, ttlSecs: 600})
step(`session ${session.sessionId.slice(0, 12)}… opened; qr = ${session.qrPayload.slice(0, 60)}…`)

// 3. the wallet presents
const resolveKey = defaultKeyResolver({allowInsecureLoopback: process.env.KK_DID_WEB_INSECURE === '1'})
const presented = await presentToRequestUri(session.qrPayload, [{sdJwt, label: vct}], holder, {resolveKey})
step(`JAR from ${presented.ro.signerDid} verified (kid ${presented.ro.header.kid}); candidates=${presented.plan.candidates.length}; encrypted=${presented.built.encrypted}; redirect=${presented.redirectUri ?? '-'}`)

// 4. the app collects the token
const result = await awaitVerifierAgentResult(session, {intervalMs: 1000, timeoutMs: 60_000})
const token = result.token
step(`compound token: binding=${token.binding} request_hash=${String(token.request_hash).slice(0, 18)}… signatures=${token.signatures.length} verifier_indexes=${JSON.stringify(token.verifier_indexes)}`)
if (token.binding !== 'holder_key') throw new Error(`expected holder_key binding, got ${token.binding}`)

// 5. sign on a committee keeper
let keeperUrl: string | undefined
for (const u of keeperUrls) {
  const r = await fetch(`${u}/v1/keys/${slotId}/share-report`).catch(() => undefined)
  if (r?.ok) { keeperUrl = u; break }
}
if (keeperUrl) {
  const sig = await committeeSign({nodeUrl: keeperUrl, committeeToken: token, message, verifierProofs: result.verifierProofs})
  if (!verifyFrostSignature(sig.groupPublicKey, message, sig.signature)) throw new Error('FROST signature does not verify under the group key')
  step(`keeper ${keeperUrl} FROST-signed; verifies under group key ${bytesToHex(sig.groupPublicKey).slice(0, 18)}…`)
} else if (keeperUrls.length) {
  throw new Error(`none of ${keeperUrls.join(', ')} holds a share of ${slotId}`)
} else {
  step('KK_KEEPER_URL / KK_KEEPER_URLS unset — skipping the keeper sign')
}
console.log('verifierAgentWallet live gate: OK')
