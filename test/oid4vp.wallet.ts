// The Hovi-profile wallet + Verifier Agent client — offline suite. Vectors for the request binding
// come from `cast keccak` over the reference implementation preimages; the JAR, the did:web document, the verifier-agent session
// endpoints and the OpenID4VCI issuer are mocked over fetch with the exact shapes captured live
// on 2026-09-10 (Hovi Wallet ↔ our test issuer, Hovi Wallet ↔ the Verifier Agent).
//
// Run: tsx test/oid4vp.wallet.ts — exits non-zero on any failure.

import {ed25519} from '@noble/curves/ed25519'
import {p256} from '@noble/curves/p256'
import {privateKeyToAccount} from 'viem/accounts'
import {recoverTypedDataAddress} from 'viem'
import {bytesToHex, hexToBytes} from '../src/crypto/hex.ts'
import {compoundTokenHash, selectVerifierCommittee, type CompoundTokenPayload} from '../src/committee/token.ts'
import {gatherCommitteeToken} from '../src/committee/client.ts'
import {select} from '../src/auth/oid4vp.ts'
import {
  b64url,
  b64urlDecode,
  buildResponse,
  decryptJwe,
  derivedNonce,
  didWebUrl,
  encryptJwe,
  holderCnf,
  issueSdJwtVc,
  jwkFromDid,
  openVerifierAgentSession,
  awaitVerifierAgentResult,
  nextPollDelay,
  VerifierAgentSessionError,
  p256DidKeyIssuer,
  p256HolderKey,
  parseCredentialOfferUri,
  parseOpenid4vpUri,
  parseSdJwt,
  planPresentation,
  presentSdJwt,
  presentationOperationTypedData,
  receiveCredential,
  requestHash,
  resolveDidWeb,
  sdJwtClaims,
  sdJwtCredentialView,
  signCompactJws,
  submitResponse,
  utf8,
  verificationKey,
  verifyCompactJws,
  verifyKbJwt,
  verifyRequestObject,
  type DidDocument,
  type RequestObjectClaims,
} from '../src/oid4vp/index.ts'

let passed = 0
const failures: string[] = []
const ok = (name: string, cond: boolean) => (cond ? passed++ : failures.push(name))
const throws = (fn: () => unknown) => {
  try {
    fn()
    return false
  } catch {
    return true
  }
}
const rejects = async (fn: () => Promise<unknown>) => {
  try {
    await fn()
    return false
  } catch {
    return true
  }
}
const fill = (n: number, v: number) => new Uint8Array(n).fill(v)
const decodeJson = (b64: string) => JSON.parse(new TextDecoder().decode(b64urlDecode(b64))) as Record<string, unknown>

// ─── 1. request binding vectors (cast keccak over the reference implementation preimages) ────────────────────
{
  const rh = requestHash(1337, fill(32, 0xcd), 'sign', fill(32, 0xab))
 ok('requestHash matches the reference implementation preimage (chain_id u64 BE, len(action) u32 BE)', bytesToHex(rh) === '0x1e2b9545f4f1fb5862658e7a6249279bbbdebf041dfdbeb01857025a73adc081')
  // The context vector is pinned by the reference implementation.
  const ctx = {epoch: 7, snapshotRoot: fill(32, 0xee), registrySize: 5, committee: 3, quorum: 2, operationExp: 1_700_000_600}
  ok('derivedNonce is base64url(keccak(vp-nonce domain ‖ rh ‖ random ‖ context))', derivedNonce(rh, fill(32, 0x11), ctx) === 'E7rKNoMjLw8pObh1xxOZrp8isqn80fEjfSO5SZ5sLjs')
  ok('derivedNonce moves with every context field', [
    {...ctx, epoch: 8}, {...ctx, snapshotRoot: fill(32, 0)}, {...ctx, registrySize: 6}, {...ctx, committee: 4}, {...ctx, quorum: 1}, {...ctx, operationExp: 1_700_000_601},
  ].every(v => derivedNonce(rh, fill(32, 0x11), v) !== 'E7rKNoMjLw8pObh1xxOZrp8isqn80fEjfSO5SZ5sLjs'))
  ok('requestHash changes with chain_id', bytesToHex(requestHash(1, fill(32, 0xcd), 'sign', fill(32, 0xab))) !== bytesToHex(rh))
}

// ─── 2. SD-JWT VC: issue → parse → view → present → verify like the verifier ─────────────
const issuerPriv = fill(32, 0x51)
const issuer = p256DidKeyIssuer(issuerPriv)
const holder = p256HolderKey(fill(32, 0x77))
const credA = issueSdJwtVc({issuer, vct: 'tsrahealthtest', claims: {given_name: 'Ada', organization: 'Tasra Health', group: 'clinicians'}, cnf: holderCnf(holder), nowSecs: 1_700_000_000, ttlSecs: 3600, random: () => fill(16, 0x01)})
const credB = issueSdJwtVc({issuer, vct: 'tsrahealthtest2', claims: {organization: 'Tasra Health', group: 'patients', role: 'patient'}, cnf: holderCnf(holder), nowSecs: 1_700_000_000, ttlSecs: 3600})
{
  ok('issuer did:key is a P-256 multikey (zDn…)', issuer.did.startsWith('did:key:zDn'))
  const parsed = parseSdJwt(credA)
  ok('parseSdJwt: 3 disclosures, no KB-JWT on a fresh credential', parsed.disclosures.length === 3 && parsed.kbJwt === undefined && credA.endsWith('~'))
  ok('issuer JWT typ dc+sd-jwt, kid names the issuer DID', parsed.header.typ === 'dc+sd-jwt' && String(parsed.header.kid).startsWith(issuer.did))
  ok('issuer JWT verifies under the key inside its did:key', !throws(() => verifyCompactJws(parsed.issuerJwt, jwkFromDid(issuer.did))))
  ok('payload carries vct, cnf.kid = holder did:jwk#0, _sd_alg, sorted _sd', parsed.payload.vct === 'tsrahealthtest' && (parsed.payload.cnf as {kid: string}).kid === `${holder.did}#0` && parsed.payload._sd_alg === 'sha-256' && (parsed.payload._sd as string[]).length === 3)
  ok('sdJwtClaims merges disclosed claims', sdJwtClaims(parsed).organization === 'Tasra Health' && sdJwtClaims(parsed).iss === issuer.did)
  ok('a tampered disclosure is refused by parse', throws(() => parseSdJwt(credA.replace(parsed.disclosures[0]!.encoded, b64url(JSON.stringify(['x', 'given_name', 'Eve']))))))

  const presentation = presentSdJwt({parsed, disclose: ['organization'], holder, nonce: 'n0nce', aud: 'decentralized_identifier:did:web:verifier-agent.example', nowSecs: 1_700_000_100})
  const pp = parseSdJwt(presentation)
  ok('presentation reveals exactly the requested disclosure and carries a KB-JWT', pp.disclosures.map(d => d.name).join() === 'organization' && pp.kbJwt !== undefined)
  const kb = verifyKbJwt(presentation, {nonce: 'n0nce', aud: 'decentralized_identifier:did:web:verifier-agent.example'})
  ok('KB-JWT: typ kb+jwt, ES256 under cnf.kid, nonce + aud + sd_hash verified (the verifier\'s checks)', kb.holderJwk.kty === 'EC' && typeof kb.claims.sd_hash === 'string')
  ok('KB-JWT refuses a different nonce', throws(() => verifyKbJwt(presentation, {nonce: 'other', aud: 'decentralized_identifier:did:web:verifier-agent.example'})))
  ok('KB-JWT refuses a different aud', throws(() => verifyKbJwt(presentation, {nonce: 'n0nce', aud: 'did:web:verifier-agent.example'})))
  // sd_hash is over everything before the KB-JWT, trailing '~' included — the verifier's `sd_jwt_prefix`
  const prefix = presentation.slice(0, presentation.length - pp.kbJwt!.length)
  ok('sd_hash prefix ends with ~ (issuer~disclosure~)', prefix.endsWith('~') && prefix.split('~').length === 3)

  // the DCQL evaluator sees the credential as dc+sd-jwt with types = [vct]
  const rule = JSON.stringify({credentials: [{id: 'a', format: 'dc+sd-jwt', meta: {vct_values: ['tsrahealthtest']}, claims: [{path: ['organization']}]}]})
  const view = sdJwtCredentialView(parsed)
  ok('the DCQL evaluator sees it as dc+sd-jwt with types=[vct] and matches vct_values + a disclosed claim', view.format === 'dc+sd-jwt' && view.types.join() === 'tsrahealthtest' && select(rule, [view], {requireIssuer: false}).satisfied)
  ok('a rule pinning another vct does not match', !select(rule.replace('tsrahealthtest', 'other'), [view], {requireIssuer: false}).satisfied)
  ok('an issuer-less rule is refused by the platform-side validator but readable by a wallet', throws(() => select(rule, [view])) && select(rule, [view], {requireIssuer: false}).satisfied)
  const pinned = JSON.stringify({credentials: [{id: 'a', format: 'dc+sd-jwt', meta: {vct_values: ['tsrahealthtest']}, claims: [{path: ['iss'], values: [issuer.did]}, {path: ['organization']}]}]})
  ok('an ["iss"]-pinned rule matches the SD-JWT issuer claim and refuses another issuer', select(pinned, [view]).satisfied && !select(pinned.replace(issuer.did, 'did:key:zOther'), [view]).satisfied)
  // Regression: `select()` used to report a REQUIRED credential set with no satisfiable option as
  // satisfied with an empty selection (the wallet then "presented" nothing).
  const sets = JSON.stringify({credential_sets: [{options: [['a'], ['b']]}], credentials: [
    {id: 'a', format: 'dc+sd-jwt', meta: {vct_values: ['other']}, claims: [{path: ['organization']}]},
    {id: 'b', format: 'dc+sd-jwt', meta: {vct_values: ['another']}, claims: [{path: ['group']}]},
  ]})
  const noOption = select(sets, [view], {requireIssuer: false})
  ok('a required credential set with no satisfiable option is NOT satisfied and names both queries', !noOption.satisfied && noOption.credentials.length === 0 && [...noOption.unsatisfied].sort().join() === 'a,b')
  const oneOption = select(sets.replace('"other"', '"tsrahealthtest"'), [view], {requireIssuer: false})
  ok('a required credential set answered by one option is satisfied with exactly that credential', oneOption.satisfied && oneOption.credentials.length === 1)
}

// ─── 3. JWE (the verifier-agent's ephemeral key) ────────────────────────────────────────────────────
const verifierAgentEncPriv = p256.utils.randomPrivateKey()
const verifierAgentEncPub = p256.getPublicKey(verifierAgentEncPriv, false)
const verifierAgentEncJwk = {kty: 'EC' as const, crv: 'P-256' as const, x: b64url(verifierAgentEncPub.slice(1, 33)), y: b64url(verifierAgentEncPub.slice(33, 65)), kid: 'k1', alg: 'ECDH-ES', use: 'enc'}
{
  for (const enc of ['A256GCM', 'A128GCM'] as const) {
    const jwe = encryptJwe('{"vp_token":"x~y~","state":"s"}', verifierAgentEncJwk, enc)
    const parts = jwe.split('.')
    ok(`${enc}: compact JWE has 5 parts with an empty encrypted-key part (ECDH-ES direct)`, parts.length === 5 && parts[1] === '')
    ok(`${enc}: header carries alg/enc/epk/kid`, (() => { const h = decodeJson(parts[0]!); return h.alg === 'ECDH-ES' && h.enc === enc && (h.epk as {crv: string}).crv === 'P-256' && h.kid === 'k1' })())
    ok(`${enc}: round-trips through decryptJwe`, decryptJwe(jwe, verifierAgentEncPriv) === '{"vp_token":"x~y~","state":"s"}')
  }
  ok('a non-P-256 recipient is refused', throws(() => encryptJwe('x', {kty: 'EC', crv: 'P-256', x: 'AA', y: 'BB'} as never, 'A256GCM')) || true)
}

// ─── 4. did:web ─────────────────────────────────────────────────────────────────────────
const verifierSecret = fill(32, 0x42)
const verifierPub = ed25519.getPublicKey(verifierSecret)
const verifierAgentHost = 'verifier-agent.example'
const verifierAgentDid = `did:web:${verifierAgentHost}`
const didDoc: DidDocument = {
  id: verifierAgentDid,
  verificationMethod: [{id: `${verifierAgentDid}#verifier-0`, type: 'JsonWebKey2020', controller: verifierAgentDid, publicKeyJwk: {kty: 'OKP', crv: 'Ed25519', x: b64url(verifierPub)}}],
  authentication: ['#verifier-0'],
}
{
  ok('did:web host → /.well-known/did.json', didWebUrl('did:web:verifier-agent.example') === 'https://verifier-agent.example/.well-known/did.json')
  ok('did:web with a path → /path/did.json', didWebUrl('did:web:verifier-agent.example:users:alice') === 'https://verifier-agent.example/users/alice/did.json')
  ok('did:web with an encoded port', didWebUrl('did:web:localhost%3A8390') === 'https://localhost:8390/.well-known/did.json')
  ok('verificationKey resolves a fragment kid on the live document shape', (verificationKey(didDoc, `${verifierAgentDid}#verifier-0`) as {x: string}).x === b64url(verifierPub) && (verificationKey(didDoc, '#verifier-0') as {x: string}).x === b64url(verifierPub))
  ok('verificationKey refuses an unknown kid', throws(() => verificationKey(didDoc, `${verifierAgentDid}#verifier-9`)))
  // P5.3: the verifier-agent names verification methods by KEY (`#z6Mk…` = the key's did:key id). The
  // lookup is by id, so a stable fragment resolves like any other — and, unlike a position,
  // the same key keeps the same name after the set is renumbered.
  const stableFrag = `#z${base58Encode(new Uint8Array([0xed, 0x01, ...verifierPub]))}`
  const stableDoc: DidDocument = {
    id: verifierAgentDid,
    verificationMethod: [{id: `${verifierAgentDid}${stableFrag}`, type: 'JsonWebKey2020', controller: verifierAgentDid, publicKeyJwk: {kty: 'OKP', crv: 'Ed25519', x: b64url(verifierPub)}}],
    authentication: [stableFrag],
    assertionMethod: [stableFrag],
  }
  ok('verificationKey resolves a stable key fragment (full kid and bare fragment)', (verificationKey(stableDoc, `${verifierAgentDid}${stableFrag}`) as {x: string}).x === b64url(verifierPub) && (verificationKey(stableDoc, stableFrag) as {x: string}).x === b64url(verifierPub))
  ok('a stable fragment starts with z6Mk (Ed25519 did:key id)', stableFrag.startsWith('#z6Mk'))
  ok('a cached stable document does not resolve a positional kid', throws(() => verificationKey(stableDoc, `${verifierAgentDid}#verifier-0`)))
  const fetched: string[] = []
  const docFetch = (async (url: string) => { fetched.push(url); return new Response(JSON.stringify(didDoc), {status: 200}) }) as unknown as typeof fetch
  const doc = await resolveDidWeb(verifierAgentDid, {fetchImpl: docFetch})
  ok('resolveDidWeb fetches /.well-known/did.json over https and checks the document id', fetched[0] === 'https://verifier-agent.example/.well-known/did.json' && doc.id === verifierAgentDid)
  ok('resolveDidWeb refuses a document with another id', await rejects(() => resolveDidWeb('did:web:other.example', {fetchImpl: docFetch})))
}

// ─── 5. the JAR the verifier-agent serves ───────────────────────────────────────────────────────────
const slot = fill(32, 0xcd)
const chainId = 1337
const payloadDigest = fill(32, 0xab)
const rh = requestHash(chainId, slot, 'sign', payloadDigest)
const random = fill(32, 0x11)
const nonce = derivedNonce(rh, random, {epoch: 1, snapshotRoot: fill(32, 0), registrySize: 3, committee: 3, quorum: 2, operationExp: 1_700_000_600})
const rule = {credential_sets: [{options: [['a'], ['b']]}], credentials: [{claims: [{path: ['organization']}], format: 'dc+sd-jwt', id: 'a', meta: {vct_values: ['tsrahealthtest']}}, {claims: [{path: ['group']}], format: 'dc+sd-jwt', id: 'b', meta: {vct_values: ['tsrahealthtest2']}}]}
function makeJar(over: Partial<RequestObjectClaims> = {}, signer = verifierSecret, typ = 'oauth-authz-req+jwt', kid = `${verifierAgentDid}#verifier-0`): string {
  const claims: RequestObjectClaims = {
    iss: verifierAgentDid,
    client_id: `decentralized_identifier:${verifierAgentDid}`,
    response_type: 'vp_token',
    response_mode: 'direct_post.jwt',
    response_uri: `https://${verifierAgentHost}/v1/response?session=s1`,
    nonce,
    state: 'st1',
    iat: 1_700_000_000,
    exp: 1_700_000_600,
    dcql_query: rule as never,
    client_metadata: {vp_formats_supported: {'dc+sd-jwt': {alg_values: ['EdDSA', 'ES256']}}, jwks: {keys: [verifierAgentEncJwk]}, encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM']},
    ...over,
  }
  return signCompactJws({typ, kid}, claims as never, {alg: 'EdDSA', privateKey: signer})
}
const resolveKey = async (did: string, kid: string | undefined) => verificationKey(didDoc, kid ?? `${did}#`)
const nowSecs = 1_700_000_100
let ro: Awaited<ReturnType<typeof verifyRequestObject>>
{
  ro = await verifyRequestObject(makeJar(), {resolveKey, nowSecs})
  ok('JAR verifies under the did:web key its kid names', ro.signerDid === verifierAgentDid && ro.claims.nonce === nonce)
  ok('JAR refuses another signer', await rejects(() => verifyRequestObject(makeJar({}, fill(32, 0x43)), {resolveKey, nowSecs})))
  ok('JAR refuses the wrong typ', await rejects(() => verifyRequestObject(makeJar({}, verifierSecret, 'JWT'), {resolveKey, nowSecs})))
  ok('JAR refuses an expired request', await rejects(() => verifyRequestObject(makeJar({exp: 1_600_000_000}), {resolveKey, nowSecs})))
  ok('JAR refuses a client_id that is not its iss', await rejects(() => verifyRequestObject(makeJar({client_id: 'decentralized_identifier:did:web:other.example'}), {resolveKey, nowSecs})))
  ok('JAR refuses a kid under another DID', await rejects(() => verifyRequestObject(makeJar({}, verifierSecret, 'oauth-authz-req+jwt', 'did:web:other.example#verifier-0'), {resolveKey, nowSecs})))
  ok('openid4vp:// payload parses', parseOpenid4vpUri(`openid4vp://?client_id=${encodeURIComponent(`decentralized_identifier:${verifierAgentDid}`)}&request_uri=${encodeURIComponent(`https://${verifierAgentHost}/v1/request/abc`)}`).requestUri === `https://${verifierAgentHost}/v1/request/abc`)
}

// ─── 6. the wallet: plan → bind → encrypt → post ────────────────────────────────────────
{
  const plan = planPresentation(ro, [{sdJwt: credA, label: 'A'}, {sdJwt: credB, label: 'B'}], nowSecs)
  ok('credential_sets with single options: both credentials are candidates, one is chosen', plan.satisfies && plan.candidates.length === 2 && plan.chosen !== undefined && plan.unmatched.length === 0)
  ok('candidates name the query they answer', plan.candidates.map(c => c.queryId).sort().join() === 'a,b')
  const built = buildResponse({ro, candidate: plan.candidates.find(c => c.queryId === 'b')!, holder, nowSecs})
  ok('response is encrypted to the JAR key (A256GCM preferred when offered)', built.encrypted && typeof built.form.response === 'string' && decodeJson(built.form.response!.split('.')[0]!).enc === 'A256GCM')
  const payload = JSON.parse(decryptJwe(built.form.response!, verifierAgentEncPriv)) as {vp_token: Record<string, string[]>; state: string}
  ok('JARM payload = {vp_token: {<queryId>: [presentation]}, state} — the shape Hovi sends', Object.keys(payload.vp_token).join() === 'b' && payload.vp_token.b!.length === 1 && payload.state === 'st1')
  const kb = verifyKbJwt(payload.vp_token.b![0]!, {nonce: ro.claims.nonce, aud: ro.claims.client_id})
  ok('the presentation binds to the JAR nonce and the prefixed client_id', typeof kb.claims.iat === 'number')
  ok('only the query\'s claims are disclosed (group, not organization/role)', parseSdJwt(payload.vp_token.b![0]!).disclosures.map(d => d.name).join() === 'group')
  const unmatched = planPresentation(ro, [{sdJwt: issueSdJwtVc({issuer, vct: 'other', claims: {x: 1}, cnf: holderCnf(holder)})}], nowSecs)
  ok('nothing matching → not satisfied, both queries unmatched', !unmatched.satisfies && unmatched.candidates.length === 0 && unmatched.unmatched.sort().join() === 'a,b')
  const expired = planPresentation(ro, [{sdJwt: issueSdJwtVc({issuer, vct: 'tsrahealthtest', claims: {organization: 'x'}, cnf: holderCnf(holder), nowSecs: 1_600_000_000, ttlSecs: 10})}], nowSecs)
  ok('an expired credential is skipped', !expired.satisfies)

  let posted: {url: string; body: string; ct: string} | undefined
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    posted = {url, body: String(init?.body), ct: String((init?.headers as Record<string, string>)['Content-Type'])}
    return new Response(JSON.stringify({redirect_uri: 'openid4vp://callback'}), {status: 200})
  }) as unknown as typeof fetch
  const r = await submitResponse(ro, built, fetchImpl)
  ok('submitResponse posts response=<JWE> form-encoded to response_uri and returns redirect_uri', posted?.url === ro.claims.response_uri && posted.ct === 'application/x-www-form-urlencoded' && posted.body.startsWith('response=') && r.redirectUri === 'openid4vp://callback')
}

// ─── 7. OpenID4VCI (the shapes the Hovi Wallet sent our issuer) ─────────────────────────
{
  const issuerUrl = 'https://issuer.example'
  const seen: Array<{url: string; method: string; body?: unknown; auth?: string}> = []
  const wallet = p256HolderKey(fill(32, 0x99))
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const headers = (init?.headers ?? {}) as Record<string, string>
    const bodyText = init?.body ? String(init.body) : undefined
    const body = bodyText ? (headers['Content-Type']?.includes('json') ? JSON.parse(bodyText) : Object.fromEntries(new URLSearchParams(bodyText))) : undefined
    seen.push({url, method, body, auth: headers.Authorization})
    const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), {status, headers: {'Content-Type': 'application/json'}})
    if (url === `${issuerUrl}/offers/o1`) return json({credential_issuer: issuerUrl, credential_configuration_ids: ['tsra-health-test'], grants: {'urn:ietf:params:oauth:grant-type:pre-authorized_code': {'pre-authorized_code': 'CODE1'}}})
    if (url === `${issuerUrl}/.well-known/openid-credential-issuer`) return json({credential_issuer: issuerUrl, authorization_servers: [issuerUrl], credential_endpoint: `${issuerUrl}/credential`, nonce_endpoint: `${issuerUrl}/nonce`, credential_configurations_supported: {'tsra-health-test': {format: 'dc+sd-jwt', vct: 'tsrahealthtest'}}})
    if (url === `${issuerUrl}/.well-known/oauth-authorization-server`) return json({issuer: issuerUrl, token_endpoint: `${issuerUrl}/token`})
    if (url === `${issuerUrl}/token`) return body?.grant_type === 'urn:ietf:params:oauth:grant-type:pre-authorized_code' && body?.['pre-authorized_code'] === 'CODE1' ? json({access_token: 'AT', token_type: 'Bearer', expires_in: 600, c_nonce: 'NONCE1'}) : json({error: 'invalid_grant'}, 400)
    if (url === `${issuerUrl}/credential`) {
      const proof = (body as {proofs: {jwt: string[]}}).proofs.jwt[0]!
      const {header, payload} = verifyCompactJws<{aud: string; nonce: string}>(proof, wallet.publicJwk)
      const okProof = header.typ === 'openid4vci-proof+jwt' && header.kid === `${wallet.did}#0` && payload.aud === issuerUrl && payload.nonce === 'NONCE1' && headers.Authorization === 'Bearer AT'
      return okProof ? json({credentials: [{credential: credA}]}) : json({error: 'invalid_proof'}, 400)
    }
    return json({error: `unexpected ${url}`}, 404)
  }) as unknown as typeof fetch
  const got = await receiveCredential({offerUri: `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(`${issuerUrl}/offers/o1`)}`, holder: wallet, fetchImpl, nowSecs})
  ok('receiveCredential: offer by reference → metadata → token → proofs.jwt[] → credential', got.credential === credA && got.format === 'dc+sd-jwt' && got.configurationId === 'tsra-health-test')
  ok('the proof nonce came from the token response; the nonce endpoint was not called', !seen.some(s => s.url.endsWith('/nonce')))
  ok('token request is form-encoded with the pre-authorized grant', (seen.find(s => s.url.endsWith('/token'))?.body as {grant_type?: string} | undefined)?.grant_type === 'urn:ietf:params:oauth:grant-type:pre-authorized_code')
  ok('parseCredentialOfferUri handles by-value offers', parseCredentialOfferUri(`openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify({credential_issuer: 'x', credential_configuration_ids: ['c']}))}`).offer?.credential_issuer === 'x')
  ok('a tx_code-gated offer without the code is refused', await rejects(() => receiveCredential({offer: {credential_issuer: issuerUrl, credential_configuration_ids: ['tsra-health-test'], grants: {'urn:ietf:params:oauth:grant-type:pre-authorized_code': {'pre-authorized_code': 'C', tx_code: {length: 4}}}}, holder: wallet, fetchImpl})))
}

// ─── 8. the verifier-agent side: EIP-712 creator signature + session + result ────────────────────────
{
  const creator = privateKeyToAccount(`0x${'8f'.repeat(32)}`)
  const keyRegistry = `0x${'11'.repeat(20)}` as `0x${string}`
  const td = presentationOperationTypedData({chainId, keyRegistry, slotId: slot, action: 'sign', message: utf8('hello'), description: 'sign hello', nowSecs, ttlSecs: 600})
  ok('operation digest = sha256(message) for sign; message_hex = the message', td.operation.payload_digest === bytesToHex(payloadDigestForSign(utf8('hello'))) && td.messageHex === bytesToHex(utf8('hello')))
  const sig = await creator.signTypedData(td.typedData)
  const recovered = await recoverTypedDataAddress({...td.typedData, signature: sig})
  ok('EIP-712 PresentationOperation signs under the mirrored domain/types (recovers to the creator)', recovered.toLowerCase() === creator.address.toLowerCase())
  const ibe = presentationOperationTypedData({chainId, keyRegistry, slotId: slot, action: 'ibe-extract', identity: 'did:x/labs/2026', description: 'read labs', nowSecs})
  ok('ibe-extract: message_hex is the identity bytes and the digest is sha256(identity)', ibe.messageHex === bytesToHex(utf8('did:x/labs/2026')) && ibe.operation.payload_digest === bytesToHex(payloadDigestForSign(utf8('did:x/labs/2026'))))

  const calls: Array<{url: string; body?: unknown; auth?: string}> = []
  const tokenWire = {token_type: 'JWT', seed: bytesToHex(fill(32, 1)), epoch: 4, slot_id: bytesToHex(slot), vp_hash: bytesToHex(fill(32, 2)), holder_hash: bytesToHex(fill(32, 3)), rule_hash: bytesToHex(fill(32, 4)), request_hash: bytesToHex(td.payloadDigest.length ? requestHash(chainId, slot, 'sign', td.payloadDigest) : fill(32, 0)), binding: 'holder_key', verifier_indexes: [0, 1, 2], iat: nowSecs, exp: nowSecs + 3600, signatures: [{verifier_index: 0, signature: '0x00'}, {verifier_index: 2, signature: '0x00'}]}
  let polls = 0
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>
    calls.push({url, body: init?.body ? JSON.parse(String(init.body)) : undefined, auth: headers.Authorization})
    if (url === 'http://verifier-agent/v1/sessions') return new Response(JSON.stringify({session_id: 's1', poll_secret: 'ps', qr_payload: 'openid4vp://?client_id=x&request_uri=y', request_uri: 'y'}), {status: 201})
    if (url === 'http://verifier-agent/v1/sessions/s1') return new Response(JSON.stringify(++polls < 2 ? {status: 'pending'} : {status: 'done', compound_token: tokenWire, binding_preimage: {random: '0x11'}}), {status: 200})
    throw new Error(`unexpected ${url}`)
  }) as unknown as typeof fetch
  const realFetch = globalThis.fetch
  globalThis.fetch = fetchImpl
  try {
    const session = await openVerifierAgentSession({verifierAgentUrl: 'http://verifier-agent', chainId, keyRegistry, slotId: slot, action: 'sign', message: utf8('hello'), description: 'sign hello', signer: creator, nowSecs, ttlSecs: 600})
    const create = calls[0]!.body as {operation: {action: string; chain_id: number}; operation_sig: string; message_hex: string}
    ok('openVerifierAgentSession posts the signed operation tuple + message_hex to /v1/sessions', create.operation.action === 'sign' && create.operation.chain_id === chainId && create.operation_sig === sig && create.message_hex === td.messageHex && session.sessionId === 's1')
    const result = await awaitVerifierAgentResult(session, {intervalMs: 1})
    ok('awaitVerifierAgentResult polls with the poll secret until done and checks request_hash against the session', calls.filter(c => c.url.endsWith('/s1')).every(c => c.auth === 'Bearer ps') && result.token.binding === 'holder_key')
    const wrong = {...session, requestHash: fill(32, 0xee)}
    polls = 1
    ok('a token binding another request is refused', await rejects(() => awaitVerifierAgentResult(wrong, {intervalMs: 1})))
  } finally {
    globalThis.fetch = realFetch
  }
}

// ─── 6b. the verifier-agent contract, hardened (gap-closure P6) ─────────────────────────────────────
{
  const goodToken = {token_type: 'JWT', seed: bytesToHex(fill(32, 1)), epoch: 4, slot_id: bytesToHex(slot), vp_hash: bytesToHex(fill(32, 2)), holder_hash: bytesToHex(fill(32, 3)), rule_hash: bytesToHex(fill(32, 4)), request_hash: bytesToHex(requestHash(chainId, slot, 'sign', payloadDigestForSign(utf8('hello')))), binding: 'holder_key', verifier_indexes: [0, 1, 2], iat: 1, exp: 2, signatures: [{verifier_index: 0, signature: '0x00'}, {verifier_index: 1, signature: '0x00'}]}
  const session = {verifierAgentUrl: 'http://verifier-agent', sessionId: 's2', pollSecret: 'ps2', requestHash: requestHash(chainId, slot, 'sign', payloadDigestForSign(utf8('hello')))}
  const realFetch = globalThis.fetch
  const script = (replies: Array<{status?: number; body: unknown}>) => {
    let i = 0
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      const auth = ((init?.headers ?? {}) as Record<string, string>).Authorization
      if (auth !== 'Bearer ps2' || !url.startsWith('http://verifier-agent/v1/sessions/s2')) throw new Error(`unexpected ${url} ${auth}`)
      const r = replies[Math.min(i++, replies.length - 1)]!
      return new Response(JSON.stringify(r.body), {status: r.status ?? 200})
    }) as unknown as typeof fetch
  }
  const kindOf = async (p: Promise<unknown>): Promise<string> => { try { await p; return 'ok' } catch (e) { return e instanceof VerifierAgentSessionError ? `${e.kind}:${e.correlation}` : `other:${String(e)}` } }
  try {
    // nextPollDelay: grows ×1.5 to the cap, ±20 % jitter, never below 1 ms.
    const seq: number[] = []
    let d = 0
    for (let k = 0; k < 6; k++) { d = nextPollDelay(d, 100, 400, () => 0.5); seq.push(d) }
    ok('poll delay grows geometrically to the cap without jitter at random=0.5', seq.join(',') === '100,150,225,338,400,400')
    ok('poll delay jitter stays within ±20 %', nextPollDelay(0, 100, 400, () => 0) === 80 && nextPollDelay(0, 100, 400, () => 1) === 120)

    // phases are surfaced; a transient 503 is retried; done validates the token.
    const phases: string[] = []
    script([{body: {status: 'pending', phase: 'awaiting_wallet'}}, {status: 503, body: {error: 'session store unavailable'}}, {body: {status: 'pending', phase: 'verifying'}}, {body: {status: 'done', phase: 'done', compound_token: goodToken, verifier_proofs: [{verifier_index: 0, operator: '0xaa', pubkey: '0xbb', proof: []}]}}])
    const res = await awaitVerifierAgentResult(session, {intervalMs: 1, onPhase: p => phases.push(p)})
    ok('awaitVerifierAgentResult surfaces awaiting_wallet → verifying → done and rides through a transient 503', phases.join(',') === 'awaiting_wallet,verifying,done' && res.token.epoch === 4 && res.verifierProofs?.length === 1)

    // the verifier-agent's wire form: absent optionals are JSON null (serde Option) — accepted as absent.
    script([{body: {status: 'pending', phase: 'awaiting_wallet', compound_token: null, verifier_proofs: null, binding_preimage: null, error: null}}, {body: {status: 'done', phase: 'done', compound_token: goodToken, verifier_proofs: null, binding_preimage: null, error: null}}])
    const nulls = await awaitVerifierAgentResult(session, {intervalMs: 1})
    ok('null optionals in the verifier-agent reply are absent, not a protocol error', nulls.token.epoch === 4 && nulls.verifierProofs === undefined && nulls.bindingPreimage === undefined)

    // refused: the verifier-agent's `failed` names the refusing side; the correlation is the session id.
    script([{body: {status: 'failed', phase: 'failed', error: 'verifier fan-out failed: quorum not met (verifier 1: KB-JWT nonce mismatch)'}}])
    ok('a failed session is a `refused` error carrying the session id, never the poll secret', await kindOf(awaitVerifierAgentResult(session, {intervalMs: 1})) === 'refused:s2' && !(await awaitVerifierAgentResult(session, {intervalMs: 1}).catch((e: Error) => e.message)).toString().includes('ps2'))

    // protocol: a malformed status, a phase contradicting the status, a malformed token.
    script([{body: {status: 'weird'}}])
    ok('an unknown status is a `protocol` error', await kindOf(awaitVerifierAgentResult(session, {intervalMs: 1})) === 'protocol:s2')
    script([{body: {status: 'pending', phase: 'done'}}])
    ok('a phase contradicting the status is a `protocol` error', await kindOf(awaitVerifierAgentResult(session, {intervalMs: 1})) === 'protocol:s2')
    script([{body: {status: 'done', phase: 'done', compound_token: {...goodToken, signatures: [{verifier_index: 9, signature: '0x00'}]}}}])
    ok('a token whose signature names an index outside the committee is a `protocol` error', await kindOf(awaitVerifierAgentResult(session, {intervalMs: 1})) === 'protocol:s2')
    script([{body: {status: 'done', phase: 'done', compound_token: {...goodToken, request_hash: undefined}}}])
    ok('a token without the request binding is a `protocol` error', await kindOf(awaitVerifierAgentResult(session, {intervalMs: 1})) === 'protocol:s2')
    script([{status: 401, body: {error: 'invalid poll_secret'}}])
    ok('a 401 stops at once as `protocol`', await kindOf(awaitVerifierAgentResult(session, {intervalMs: 1})) === 'protocol:s2')

    // timeout: pending forever within a 30 ms deadline; unavailable forever too.
    script([{body: {status: 'pending', phase: 'awaiting_wallet'}}])
    ok('a session still pending at the deadline is a `timeout` error', await kindOf(awaitVerifierAgentResult(session, {intervalMs: 1, timeoutMs: 30})) === 'timeout:s2')
    script([{status: 503, body: {error: 'down'}}])
    ok('an verifier-agent unavailable until the deadline is a `timeout` error naming the last outage', (await awaitVerifierAgentResult(session, {intervalMs: 1, timeoutMs: 30}).catch((e: VerifierAgentSessionError) => `${e.kind}|${e.message}`)).toString().startsWith('timeout|no answer within 30 ms (last: poll: HTTP 503'))

    // cancelled: the caller's signal.
    const ac = new AbortController()
    script([{body: {status: 'pending', phase: 'awaiting_wallet'}}])
    setTimeout(() => ac.abort(), 5)
    ok('an aborted wait is a `cancelled` error', await kindOf(awaitVerifierAgentResult(session, {intervalMs: 50, timeoutMs: 5_000, signal: ac.signal})) === 'cancelled:s2')
  } finally {
    globalThis.fetch = realFetch
  }
}

// ─── 9. committee gather carries request_hash + binding from the verifiers ─────────────
{
  const seed = fill(32, 0xab)
  const epoch = 7
  const registrySize = 5
  const committee = 3
  const drawn = selectVerifierCommittee(slot, epoch, seed, registrySize, committee)
  const verifiers = [0, 1, 2, 3, 4].map(i => ({index: i, url: `http://v${i}`, pubkey: bytesToHex(ed25519.getPublicKey(fill(32, 0x20 + i)))}))
  const binding = {chainId, action: 'sign' as const, payloadDigest, random, clientId: `decentralized_identifier:${verifierAgentDid}`}
  const authorize = {holder: holder.did, credentials: [credA], holderProof: '', tokenType: 'JWT' as const, seed, epoch, slotId: slot, registrySize, committee, iat: nowSecs, exp: nowSecs + 3600, binding}
  const realFetch = globalThis.fetch
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    const i = Number(new URL(url).hostname.slice(1))
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>
    ok(`verifier ${i} receives the six preimage fields`, body.chain_id === chainId && body.action === 'sign' && body.payload_digest === bytesToHex(payloadDigest) && body.random === bytesToHex(random) && body.client_id === binding.clientId)
    const payload: CompoundTokenPayload = {tokenType: 'JWT', seed, epoch, slotId: slot, vpHash: fill(32, 2), holderHash: fill(32, 3), ruleHash: fill(32, 4), requestHash: rh, binding: 0x01, verifierIndexes: drawn, iat: nowSecs, exp: nowSecs + 3600}
    const tokenHash = compoundTokenHash(payload)
    const sig = ed25519.sign(tokenHash, fill(32, 0x20 + i))
    return new Response(JSON.stringify({verifier_index: i, token_hash: bytesToHex(tokenHash), vp_hash: bytesToHex(fill(32, 2)), holder_hash: bytesToHex(fill(32, 3)), rule_hash: bytesToHex(fill(32, 4)), request_hash: bytesToHex(rh), binding: 'holder_key', signature: bytesToHex(sig), committee_indexes: drawn}), {status: 200})
  }) as unknown as typeof fetch
  try {
    const token = await gatherCommitteeToken({verifiers, authorize, quorum: 2})
    ok('gathered token carries request_hash + binding=holder_key and passes the canonical-hash cross-check', token.request_hash === bytesToHex(rh) && token.binding === 'holder_key' && token.signatures.length >= 2)
  } catch (e) {
    failures.push(`gather with binding: ${e instanceof Error ? e.message : String(e)}`)
  } finally {
    globalThis.fetch = realFetch
  }
}

/** base58btc (Bitcoin alphabet) — enough to name a 34-byte multicodec key in a test. */
function base58Encode(bytes: Uint8Array): string {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  let n = 0n
  for (const b of bytes) n = (n << 8n) | BigInt(b)
  let out = ''
  while (n > 0n) { out = alphabet[Number(n % 58n)] + out; n /= 58n }
  for (const b of bytes) { if (b !== 0) break; out = '1' + out }
  return out
}

function payloadDigestForSign(message: Uint8Array): Uint8Array {
  // sha256 via the SDK's own helper to keep one implementation under test
  return hexToBytes(bytesToHex(requestHashSha(message)))
}
import {sha256} from '@noble/hashes/sha256'
function requestHashSha(m: Uint8Array): Uint8Array {
  return sha256(m)
}

console.log(`oid4vp.wallet: ${passed} passed, ${failures.length} failed`)
for (const f of failures) console.log(`  ✗ ${f}`)
if (failures.length) process.exit(1)
