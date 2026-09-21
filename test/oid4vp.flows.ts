// The OID4VP/OID4VCI flows that reach the network — JAR fetch + verification, the whole
// wallet presentation, and the OpenID4VCI pre-authorized code flow.
//
// test/oid4vp.wallet.ts drives the pieces individually against captured shapes. What had no
// coverage was the code that STITCHES them: `defaultKeyResolver`, `fetchRequestObject`,
// `presentToRequestUri` and `receiveCredential`'s alternate branches. Each is a sequence of
// remote calls where a wrong header, a skipped check or a missed fallback is invisible
// unless the request itself is inspected.
//
// The JAR here is really signed by a real did:web key and really verified, so the
// verification path is exercised rather than stubbed: a test that fed `verifyRequestObject`
// a token it could not check would pass while proving nothing.
//
// Three properties are the point:
//
//   • a JAR's `client_id` must name its `iss`, and its `kid` must belong to that DID.
//     Without both, a signer who controls any key in any document could issue a request
//     claiming to be the platform.
//   • the wallet must present exactly ONE credential and disclose exactly the claims the
//     chosen query names. Over-disclosure is a privacy failure a passing happy path hides.
//   • `receiveCredential` has four fallbacks (offer by value or reference, authorization
//     server metadata at two well-known paths, `c_nonce` from the token response or the
//     nonce endpoint, `credentials[]` or `credential`). Each is a real issuer shape.
//
// Run: tsx test/oid4vp.flows.ts — exits non-zero on any failure.

import {p256} from '@noble/curves/p256'
import {
  ed25519DidKey,
  ed25519HolderKey,
  p256HolderKey,
  p256PublicJwk,
  signCompactJws,
  type Jwk,
} from '../src/oid4vp/jose.ts'
import {
  CLIENT_ID_PREFIX_DID,
  REQUEST_OBJECT_TYP,
  defaultKeyResolver,
  fetchRequestObject,
  parseOpenid4vpUri,
  responseEncryptionKey,
  verifyRequestObject,
  type RequestObjectClaims,
} from '../src/oid4vp/request-object.ts'
import {didJwkIssuer, holderCnf, issueSdJwtVc, parseSdJwt} from '../src/oid4vp/sd-jwt.ts'
import {buildResponse, planPresentation, presentToRequestUri, submitResponse, type HeldSdJwt} from '../src/oid4vp/wallet.ts'
import {decryptJwe} from '../src/oid4vp/jwe.ts'
import {
  CREDENTIAL_OFFER_SCHEME,
  PRE_AUTHORIZED_GRANT,
  PROOF_TYP,
  parseCredentialOfferUri,
  receiveCredential,
} from '../src/oid4vp/oid4vci.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean, detail = ''): void {
  if (cond) passed++
  else failures.push(name + (detail ? ` — ${detail}` : ''))
}
function eq(name: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual)
  const b = JSON.stringify(expected)
  ok(name, a === b, `got ${a}, want ${b}`)
}
function throwsWith(name: string, re: RegExp, run: () => unknown): void {
  try {
    run()
    ok(name, false, 'did not throw')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    ok(name, re.test(message), `message was ${JSON.stringify(message)}`)
  }
}
async function rejectsWith(name: string, re: RegExp, run: () => Promise<unknown>): Promise<void> {
  try {
    await run()
    ok(name, false, 'did not throw')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    ok(name, re.test(message), `message was ${JSON.stringify(message)}`)
  }
}
const fill = (n: number, v: number): Uint8Array => new Uint8Array(n).fill(v)

// ─── the platform's did:web identity ──────────────────────────────────────────
const AGENT_HOST = 'agent.example'
const AGENT_DID = `did:web:${AGENT_HOST}`
const agentKey = ed25519HolderKey(fill(32, 0x11))
// Named by KEY, which is the current encoding: `did:web:<host>#z6Mk…`, the fragment being
// the key's own did:key id. That is what makes a roster change leave every fragment meaning
// the same thing it did before.
const agentPublicKey = Uint8Array.from(Buffer.from((agentKey.publicJwk as {x: string}).x, 'base64url'))
const AGENT_KID = `${AGENT_DID}#${ed25519DidKey(agentPublicKey).slice('did:key:'.length)}`
const didDoc = {
  id: AGENT_DID,
  verificationMethod: [{id: AGENT_KID, type: 'JsonWebKey2020', controller: AGENT_DID, publicKeyJwk: agentKey.publicJwk}],
  authentication: [AGENT_KID],
}

// ─── the holder and a credential it holds ─────────────────────────────────────
const holder = p256HolderKey(fill(32, 0x22))
const issuerPriv = fill(32, 0x33)
const issuer = didJwkIssuer(issuerPriv)
const employeeVc = issueSdJwtVc({
  issuer,
  vct: 'https://example.com/EmployeeCard',
  claims: {given_name: 'Alice', family_name: 'Ng', dept: 'Engineering', salary_band: 'L7'},
  cnf: holderCnf(holder),
  sub: holder.did,
  nowSecs: 1_000,
  ttlSecs: 9_000_000,
})
const held: HeldSdJwt[] = [{sdJwt: employeeVc, label: 'Employee card'}]

const dcqlQuery = {
  credentials: [
    {
      id: 'employee',
      format: 'dc+sd-jwt' as const,
      meta: {vct_values: ['https://example.com/EmployeeCard']},
      claims: [{path: ['given_name']}, {path: ['dept'], values: ['Engineering']}],
    },
  ],
}

/** The ephemeral P-256 key the verifier-agent offers for response encryption. */
const agentEncPriv = p256.utils.randomPrivateKey()
const agentEncJwk: Jwk = {...p256PublicJwk(agentEncPriv), kid: 'enc-1'}

const RESPONSE_URI = `https://${AGENT_HOST}/v1/sessions/abc/response`
function jarClaims(over: Partial<RequestObjectClaims> = {}): RequestObjectClaims {
  return {
    iss: AGENT_DID,
    client_id: `${CLIENT_ID_PREFIX_DID}${AGENT_DID}`,
    response_type: 'vp_token',
    response_mode: 'direct_post.jwt',
    response_uri: RESPONSE_URI,
    nonce: 'derived-nonce-xyz',
    state: 'state-1',
    iat: 1_000,
    exp: 9_999_999_999,
    dcql_query: dcqlQuery,
    client_metadata: {jwks: {keys: [agentEncJwk]}, encrypted_response_enc_values_supported: ['A256GCM']},
    ...over,
  }
}
const signJar = (claims: RequestObjectClaims, kid = AGENT_KID, typ = REQUEST_OBJECT_TYP): string =>
  signCompactJws({typ, kid}, claims, {alg: 'EdDSA', privateKey: agentKey.privateKey})

// ─── the network stub ─────────────────────────────────────────────────────────
interface Sent {
  url: string
  method: string
  headers: Record<string, string>
  body: string
}
const sent: Sent[] = []
const jar = signJar(jarClaims())
/** Status to serve for the request_uri (200 = the JAR). */
let jarStatus = 200
/** What the response_uri answers with. */
let responseBody: unknown = {redirect_uri: 'https://app.example/done'}
let responseStatus = 200
const lastTo = (fragment: string): Sent | undefined => [...sent].reverse().find(s => s.url.includes(fragment))

// ─── the OpenID4VCI issuer ────────────────────────────────────────────────────
const ISSUER = 'https://issuer.example'
const OFFER = {
  credential_issuer: ISSUER,
  credential_configuration_ids: ['EmployeeCard'],
  grants: {[PRE_AUTHORIZED_GRANT]: {'pre-authorized_code': 'pre-auth-code-1'}},
}
/** Issuer behaviour switches, one per real-world shape. */
const vci = {
  offerByReference: false,
  requireTxCode: false,
  cNonceInToken: true,
  nonceEndpoint: false,
  credentialsArray: false,
  oauthWellKnown: true,
  authorizationServer: undefined as string | undefined,
  omitCredential: false,
  tokenStatus: 200,
  credentialStatus: 200,
}

/**
 * When set, a failing response's own `text()`/`json()` REJECT.
 *
 * ⚠ This is the case the `.catch(() => '')` guards in the error paths exist for: a handler
 * that throws while building its own message replaces a useful diagnosis ("HTTP 502 from
 * the token endpoint") with an opaque unrelated failure. An untested guard of that kind is
 * indistinguishable from a missing one.
 */
let unreadableBodies = false

const realFetch = globalThis.fetch
globalThis.fetch = (async (url: string, init?: RequestInit) => {
  const u = String(url)
  sent.push({
    url: u,
    method: String(init?.method ?? 'GET'),
    headers: (init?.headers ?? {}) as Record<string, string>,
    body: String(init?.body ?? ''),
  })
  const unreadable = (status: number): Response =>
    ({
      ok: false,
      status,
      text: () => Promise.reject(new Error('socket closed mid-body')),
      json: () => Promise.reject(new Error('socket closed mid-body')),
    } as unknown as Response)
  const json = (o: unknown, status = 200): Response =>
    status >= 400 && unreadableBodies
      ? unreadable(status)
      : ({ok: status < 400, status, json: async () => o, text: async () => JSON.stringify(o)} as unknown as Response)
  const text = (s: string, status = 200): Response =>
    status >= 400 && unreadableBodies
      ? unreadable(status)
      : ({ok: status < 400, status, text: async () => s, json: async () => JSON.parse(s)} as unknown as Response)

  // did:web document
  if (u === `https://${AGENT_HOST}/.well-known/did.json`) return json(didDoc)
  // the JAR
  if (u.includes('/request-object')) {
    return jarStatus === 200 ? text(`${jar}\n`) : text('gone', jarStatus)
  }
  // the wallet's POST
  if (u === RESPONSE_URI) return json(responseBody, responseStatus)

  // ── OpenID4VCI ──
  if (u === 'https://issuer.example/offer.json') return json(OFFER)
  if (u === `${ISSUER}/.well-known/openid-credential-issuer`) {
    return json({
      credential_issuer: ISSUER,
      credential_endpoint: `${ISSUER}/credential`,
      ...(vci.nonceEndpoint ? {nonce_endpoint: `${ISSUER}/nonce`} : {}),
      ...(vci.authorizationServer ? {authorization_servers: [vci.authorizationServer]} : {}),
      credential_configurations_supported: {EmployeeCard: {format: 'dc+sd-jwt', vct: 'https://example.com/EmployeeCard'}},
    })
  }
  if (u.endsWith('/.well-known/oauth-authorization-server')) {
    // A deployment may serve only the OIDC path, so this one can 404 and the client must
    // fall back rather than fail.
    return vci.oauthWellKnown ? json({token_endpoint: `${new URL(u).origin}/token`}) : json({}, 404)
  }
  if (u.endsWith('/.well-known/openid-configuration')) return json({token_endpoint: `${new URL(u).origin}/token`})
  if (u.endsWith('/token')) {
    return json({access_token: 'at-1', ...(vci.cNonceInToken ? {c_nonce: 'c-nonce-from-token'} : {})}, vci.tokenStatus)
  }
  if (u.endsWith('/nonce')) return json({c_nonce: 'c-nonce-from-endpoint'})
  if (u.endsWith('/credential')) {
    if (vci.credentialStatus !== 200) return json({}, vci.credentialStatus)
    if (vci.omitCredential) return json({})
    return vci.credentialsArray ? json({credentials: [{credential: employeeVc}]}) : json({credential: employeeVc})
  }
  return text(`no route ${u}`, 404)
}) as typeof globalThis.fetch

try {
  // ─── parsing the QR payload ───────────────────────────────────────────────
  {
    const uri = `openid4vp://?client_id=${encodeURIComponent(`${CLIENT_ID_PREFIX_DID}${AGENT_DID}`)}&request_uri=${encodeURIComponent(`https://${AGENT_HOST}/request-object/1`)}`
    const parsed = parseOpenid4vpUri(uri)
    eq('the request_uri is url-decoded', parsed.requestUri, `https://${AGENT_HOST}/request-object/1`)
    eq('the client_id comes back when present', parsed.clientId, `${CLIENT_ID_PREFIX_DID}${AGENT_DID}`)
    eq('a missing client_id is undefined, not an error', parseOpenid4vpUri('openid4vp://?request_uri=https://x/y').clientId, undefined)
    throwsWith('a URI with no request_uri is refused', /carries no request_uri/, () => parseOpenid4vpUri('openid4vp://?client_id=x'))
    throwsWith('a URI with no query at all is refused', /carries no request_uri/, () => parseOpenid4vpUri('openid4vp://'))
  }

  // ─── verifying the JAR ────────────────────────────────────────────────────
  {
    const verified = await verifyRequestObject(jar, {nowSecs: 2_000})
    eq('the signer DID is the iss', verified.signerDid, AGENT_DID)
    eq('the header kid is carried through', verified.header.kid, AGENT_KID)
    eq('the nonce is available for the KB-JWT', verified.claims.nonce, 'derived-nonce-xyz')
    ok('the resolved signer key is the agent key', (verified.signerKey as {x: string}).x === (agentKey.publicJwk as {x: string}).x)
    ok('the did:web document was fetched', !!lastTo('/.well-known/did.json'))

    // ⚠ `client_id` must name `iss`. Without this, anyone holding any key could sign a
    // request claiming to be the platform and the wallet would present to them.
    await rejectsWith('a client_id that does not name its iss is refused', /client_id does not name its iss/, () =>
      verifyRequestObject(signJar(jarClaims({client_id: `${CLIENT_ID_PREFIX_DID}did:web:evil.example`})), {nowSecs: 2_000}),
    )
    // The bare (unprefixed) form is accepted, since the prefix is what the client agreed.
    ok(
      'a bare client_id equal to iss is accepted',
      !!(await verifyRequestObject(signJar(jarClaims({client_id: AGENT_DID})), {nowSecs: 2_000})),
    )
    // ⚠ The kid must belong to the SAME DID as iss.
    await rejectsWith('a kid from another DID is refused', /kid belongs to a different DID than iss/, () =>
      verifyRequestObject(signJar(jarClaims(), 'did:web:evil.example#k'), {nowSecs: 2_000}),
    )
    await rejectsWith('a wrong typ is refused, naming the expected one', new RegExp(`typ must be ${REQUEST_OBJECT_TYP.replace('+', '\\+')}`), () =>
      verifyRequestObject(signJar(jarClaims(), AGENT_KID, 'JWT'), {nowSecs: 2_000}),
    )
    await rejectsWith('a non-DID iss is refused', /iss is not a DID/, () =>
      verifyRequestObject(signJar(jarClaims({iss: 'https://agent.example', client_id: 'https://agent.example'})), {nowSecs: 2_000}),
    )
    await rejectsWith('a non-compact JWS is refused', /not a compact JWS/, () => verifyRequestObject('a.b', {}))
    // Expiry, with the documented default leeway of 60s.
    await rejectsWith('an expired JAR is refused', /request object expired/, () =>
      verifyRequestObject(signJar(jarClaims({exp: 1_000})), {nowSecs: 5_000}),
    )
    ok(
      'a JAR just inside the leeway is accepted',
      !!(await verifyRequestObject(signJar(jarClaims({exp: 1_000})), {nowSecs: 1_030})),
    )
    ok(
      'the leeway is configurable',
      !!(await verifyRequestObject(signJar(jarClaims({exp: 1_000})), {nowSecs: 5_000, leewaySecs: 10_000})),
    )
    // The remaining required claims.
    for (const [label, over] of [
      ['no nonce', {nonce: ''}],
      ['no response_uri', {response_uri: undefined as unknown as string}],
      ['no dcql_query', {dcql_query: undefined as never}],
    ] as Array<[string, Partial<RequestObjectClaims>]>) {
      await rejectsWith(`a JAR with ${label} is refused`, /request object has no/, () =>
        verifyRequestObject(signJar(jarClaims(over)), {nowSecs: 2_000}),
      )
    }
    // A signature that does not verify must fail even when every claim is well-formed.
    await rejectsWith('a JAR signed by another key is refused', /signature does not verify/, () =>
      verifyRequestObject(
        signCompactJws({typ: REQUEST_OBJECT_TYP, kid: AGENT_KID}, jarClaims(), {alg: 'EdDSA', privateKey: fill(32, 0x99)}),
        {nowSecs: 2_000},
      ),
    )
  }

  // ─── defaultKeyResolver ───────────────────────────────────────────────────
  {
    const resolver = defaultKeyResolver()
    const web = await resolver(AGENT_DID, AGENT_KID)
    eq('a did:web key is resolved from the document', (web as {x: string}).x, (agentKey.publicJwk as {x: string}).x)
    // did:key / did:jwk resolve OFFLINE — no request at all, which is what makes a local
    // verification possible.
    sent.length = 0
    const offline = await resolver(holder.did, undefined)
    eq('a did:jwk key is resolved with no network call', sent.length, 0)
    eq('…and it is the right key', (offline as {x: string}).x, (holder.publicJwk as {x: string}).x)
  }

  // ─── fetchRequestObject ───────────────────────────────────────────────────
  {
    sent.length = 0
    const verified = await fetchRequestObject(`https://${AGENT_HOST}/request-object/1`, {nowSecs: 2_000})
    eq('the fetched JAR verifies', verified.signerDid, AGENT_DID)
    // The Accept header is what tells a compliant agent to serve the JAR rather than HTML.
    eq('the request asks for the JAR media type', lastTo('/request-object')?.headers.Accept, `application/${REQUEST_OBJECT_TYP}`)
    // The served body had a trailing newline; it must be trimmed rather than break parsing.
    ok('surrounding whitespace in the served JAR is tolerated', !!verified.jwt)
    jarStatus = 410
    await rejectsWith('a non-200 request_uri reports the URL and status', /request_uri https:\/\/agent\.example\/request-object\/1 → HTTP 410/, () =>
      fetchRequestObject(`https://${AGENT_HOST}/request-object/1`, {nowSecs: 2_000}),
    )
    jarStatus = 200
  }

  // ─── response encryption key ──────────────────────────────────────────────
  {
    ok('the agent\'s P-256 key is offered for encryption', !!responseEncryptionKey({claims: jarClaims()}))
    eq('no client_metadata means no encryption', responseEncryptionKey({claims: jarClaims({client_metadata: undefined})}), undefined)
    // A non-P-256 key is not usable for this profile and must not be picked up.
    eq(
      'an Ed25519 key in client_metadata is not treated as an encryption key',
      responseEncryptionKey({claims: jarClaims({client_metadata: {jwks: {keys: [agentKey.publicJwk]}}})}),
      undefined,
    )
  }

  // ─── the wallet: plan, build, submit ──────────────────────────────────────
  {
    const ro = await verifyRequestObject(jar, {nowSecs: 2_000})
    const plan = planPresentation(ro, held, 2_000)
    ok('the held credential satisfies the query', plan.satisfies)
    eq('exactly one candidate answers', plan.candidates.length, 1)
    eq('the candidate names the query it answers', plan.candidates[0]?.queryId, 'employee')
    eq('nothing is unmatched', plan.unmatched, [])

    const built = buildResponse({ro, candidate: plan.chosen!, holder, nowSecs: 2_000})
    ok('the response is encrypted when the agent offered a key', built.encrypted)
    eq('the form carries a single `response` field', Object.keys(built.form), ['response'])
    // The JARM payload must decrypt with the agent's private key and carry the presentation
    // under the QUERY ID — a wallet that keyed it differently is silently unreadable.
    const decrypted = JSON.parse(decryptJwe(built.form.response!, agentEncPriv)) as {
      vp_token: Record<string, string[]>
      state: string
    }
    eq('the decrypted payload is keyed by query id', Object.keys(decrypted.vp_token), ['employee'])
    eq('the state is echoed', decrypted.state, 'state-1')
    eq('one presentation is sent', decrypted.vp_token.employee?.length, 1)

    // ⚠ Selective disclosure: exactly the claims the query names, and nothing else. The
    // credential also holds family_name and salary_band; presenting those would be a
    // privacy failure no happy-path assertion would notice.
    const shown = parseSdJwt(decrypted.vp_token.employee![0]!).disclosures.map(d => d.name).sort()
    eq('only the queried claims are disclosed', shown, ['dept', 'given_name'])
    ok('the salary band is NOT disclosed', !shown.includes('salary_band'))

    // `disclose: 'all'` is the explicit opt-out.
    const all = buildResponse({ro, candidate: plan.chosen!, holder, disclose: 'all', nowSecs: 2_000})
    const allShown = parseSdJwt(JSON.parse(all.payload).vp_token.employee[0] as string).disclosures.map(d => d.name)
    eq('disclose:all reveals every claim', allShown.length, 4)
    // And an explicit list is honoured verbatim.
    const one = buildResponse({ro, candidate: plan.chosen!, holder, disclose: ['dept'], nowSecs: 2_000})
    eq('an explicit disclose list is honoured', parseSdJwt(JSON.parse(one.payload).vp_token.employee[0] as string).disclosures.map(d => d.name), ['dept'])

    // With no encryption key the form carries the plain fields instead.
    const plainRo = {claims: jarClaims({client_metadata: undefined})}
    const plainBuilt = buildResponse({ro: plainRo, candidate: plan.chosen!, holder, nowSecs: 2_000})
    ok('an unencrypted response is marked as such', !plainBuilt.encrypted)
    eq('the plain form carries vp_token and state', Object.keys(plainBuilt.form).sort(), ['state', 'vp_token'])

    // The agent may only support A128GCM; the wallet must follow rather than insist.
    const a128 = buildResponse({
      ro: {claims: jarClaims({client_metadata: {jwks: {keys: [agentEncJwk]}, encrypted_response_enc_values_supported: ['A128GCM']}})},
      candidate: plan.chosen!,
      holder,
      nowSecs: 2_000,
    })
    const encHeader = JSON.parse(Buffer.from(a128.form.response!.split('.')[0]!, 'base64url').toString()) as {enc: string}
    eq('the wallet honours an agent that only lists A128GCM', encHeader.enc, 'A128GCM')

    // Submit.
    sent.length = 0
    const {redirectUri} = await submitResponse(ro, built)
    eq('the response is form-encoded', lastTo('/response')?.headers['Content-Type'], 'application/x-www-form-urlencoded')
    ok('the body is a urlencoded response field', lastTo('/response')?.body.startsWith('response=') === true)
    eq('a redirect_uri is returned when the agent gives one', redirectUri, 'https://app.example/done')
    responseBody = {}
    eq('no redirect_uri is undefined rather than an error', (await submitResponse(ro, built)).redirectUri, undefined)
    responseStatus = 400
    await rejectsWith('a rejected response reports the status', /response_uri → HTTP 400/, () => submitResponse(ro, built))
    responseStatus = 200
    responseBody = {redirect_uri: 'https://app.example/done'}
  }
  {
    // An expired credential is skipped: `nowSecs` past its exp leaves nothing to present.
    const ro = await verifyRequestObject(jar, {nowSecs: 2_000})
    const expiredPlan = planPresentation(ro, held, 9_999_999)
    ok('an expired credential is not a candidate', !expiredPlan.satisfies && expiredPlan.candidates.length === 0)
    eq('the unanswered query is reported', expiredPlan.unmatched, ['employee'])
    // A malformed stored credential is skipped rather than throwing — a wallet with one bad
    // entry must still present the others.
    const withGarbage = planPresentation(ro, [{sdJwt: 'not-a-credential'}, ...held], 2_000)
    ok('a malformed held credential is skipped, not fatal', withGarbage.satisfies)
    // A credential that does not match the query is not offered.
    const otherVc = issueSdJwtVc({
      issuer,
      vct: 'https://example.com/GymCard',
      claims: {given_name: 'Alice', dept: 'Engineering'},
      cnf: holderCnf(holder),
      nowSecs: 1_000,
      ttlSecs: 9_000_000,
    })
    const wrongVct = planPresentation(ro, [{sdJwt: otherVc}], 2_000)
    ok('a credential of another vct does not answer the query', !wrongVct.satisfies)
  }

  // ─── presentToRequestUri: the whole flow ──────────────────────────────────
  {
    sent.length = 0
    const result = await presentToRequestUri(`https://${AGENT_HOST}/request-object/1`, held, holder, {nowSecs: 2_000})
    eq('the flow returns the verified request object', result.ro.signerDid, AGENT_DID)
    ok('…the plan', result.plan.satisfies)
    ok('…the built response', result.built.encrypted)
    eq('…and the redirect', result.redirectUri, 'https://app.example/done')
    // The order matters: JAR first, response last.
    const order = sent.map(s => s.url).filter(u => u.includes('request-object') || u === RESPONSE_URI)
    eq('the JAR is fetched before the response is posted', order, [`https://${AGENT_HOST}/request-object/1`, RESPONSE_URI])

    // An `openid4vp://` deep link is accepted directly.
    sent.length = 0
    const viaUri = await presentToRequestUri(
      `openid4vp://?request_uri=${encodeURIComponent(`https://${AGENT_HOST}/request-object/1`)}`,
      held,
      holder,
      {nowSecs: 2_000},
    )
    ok('an openid4vp:// deep link is unwrapped', viaUri.plan.satisfies)

    // `choose` is the consent screen. Returning undefined ABORTS — a wallet must be able to
    // decline, and declining must not post anything.
    sent.length = 0
    await rejectsWith('declining at the consent step aborts', /presentation declined/, () =>
      presentToRequestUri(`https://${AGENT_HOST}/request-object/1`, held, holder, {nowSecs: 2_000, choose: () => undefined}),
    )
    ok('a declined presentation posts nothing', !sent.some(s => s.url === RESPONSE_URI))
    // And the chooser's pick is what gets presented.
    let offered = 0
    const chosen = await presentToRequestUri(`https://${AGENT_HOST}/request-object/1`, held, holder, {
      nowSecs: 2_000,
      choose: plan => {
        offered = plan.candidates.length
        return plan.candidates[0]
      },
      disclose: ['dept'],
    })
    eq('the chooser saw the candidates', offered, 1)
    eq('the chooser\'s disclose list is honoured', parseSdJwt(chosen.built.presentation).disclosures.map(d => d.name), ['dept'])

    // Nothing held → the error names the query that went unanswered, not a generic failure.
    await rejectsWith('an empty wallet names the unanswered query', /no held credential answers: employee/, () =>
      presentToRequestUri(`https://${AGENT_HOST}/request-object/1`, [], holder, {nowSecs: 2_000}),
    )
  }

  // ─── OpenID4VCI ───────────────────────────────────────────────────────────
  {
    // Offer parsing, both shapes.
    const byValue = `${CREDENTIAL_OFFER_SCHEME}?credential_offer=${encodeURIComponent(JSON.stringify(OFFER))}`
    eq('an offer by value parses inline', parseCredentialOfferUri(byValue).offer?.credential_issuer, ISSUER)
    eq('an offer by reference returns the URI', parseCredentialOfferUri(`${CREDENTIAL_OFFER_SCHEME}?credential_offer_uri=https://issuer.example/offer.json`).offerUri, 'https://issuer.example/offer.json')
    throwsWith('an offer URI with neither parameter is refused', /neither credential_offer nor credential_offer_uri/, () =>
      parseCredentialOfferUri(`${CREDENTIAL_OFFER_SCHEME}?nothing=1`),
    )

    // The full flow, offer by value.
    sent.length = 0
    const received = await receiveCredential({offer: OFFER, holder, nowSecs: 3_000})
    eq('the issued credential comes back', received.credential, employeeVc)
    eq('the configuration and format are reported', [received.configurationId, received.format], ['EmployeeCard', 'dc+sd-jwt'])
    eq('the issuer identifier is reported', received.issuer, ISSUER)

    // The token request is form-encoded with the pre-authorized grant.
    const tokenCall = lastTo('/token')
    ok('the token request uses the pre-authorized grant', tokenCall?.body.includes(`grant_type=${encodeURIComponent(PRE_AUTHORIZED_GRANT)}`) === true)
    ok('the pre-authorized code is sent', tokenCall?.body.includes('pre-authorized_code=pre-auth-code-1') === true)
    // The credential request carries the access token and a proof.
    const credCall = lastTo('/credential')
    eq('the credential request bears the access token', credCall?.headers.Authorization, 'Bearer at-1')
    const credBody = JSON.parse(credCall?.body ?? '{}') as {credential_configuration_id: string; proofs: {jwt: string[]}}
    eq('the configuration id is named', credBody.credential_configuration_id, 'EmployeeCard')
    eq('exactly one proof is sent, under proofs.jwt', credBody.proofs.jwt.length, 1)
    // ⚠ The proof binds the holder key to THIS issuer and THIS nonce. Its typ, kid and aud
    // are all fixed by the spec and by what the issuer checks.
    const proof = credBody.proofs.jwt[0]!
    const proofHeader = JSON.parse(Buffer.from(proof.split('.')[0]!, 'base64url').toString()) as {typ: string; kid: string; alg: string}
    const proofClaims = JSON.parse(Buffer.from(proof.split('.')[1]!, 'base64url').toString()) as {aud: string; nonce?: string; iat: number}
    eq('the proof typ is the OpenID4VCI one', proofHeader.typ, PROOF_TYP)
    eq('the proof kid is the holder did:jwk #0', proofHeader.kid, `${holder.did}#0`)
    eq('the proof alg is ES256', proofHeader.alg, 'ES256')
    eq('the proof audience is the credential issuer', proofClaims.aud, ISSUER)
    eq('the c_nonce from the token response is used', proofClaims.nonce, 'c-nonce-from-token')
    eq('iat is the supplied clock', proofClaims.iat, 3_000)
  }
  {
    // Offer BY REFERENCE: the offer is fetched first.
    sent.length = 0
    const received = await receiveCredential({
      offerUri: `${CREDENTIAL_OFFER_SCHEME}?credential_offer_uri=https://issuer.example/offer.json`,
      holder,
      nowSecs: 3_000,
    })
    eq('an offer by reference is fetched and used', received.credential, employeeVc)
    ok('the offer URL was fetched', !!lastTo('/offer.json'))
  }
  {
    // No c_nonce in the token response → fall back to the nonce endpoint.
    vci.cNonceInToken = false
    vci.nonceEndpoint = true
    sent.length = 0
    await receiveCredential({offer: OFFER, holder, nowSecs: 3_000})
    const proof = (JSON.parse(lastTo('/credential')?.body ?? '{}') as {proofs: {jwt: string[]}}).proofs.jwt[0]!
    eq('the nonce endpoint is the documented fallback', (JSON.parse(Buffer.from(proof.split('.')[1]!, 'base64url').toString()) as {nonce?: string}).nonce, 'c-nonce-from-endpoint')
    ok('the nonce endpoint was POSTed', lastTo('/nonce')?.method === 'POST')
    // Neither source → the proof simply carries no nonce (the issuer may not require one).
    vci.nonceEndpoint = false
    sent.length = 0
    await receiveCredential({offer: OFFER, holder, nowSecs: 3_000})
    const proof2 = (JSON.parse(lastTo('/credential')?.body ?? '{}') as {proofs: {jwt: string[]}}).proofs.jwt[0]!
    eq('with no nonce available the claim is omitted', (JSON.parse(Buffer.from(proof2.split('.')[1]!, 'base64url').toString()) as {nonce?: string}).nonce, undefined)
    vci.cNonceInToken = true
  }
  {
    // The AS metadata has two well-known paths; a deployment may serve only the OIDC one.
    vci.oauthWellKnown = false
    sent.length = 0
    const received = await receiveCredential({offer: OFFER, holder, nowSecs: 3_000})
    eq('a 404 on oauth-authorization-server falls back to openid-configuration', received.credential, employeeVc)
    ok('both well-known paths were tried', !!lastTo('/.well-known/openid-configuration'))
    vci.oauthWellKnown = true
  }
  {
    // A separate authorization server is honoured when the metadata names one.
    vci.authorizationServer = 'https://as.example'
    sent.length = 0
    await receiveCredential({offer: OFFER, holder, nowSecs: 3_000})
    ok('the named authorization server is used for the token', lastTo('/token')?.url.startsWith('https://as.example') === true)
    vci.authorizationServer = undefined
  }
  {
    // Either credential response shape.
    vci.credentialsArray = true
    eq('a credentials[] response is accepted', (await receiveCredential({offer: OFFER, holder, nowSecs: 3_000})).credential, employeeVc)
    vci.credentialsArray = false
    vci.omitCredential = true
    await rejectsWith('a response with no credential at all is named', /carries no credential/, () =>
      receiveCredential({offer: OFFER, holder, nowSecs: 3_000}),
    )
    vci.omitCredential = false
  }
  {
    // The guards, each naming what is missing.
    await rejectsWith('neither offer nor offerUri is refused', /needs an offer or an offerUri/, () =>
      receiveCredential({holder, nowSecs: 3_000}),
    )
    await rejectsWith('an offer with no pre-authorized grant is refused', /no pre-authorized code grant/, () =>
      receiveCredential({offer: {...OFFER, grants: {}}, holder, nowSecs: 3_000}),
    )
    // A tx_code grant needs the code the issuer displayed — proceeding without it would
    // fail at the token endpoint with a less useful message.
    await rejectsWith('a tx_code grant without the code is refused up front', /requires a transaction code \(tx_code\)/, () =>
      receiveCredential({
        offer: {...OFFER, grants: {[PRE_AUTHORIZED_GRANT]: {'pre-authorized_code': 'c', tx_code: {length: 4}}}},
        holder,
        nowSecs: 3_000,
      }),
    )
    // …and with it, the code is forwarded.
    sent.length = 0
    await receiveCredential({
      offer: {...OFFER, grants: {[PRE_AUTHORIZED_GRANT]: {'pre-authorized_code': 'c', tx_code: {length: 4}}}},
      holder,
      txCode: '1234',
      nowSecs: 3_000,
    })
    ok('a supplied tx_code is sent to the token endpoint', lastTo('/token')?.body.includes('tx_code=1234') === true)

    await rejectsWith('an unadvertised configuration is refused, naming it', /does not advertise configuration Nope/, () =>
      receiveCredential({offer: OFFER, holder, credentialConfigurationId: 'Nope', nowSecs: 3_000}),
    )
    await rejectsWith('an offer naming no configuration is refused', /names no credential configuration/, () =>
      receiveCredential({offer: {...OFFER, credential_configuration_ids: []}, holder, nowSecs: 3_000}),
    )
  }

  // ─── an error path must not fail while building its own message ─────────────
  {
    // ⚠ Every one of these reads the failed response's body to enrich the error. If that
    // read throws — a truncated body, a closed socket — the guard must swallow it and still
    // report the STATUS, because a diagnosis is the only thing the caller has left.
    unreadableBodies = true

    responseStatus = 502
    const ro = await verifyRequestObject(jar, {nowSecs: 2_000})
    const plan = planPresentation(ro, held, 2_000)
    const built = buildResponse({ro, candidate: plan.chosen!, holder, nowSecs: 2_000})
    await rejectsWith('an unreadable response_uri error still reports the status', /response_uri → HTTP 502/, () =>
      submitResponse(ro, built),
    )
    responseStatus = 200

    jarStatus = 503
    await rejectsWith('an unreadable request_uri error still reports the status', /request_uri .* → HTTP 503/, () =>
      fetchRequestObject(`https://${AGENT_HOST}/request-object/1`, {nowSecs: 2_000}),
    )
    jarStatus = 200

    vci.tokenStatus = 500
    await rejectsWith('an unreadable token error still reports the status', /token endpoint → HTTP 500/, () =>
      receiveCredential({offer: OFFER, holder, nowSecs: 3_000}),
    )
    vci.tokenStatus = 200

    vci.credentialStatus = 403
    await rejectsWith('an unreadable credential error still reports the status', /credential endpoint → HTTP 403/, () =>
      receiveCredential({offer: OFFER, holder, nowSecs: 3_000}),
    )
    vci.credentialStatus = 200

    unreadableBodies = false
  }
  {
    // A response body that is valid HTTP but not JSON must not take out a successful
    // submission — the redirect is optional.
    responseBody = 'not json at all'
    const ro = await verifyRequestObject(jar, {nowSecs: 2_000})
    const plan = planPresentation(ro, held, 2_000)
    const built = buildResponse({ro, candidate: plan.chosen!, holder, nowSecs: 2_000})
    const nonJson: typeof fetch = (async () =>
      ({ok: true, status: 200, json: () => Promise.reject(new Error('not json')), text: async () => 'ok'}) as unknown as Response) as typeof fetch
    eq('a non-JSON success body yields no redirect rather than an error', (await submitResponse(ro, built, nonJson)).redirectUri, undefined)
    responseBody = {redirect_uri: 'https://app.example/done'}
  }
} finally {
  globalThis.fetch = realFetch
}

if (failures.length > 0) {
  console.error(`✗ oid4vp.flows: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ oid4vp.flows: ${passed} checks passed`)
