// The verifier HTTP client — every call's wire shape, and the client-side JWT helpers.
//
// src/auth/verifier.ts is thin, which is exactly why it was worth covering: every function
// is a hand-written camelCase ↔ snake_case mapping over an endpoint, and a mistyped field
// name is a 400 or, worse, a silently ignored option. Five of its functions had never been
// called at all.
//
// Three things here are more than field mapping:
//
//   • `revokeRenewal` must NOT parse its response. Revoke answers 200/204 with an EMPTY
//     body, so routing it through the shared `postJson` would throw on a successful
//     revocation. The source says so in a comment; this asserts it.
//   • `revokeSlotUser` validates the DID BEFORE any request. The verifier blocklists
//     strictly by DID, so sending a handle would report success while revoking nobody.
//   • `rotate` defaults to TRUE. Revoking without rotating leaves the revoked holder's JWT
//     useful against everything encrypted before the rotation, so the safe value has to be
//     the default rather than the caller's responsibility.
//
// Run: tsx test/auth.verifier-client.ts — exits non-zero on any failure.

import {
  createRenewal,
  decodeJwtClaims,
  isJwtExpiringSoon,
  issueAdminCredential,
  jwtExpMs,
  redeemCredential,
  redeemRenewalToken,
  revokeRenewal,
  revokeSlotUser,
  verifyPresentation,
  verifyVpJwt,
} from '../src/auth/verifier.ts'

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
async function rejectsWith(name: string, re: RegExp, run: () => Promise<unknown>): Promise<void> {
  try {
    await run()
    ok(name, false, 'did not throw')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    ok(name, re.test(message), `message was ${JSON.stringify(message)}`)
  }
}

const VERIFIER = 'http://verifier.example'
const DID = 'did:example:alice'

// ─── the verifier stub ────────────────────────────────────────────────────────
interface Sent {
  url: string
  method: string
  body: Record<string, unknown>
  headers: Record<string, string>
}
const sent: Sent[] = []
/** Force the next response to this status (0 = serve normally). */
let failStatus = 0
/** Serve an EMPTY body (what revoke really answers with). */
let emptyBody = false
/** Which token field a redeem answers with. */
let redeemField: 'jwt' | 'token' | 'none' = 'jwt'

const realFetch = globalThis.fetch
const lastTo = (fragment: string): Sent | undefined => [...sent].reverse().find(s => s.url.includes(fragment))

globalThis.fetch = (async (url: string, init?: RequestInit) => {
  const u = String(url)
  sent.push({
    url: u,
    method: String(init?.method ?? 'GET'),
    body: JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>,
    headers: (init?.headers ?? {}) as Record<string, string>,
  })
  if (failStatus) {
    const status = failStatus
    return {ok: false, status, text: async () => `refused with ${status}`} as unknown as Response
  }
  if (emptyBody) {
    return {
      ok: true,
      status: 204,
      // A real empty body: json() rejects, which is what `postJson` would trip on.
      json: () => Promise.reject(new SyntaxError('Unexpected end of JSON input')),
      text: async () => '',
    } as unknown as Response
  }
  const json = (o: unknown): Response => ({ok: true, status: 200, json: async () => o} as unknown as Response)
  if (u.includes('/v1/renewals/redeem')) return json({token: 'fresh.jwt.sig', exp: 1_800, holder: DID})
  if (u.includes('/v1/renewals')) {
    return json({renewal_token: 'renew-me', holder: DID, expires_at: 9_000, scopes: ['read', 'write']})
  }
  if (u.includes('/v1/credentials/redeem')) {
    const base = {exp: 1_700, holder: DID}
    if (redeemField === 'jwt') return json({...base, jwt: 'from.jwt.field'})
    if (redeemField === 'token') return json({...base, token: 'from.token.field'})
    return json(base)
  }
  if (u.includes('/v1/admin/credentials/issue')) return json({redemption_token: 'redeem-me', expires_at: 4_200})
  if (u.includes('/v1/admin/slots/revoke-user')) return json({})
  if (u.includes('/v1/verify-vp-jwt')) return json({token: 'vp.jwt.sig', exp: 2_400, holder: DID})
  if (u.includes('/v1/verify')) return json({token: 'presented.jwt.sig', exp: 2_100, holder: DID})
  return {ok: false, status: 404, text: async () => `no route ${u}`} as unknown as Response
}) as typeof globalThis.fetch

try {
  // ─── renewals ─────────────────────────────────────────────────────────────
  {
    sent.length = 0
    const grant = await createRenewal(`${VERIFIER}/`, {
      dcql_rule: 'any',
      presentation: {vp: 1},
      credentials: ['vc-jwt'],
      slot_ids: [`0x${'cd'.repeat(32)}`],
    })
    // snake_case in, camelCase out: every one of these is a hand-written mapping.
    eq('createRenewal maps renewal_token → renewalToken', grant.renewalToken, 'renew-me')
    eq('createRenewal maps expires_at → expiresAt', grant.expiresAt, 9_000)
    eq('createRenewal returns the holder and scopes', [grant.holder, grant.scopes], [DID, ['read', 'write']])
    const call = lastTo('/v1/renewals')
    eq('createRenewal POSTs to /v1/renewals', [call?.method, call?.url], ['POST', `${VERIFIER}/v1/renewals`])
    ok('a trailing slash on the verifier url is normalised away', !sent.some(s => s.url.includes('//v1')))
    // The body passes through untouched, so the SDK stays agnostic to the credential format.
    eq('the request body is forwarded as given', call?.body, {
      dcql_rule: 'any',
      presentation: {vp: 1},
      credentials: ['vc-jwt'],
      slot_ids: [`0x${'cd'.repeat(32)}`],
    })
  }
  {
    sent.length = 0
    const issued = await redeemRenewalToken(VERIFIER, 'renew-me')
    eq('redeemRenewalToken returns the fresh token', [issued.token, issued.exp, issued.holder], ['fresh.jwt.sig', 1_800, DID])
    eq('redeemRenewalToken sends renewal_token', lastTo('/v1/renewals/redeem')?.body, {renewal_token: 'renew-me'})
  }
  {
    // ⚠ Revoke answers with an EMPTY body. This must succeed anyway — routing it through
    // the shared postJson would make a successful revocation look like a failure, and a
    // caller who retried would be told again that revoking failed.
    sent.length = 0
    emptyBody = true
    let threw = false
    try {
      await revokeRenewal(VERIFIER, 'renew-me')
    } catch {
      threw = true
    }
    ok('revokeRenewal succeeds on an empty 204 body', !threw)
    eq('revokeRenewal sends renewal_token', lastTo('/v1/renewals/revoke')?.body, {renewal_token: 'renew-me'})
    eq('revokeRenewal returns nothing', await revokeRenewal(VERIFIER, 'renew-me'), undefined)
    emptyBody = false
    // But a real failure still has to surface.
    failStatus = 403
    await rejectsWith('revokeRenewal still reports a refusal', /403/, () => revokeRenewal(VERIFIER, 'renew-me'))
    failStatus = 0
  }

  // ─── credential redemption ────────────────────────────────────────────────
  {
    // The verifier has answered with either field name across versions, so both are
    // accepted rather than one being guessed.
    sent.length = 0
    redeemField = 'jwt'
    eq('redeemCredential accepts a `jwt` field', (await redeemCredential(VERIFIER, 'tok', DID)).token, 'from.jwt.field')
    redeemField = 'token'
    eq('redeemCredential accepts a `token` field', (await redeemCredential(VERIFIER, 'tok', DID)).token, 'from.token.field')
    eq('redeemCredential sends both wire fields', lastTo('/v1/credentials/redeem')?.body, {
      redemption_token: 'tok',
      recipient_did: DID,
    })
    // Neither field is a protocol violation, not an empty token to pass along.
    redeemField = 'none'
    await rejectsWith('a response with no token at all is named as such', /no token in response/, () =>
      redeemCredential(VERIFIER, 'tok', DID),
    )
    redeemField = 'jwt'
  }

  // ─── admin endpoints ──────────────────────────────────────────────────────
  {
    sent.length = 0
    const grant = await issueAdminCredential(VERIFIER, 'super-secret', {scopes: ['read']})
    eq('issueAdminCredential maps redemption_token/expires_at', [grant.redemptionToken, grant.expiresAt], ['redeem-me', 4_200])
    const call = lastTo('/v1/admin/credentials/issue')
    // The admin secret goes in a HEADER, never the body.
    eq('the admin secret goes in X-Admin-Secret', call?.headers['X-Admin-Secret'], 'super-secret')
    ok('the admin secret is not in the body', !JSON.stringify(call?.body).includes('super-secret'))
    // Defaults the server expects present.
    eq('slot_ids defaults to an empty array, not absent', call?.body.slot_ids, [])
    eq('ttl_secs defaults to 600', call?.body.ttl_secs, 600)
    sent.length = 0
    await issueAdminCredential(VERIFIER, 's', {scopes: ['a'], slotIds: ['0xabc'], ttlSecs: 60})
    eq('explicit slotIds/ttlSecs are mapped to snake_case', lastTo('issue')?.body, {
      scopes: ['a'],
      slot_ids: ['0xabc'],
      ttl_secs: 60,
    })
    failStatus = 401
    await rejectsWith('a bad admin secret surfaces the status', /401/, () =>
      issueAdminCredential(VERIFIER, 'wrong', {scopes: ['read']}),
    )
    failStatus = 0
  }
  {
    sent.length = 0
    await revokeSlotUser(VERIFIER, 'super-secret', {slotId: `0x${'cd'.repeat(32)}`, did: DID})
    const call = lastTo('/v1/admin/slots/revoke-user')
    eq('revokeSlotUser sends the admin secret as a header', call?.headers['X-Admin-Secret'], 'super-secret')
    // ⚠ rotate defaults to TRUE: without a rotation the revoked holder's JWT stays useful
    // against everything encrypted before now, so the safe value cannot be opt-in.
    eq('rotate defaults to true', call?.body.rotate, true)
    eq('a reason is always sent', call?.body.reason, 'revoked via SDK')
    eq('slot_id and did are snake_case', [call?.body.slot_id, call?.body.did], [`0x${'cd'.repeat(32)}`, DID])
    sent.length = 0
    await revokeSlotUser(VERIFIER, 's', {slotId: '0xabc', did: DID, rotate: false, reason: 'left the team'})
    eq('rotate:false is honoured when stated explicitly', lastTo('revoke-user')?.body.rotate, false)
    eq('an explicit reason is forwarded', lastTo('revoke-user')?.body.reason, 'left the team')

    // ⚠ The verifier blocklists strictly BY DID. A handle would be accepted by the
    // endpoint and revoke nobody, so it is refused here — before any request is made.
    sent.length = 0
    await rejectsWith(
      'a non-DID identifier is refused, explaining that the verifier blocklists by DID',
      /expected a DID \(got "alice.bsky.social"\).*blocklists by DID/s,
      () => revokeSlotUser(VERIFIER, 's', {slotId: '0xabc', did: 'alice.bsky.social'}),
    )
    eq('and nothing was sent', sent.length, 0)

    failStatus = 403
    await rejectsWith('a refused revocation surfaces the status', /403/, () =>
      revokeSlotUser(VERIFIER, 'wrong', {slotId: '0xabc', did: DID}),
    )
    failStatus = 0
  }

  // ─── presentation endpoints ───────────────────────────────────────────────
  {
    sent.length = 0
    const issued = await verifyPresentation(VERIFIER, {dcql_rule: 'any', presentation: {vp: 1}, credentials: ['c']})
    eq('verifyPresentation returns the issued token', [issued.token, issued.exp], ['presented.jwt.sig', 2_100])
    eq('verifyPresentation POSTs the body untouched', lastTo('/v1/verify')?.body, {
      dcql_rule: 'any',
      presentation: {vp: 1},
      credentials: ['c'],
    })

    sent.length = 0
    const vp = await verifyVpJwt(VERIFIER, {dcql_rule: 'any', holder: DID, credentials: ['c'], holder_proof: 'proof'})
    eq('verifyVpJwt returns the issued token', [vp.token, vp.holder], ['vp.jwt.sig', DID])
    ok('verifyVpJwt hits the vp-jwt endpoint', !!lastTo('/v1/verify-vp-jwt'))
    // The holder proof is what stops a stolen credential being replayed, so an empty one
    // is refused locally rather than sent for the verifier to reject.
    sent.length = 0
    await rejectsWith(
      'verifyVpJwt refuses an empty holder_proof, saying what it is for',
      /holder_proof is required to prove control of the holder DID/,
      () => verifyVpJwt(VERIFIER, {dcql_rule: 'any', holder: DID, credentials: ['c'], holder_proof: ''}),
    )
    eq('and no request was made', sent.length, 0)

    failStatus = 422
    await rejectsWith('a rejected presentation surfaces the status', /422/, () =>
      verifyPresentation(VERIFIER, {dcql_rule: 'any', presentation: {}}),
    )
    failStatus = 0
  }
} finally {
  globalThis.fetch = realFetch
}

// ─── client-side JWT inspection (no network, no signature check) ──────────────
{
  const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url')
  const jwt = (claims: unknown): string => `${b64({alg: 'EdDSA', typ: 'JWT'})}.${b64(claims)}.sig`
  const nowSecs = Math.floor(Date.now() / 1000)

  eq('decodeJwtClaims reads the payload', decodeJwtClaims(jwt({sub: DID, exp: 42}))?.sub, DID)
  eq('decodeJwtClaims keeps unknown claims', decodeJwtClaims(jwt({custom: 'x'}))?.custom, 'x')
  // Malformed input returns null rather than throwing — this is used on a UX path where a
  // throw would take out a render.
  eq('a token with the wrong number of parts is null', decodeJwtClaims('a.b'), null)
  eq('an empty string is null', decodeJwtClaims(''), null)
  eq('a non-JSON payload is null, not a throw', decodeJwtClaims('aaa.!!!not-base64!!!.sig'), null)
  eq('a JSON-but-not-object payload still decodes', decodeJwtClaims(`${b64({})}.${b64([1, 2])}.s`) !== null, true)

  eq('jwtExpMs converts seconds to milliseconds', jwtExpMs(jwt({exp: 1_700_000_000})), 1_700_000_000_000)
  eq('jwtExpMs is null when exp is absent', jwtExpMs(jwt({sub: DID})), null)
  eq('jwtExpMs is null when exp is not a number', jwtExpMs(jwt({exp: 'soon'})), null)
  eq('jwtExpMs is null for a malformed token', jwtExpMs('nope'), null)

  ok('a token already past exp is expiring soon', isJwtExpiringSoon(jwt({exp: nowSecs - 10})))
  ok('a token inside the default 30s skew is expiring soon', isJwtExpiringSoon(jwt({exp: nowSecs + 10})))
  ok('a token well beyond the skew is not', !isJwtExpiringSoon(jwt({exp: nowSecs + 3600})))
  // The skew is what makes a refresh land before the node sees an expired token.
  ok('a larger skew brings the deadline forward', isJwtExpiringSoon(jwt({exp: nowSecs + 120}), 300_000))
  ok('a zero skew only counts real expiry', !isJwtExpiringSoon(jwt({exp: nowSecs + 5}), 0))
  // ⚠ FAIL-OPEN, deliberately: a token with no exp is never "expiring soon", so a caller
  // does not refresh forever against a non-expiring token. Pinned because the opposite
  // default would be an infinite refresh loop.
  ok('a token with NO exp is not treated as expiring', !isJwtExpiringSoon(jwt({sub: DID})))
  ok('a malformed token is not treated as expiring', !isJwtExpiringSoon('not-a-jwt'))
}

if (failures.length > 0) {
  console.error(`✗ auth.verifier-client: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ auth.verifier-client: ${passed} checks passed`)
