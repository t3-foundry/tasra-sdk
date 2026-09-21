// The wallet half, cloned from what the Hovi Wallet does against the Verifier Agent: fetch and verify
// the JAR, pick ONE held SD-JWT VC that answers the `dcql_query` (one credential per presentation —
// `credential_sets` with single-credential options are the only multi-query shape a Hovi user can
// satisfy), disclose exactly the claims the chosen query asks for, bind with a KB-JWT to the JAR's
// nonce and `client_id`, encrypt the JARM payload to the verifier-agent's ephemeral key, POST it.
//
// Runs in a browser extension's service worker (Tasra Vault), a PWA and Node alike — the holder
// key is a P-256 scalar the caller keeps.

import {select, credentialMatches, validate, type CredentialView, type Query} from '../auth/oid4vp.js'
import {encryptJwe, type JweEnc} from './jwe.js'
import type {HolderKey} from './jose.js'
import {fetchRequestObject, parseOpenid4vpUri, responseEncryptionKey, type VerifiedRequestObject, type VerifyRequestObjectOpts} from './request-object.js'
import {parseSdJwt, presentSdJwt, sdJwtCredentialView, type ParsedSdJwt} from './sd-jwt.js'

/** A credential the wallet holds. */
export interface HeldSdJwt {
  sdJwt: string
  /** For the consent screen. */
  label?: string
}

export interface PresentationCandidate {
  held: HeldSdJwt
  parsed: ParsedSdJwt
  view: CredentialView
  /** The credential query id this credential answers. */
  queryId: string
}

export interface PresentationPlan {
  /** Whether the local (advisory) selection found a credential that satisfies the request. */
  satisfies: boolean
  /** Every held credential that answers some query — the choice to offer the user. */
  candidates: PresentationCandidate[]
  /** The default choice (the evaluator's pick), when satisfied. */
  chosen?: PresentationCandidate
  /** Query ids nothing in the wallet answers. */
  unmatched: string[]
}

/**
 * Match held SD-JWT VCs against the request's `dcql_query`. Expired credentials are skipped.
 * Advisory: the drawn verifiers decide; a wrong local answer costs a wasted request, never access.
 */
export function planPresentation(ro: Pick<VerifiedRequestObject, 'claims'>, held: readonly HeldSdJwt[], nowSecs = Math.floor(Date.now() / 1000)): PresentationPlan {
  // A wallet reads the rule as dispatched; the issuer-entry mandate is the platform's.
  const query = validate(JSON.stringify(ro.claims.dcql_query), {requireIssuer: false})
  const live = held.flatMap(h => {
    try {
      const parsed = parseSdJwt(h.sdJwt)
      const exp = parsed.payload.exp
      if (typeof exp === 'number' && exp <= nowSecs) return []
      return [{held: h, parsed, view: sdJwtCredentialView(parsed)}]
    } catch {
      return []
    }
  })
  const candidates: PresentationCandidate[] = []
  for (const q of query.credentials) {
    for (const c of live) {
      if (credentialMatches(q, c.view)) candidates.push({...c, queryId: q.id})
    }
  }
  const sel = select(JSON.stringify(ro.claims.dcql_query), live.map(c => c.view), {requireIssuer: false})
  const chosenView = sel.credentials[0]
  const chosen = chosenView ? candidates.find(c => c.view === chosenView) : undefined
  return {satisfies: sel.satisfied && sel.credentials.length === 1 && chosen !== undefined, candidates, chosen, unmatched: sel.unsatisfied}
}

/** The top-level claim names a credential query asks to see. */
export function requestedClaimNames(query: Query, queryId: string): string[] {
  const q = query.credentials.find(c => c.id === queryId)
  return [...new Set((q?.claims ?? []).map(c => c.path[0]).filter((n): n is string => typeof n === 'string'))]
}

export interface BuildResponseOpts {
  ro: Pick<VerifiedRequestObject, 'claims'>
  candidate: PresentationCandidate
  holder: HolderKey
  /** Override which disclosures to reveal (default: exactly the claims the query names). */
  disclose?: 'all' | readonly string[]
  nowSecs?: number
  /** Preferred content encryption when the verifier-agent lists several (default A256GCM). */
  enc?: JweEnc
}

export interface BuiltResponse {
  /** The presentation `issuer~disclosures~kb-jwt` that went into `vp_token`. */
  presentation: string
  /** The JARM payload `{vp_token: {<queryId>: [presentation]}, state}` as JSON. */
  payload: string
  /** The form body to POST: `response=<JWE>` when the verifier-agent served an encryption key, else the plain fields. */
  form: Record<string, string>
  encrypted: boolean
}

/** Bind the chosen credential to the request (KB-JWT) and wrap it as the verifier-agent expects it. */
export function buildResponse(opts: BuildResponseOpts): BuiltResponse {
  const claims = opts.ro.claims
  const disclose = opts.disclose ?? requestedClaimNames(validate(JSON.stringify(claims.dcql_query), {requireIssuer: false}), opts.candidate.queryId)
  const presentation = presentSdJwt({parsed: opts.candidate.parsed, disclose, holder: opts.holder, nonce: claims.nonce, aud: claims.client_id, nowSecs: opts.nowSecs})
  const payloadObj = {vp_token: {[opts.candidate.queryId]: [presentation]}, state: claims.state}
  const payload = JSON.stringify(payloadObj)
  const key = responseEncryptionKey(opts.ro)
  if (key) {
    const offered = claims.client_metadata?.encrypted_response_enc_values_supported
    const enc: JweEnc = opts.enc ?? (offered && !offered.includes('A256GCM') && offered.includes('A128GCM') ? 'A128GCM' : 'A256GCM')
    return {presentation, payload, form: {response: encryptJwe(payload, key, enc)}, encrypted: true}
  }
  return {presentation, payload, form: {vp_token: JSON.stringify(payloadObj.vp_token), state: claims.state}, encrypted: false}
}

/** POST the built response to `response_uri`; returns the verifier-agent's `redirect_uri` when it gives one. */
export async function submitResponse(ro: Pick<VerifiedRequestObject, 'claims'>, built: Pick<BuiltResponse, 'form'>, fetchImpl: typeof fetch = fetch): Promise<{redirectUri?: string}> {
  const res = await fetchImpl(ro.claims.response_uri, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams(built.form).toString(),
  })
  if (!res.ok) throw new Error(`response_uri → HTTP ${res.status}: ${(await res.text().catch(() => '')).slice(0, 200)}`)
  const body = (await res.json().catch(() => ({}))) as {redirect_uri?: string}
  return {redirectUri: body.redirect_uri}
}

export interface PresentOpts extends VerifyRequestObjectOpts {
  fetchImpl?: typeof fetch
  /** Pick among the candidates (default: the evaluator's choice). Return `undefined` to abort. */
  choose?: (plan: PresentationPlan) => PresentationCandidate | undefined | Promise<PresentationCandidate | undefined>
  disclose?: 'all' | readonly string[]
}

/**
 * The whole wallet flow for one QR / deep link: fetch + verify the JAR, plan, let the caller
 * choose (consent screen), bind, encrypt, POST.
 */
export async function presentToRequestUri(requestUriOrOpenid4vp: string, held: readonly HeldSdJwt[], holder: HolderKey, opts: PresentOpts = {}): Promise<{ro: VerifiedRequestObject; plan: PresentationPlan; built: BuiltResponse; redirectUri?: string}> {
  const requestUri = requestUriOrOpenid4vp.startsWith('openid4vp://') ? parseOpenid4vpUri(requestUriOrOpenid4vp).requestUri : requestUriOrOpenid4vp
  const ro = await fetchRequestObject(requestUri, opts)
  const plan = planPresentation(ro, held, opts.nowSecs)
  const candidate = opts.choose ? await opts.choose(plan) : plan.chosen
  if (!candidate) throw new Error(plan.unmatched.length ? `no held credential answers: ${plan.unmatched.join(', ')}` : 'presentation declined')
  const built = buildResponse({ro, candidate, holder, disclose: opts.disclose, nowSecs: opts.nowSecs})
  const {redirectUri} = await submitResponse(ro, built, opts.fetchImpl)
  return {ro, plan, built, redirectUri}
}
