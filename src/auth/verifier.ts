// Agnostic verifier-auth + JWT helpers.
//
// Pure HTTP/JSON against the keykeeper verifier and pure client-side JWT
// inspection. NOTHING here knows about any specific transport or product —
// a consumer brings a verifier URL and the relevant
// token(s). These cover the "(obtain, refresh) a DCQL-gated JWT" lifecycle that
// every product on top of a Tasra Network needs.

import {httpError} from '../errors.js'

export interface IssuedToken {
  /** The signed JWT (EdDSA) to present to keykeeper-nodes as a Bearer token. */
  token: string
  /** Expiry, Unix seconds. */
  exp: number
  /** Subject / holder the token was minted for. */
  holder: string
}

function base(url: string): string {
  return url.replace(/\/$/, '')
}

async function postJson(url: string, body: unknown): Promise<unknown> {
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  })
  if (!res.ok) throw await httpError(res, url, `POST ${url}`)
  return res.json()
}

export interface RenewalGrant {
  /** Long-lived token to exchange for fresh JWTs via redeemRenewalToken(). */
  renewalToken: string
  holder: string
  /** Expiry, Unix seconds. */
  expiresAt: number
  scopes: string[]
}

/**
 * Create a long-lived renewal from a presentation. On the prod (signed) path,
 * pass `credentials` (compact JWS JWT-VCs) — they're signature-verified and
 * replace the presentation's credentials. `slot_ids` (if given) are rotated via
 * a webhook when the renewal is revoked.
 * POST {verifier}/v1/renewals
 */
export async function createRenewal(
  verifierUrl: string,
  body: {dcql_rule: string; presentation: unknown; credentials?: string[]; slot_ids?: string[]},
): Promise<RenewalGrant> {
  const b = (await postJson(`${base(verifierUrl)}/v1/renewals`, body)) as {
    renewal_token: string
    holder: string
    expires_at: number
    scopes: string[]
  }
  return {renewalToken: b.renewal_token, holder: b.holder, expiresAt: b.expires_at, scopes: b.scopes}
}

/**
 * Revoke a renewal token — future redeems are denied, and any bound slots get a
 * rotation webhook. POST {verifier}/v1/renewals/revoke  {renewal_token}
 */
export async function revokeRenewal(verifierUrl: string, renewalToken: string): Promise<void> {
  // revoke returns 200/204 with an EMPTY body — don't JSON-parse the response.
  const url = `${base(verifierUrl)}/v1/renewals/revoke`
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({renewal_token: renewalToken}),
  })
  if (!res.ok) throw await httpError(res, url, 'renewals/revoke')
}

/**
 * Redeem a long-lived renewal token for a fresh JWT.
 * POST {verifier}/v1/renewals/redeem  {renewal_token}
 */
export async function redeemRenewalToken(
  verifierUrl: string,
  renewalToken: string,
): Promise<IssuedToken> {
  const b = (await postJson(`${base(verifierUrl)}/v1/renewals/redeem`, {
    renewal_token: renewalToken,
  })) as {token: string; exp: number; holder: string}
  return {token: b.token, exp: b.exp, holder: b.holder}
}

/**
 * Redeem an admin-issued, single-use credential/invite token for a JWT.
 * POST {verifier}/v1/credentials/redeem  {redemption_token, recipient_did}
 */
export async function redeemCredential(
  verifierUrl: string,
  redemptionToken: string,
  recipientDid: string,
): Promise<IssuedToken> {
  const b = (await postJson(`${base(verifierUrl)}/v1/credentials/redeem`, {
    redemption_token: redemptionToken,
    recipient_did: recipientDid,
  })) as {jwt?: string; token?: string; exp: number; holder: string}
  const token = b.jwt ?? b.token
  if (!token) throw new Error('credentials/redeem: no token in response')
  return {token, exp: b.exp, holder: b.holder}
}

export interface RedemptionGrant {
  /** Single-use token to exchange for a JWT via redeemCredential(). */
  redemptionToken: string
  /** Expiry of the redemption token, Unix seconds. */
  expiresAt: number
}

/**
 * Admin-mint a single-use credential (redemption token) for the given scopes.
 * Requires the verifier's admin secret. Pair with redeemCredential() to get a
 * JWT whose `sub` is the recipient DID you pass there.
 * POST {verifier}/v1/admin/credentials/issue  (header: X-Admin-Secret)
 */
export async function issueAdminCredential(
  verifierUrl: string,
  adminSecret: string,
  opts: {scopes: string[]; slotIds?: string[]; ttlSecs?: number},
): Promise<RedemptionGrant> {
  const url = `${base(verifierUrl)}/v1/admin/credentials/issue`
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Admin-Secret': adminSecret},
    body: JSON.stringify({
      scopes: opts.scopes,
      slot_ids: opts.slotIds ?? [],
      ttl_secs: opts.ttlSecs ?? 600,
    }),
  })
  if (!res.ok) throw await httpError(res, url, 'admin/credentials/issue')
  const b = (await res.json()) as {redemption_token: string; expires_at: number}
  return {redemptionToken: b.redemption_token, expiresAt: b.expires_at}
}

/**
 * Admin: revoke a holder's (DID's) access to a slot and, by default, rotate the
 * slot — re-keying it so any JWT the revoked holder still holds is
 * cryptographically useless for anything encrypted after the rotation. The
 * verifier blocklists the DID and fires a rotation webhook to the nodes.
 * Requires the verifier's admin secret. Resolve handle→DID upstream; the
 * verifier blocklists strictly by DID.
 * POST {verifier}/v1/admin/slots/revoke-user  (header: X-Admin-Secret)
 */
export async function revokeSlotUser(
  verifierUrl: string,
  adminSecret: string,
  opts: {slotId: string; did: string; rotate?: boolean; reason?: string},
): Promise<void> {
  if (!opts.did.startsWith('did:')) {
    throw new Error(`revokeSlotUser: expected a DID (got "${opts.did}") — the verifier blocklists by DID`)
  }
  const url = `${base(verifierUrl)}/v1/admin/slots/revoke-user`
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Admin-Secret': adminSecret},
    body: JSON.stringify({
      slot_id: opts.slotId,
      did: opts.did,
      rotate: opts.rotate ?? true,
      reason: opts.reason ?? 'revoked via SDK',
    }),
  })
  if (!res.ok) throw await httpError(res, url, 'admin/slots/revoke-user')
}

/**
 * Present credentials directly for a JWT. The `body` shape is defined by the
 * verifier (a DCQL rule + a presentation/credentials); we pass it through
 * untouched so this stays agnostic to the credential format.
 * POST {verifier}/v1/verify
 */
export async function verifyPresentation(
  verifierUrl: string,
  body: {dcql_rule: string; presentation: unknown; credentials?: unknown},
): Promise<IssuedToken> {
  const b = (await postJson(`${base(verifierUrl)}/v1/verify`, body)) as {
    token: string
    exp: number
    holder: string
  }
  return {token: b.token, exp: b.exp, holder: b.holder}
}

/**
 * The PRODUCTION credential path: present signed JWT-VCs + holder proof for a
 * DCQL-gated JWT. The verifier checks each credential's signature against its
 * configured trust anchor (by `iss`), that each `sub` equals `holder`, that
 * `holder_proof` proves live control of the holder DID authentication key, then
 * evaluates the rule. `credentials` are compact JWS strings (e.g. from
 * `tasra-cli vc issue`).
 * POST {verifier}/v1/verify-vp-jwt
 */
export async function verifyVpJwt(
  verifierUrl: string,
  body: {dcql_rule: string; holder: string; credentials: string[]; holder_proof: string},
): Promise<IssuedToken> {
  if (!body.holder_proof) {
    throw new Error('verifyVpJwt: holder_proof is required to prove control of the holder DID')
  }
  const b = (await postJson(`${base(verifierUrl)}/v1/verify-vp-jwt`, body)) as {
    token: string
    exp: number
    holder: string
  }
  return {token: b.token, exp: b.exp, holder: b.holder}
}

// ─── client-side JWT inspection (no signature verification) ──────────────────

export interface JwtClaims {
  sub?: string
  iss?: string
  aud?: string
  exp?: number
  iat?: number
  scope?: string | string[]
  [k: string]: unknown
}

function b64urlDecode(s: string): string {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  return atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad)
}

/** Decode JWT claims WITHOUT verifying the signature (for expiry/UX only). */
export function decodeJwtClaims(jwt: string): JwtClaims | null {
  const parts = jwt.split('.')
  if (parts.length !== 3) return null
  try {
    return JSON.parse(b64urlDecode(parts[1]!)) as JwtClaims
  } catch {
    return null
  }
}

/** Expiry as epoch-ms, or null if absent/unparseable. */
export function jwtExpMs(jwt: string): number | null {
  const exp = decodeJwtClaims(jwt)?.exp
  return typeof exp === 'number' ? exp * 1000 : null
}

/** True when the token is expired or within `skewMs` of expiring. */
export function isJwtExpiringSoon(jwt: string, skewMs = 30_000): boolean {
  const exp = jwtExpMs(jwt)
  if (exp === null) return false
  return Date.now() + skewMs >= exp
}
