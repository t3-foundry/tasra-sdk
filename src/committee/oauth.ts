// The two strings an OAuth+DPoP authorization is bound to, DERIVED.
//
// Mirrors the reference OAuth derivations exactly, including its normalisation, because
// three independent parties have to agree on these byte for byte: the tenant (which
// registers the audience with its IdP), the client (which mints a DPoP proof over the `htu`)
// and every drawn verifier (which checks both). Only one of the three has a config file we
// control, so neither string is ever configured anywhere.
//
// ⚠ The agent RETURNS both values from `createOauthSession`, so a client normally never
// calls these. They exist for the step that happens BEFORE any session: telling a tenant
// which `aud` to register with their IdP.

/** Path segment identifying the platform's authorization API, under the agent origin. */
const AUDIENCE_PATH = 'authz'

/** The path an OAuth response is POSTed to — the `htu` a DPoP proof must name. */
export const OAUTH_RESPONSE_PATH = '/v1/sessions/oauth-response'

/**
 * Normalise an origin the way the reference endpoint normaliser
 * does: trim, drop a trailing slash, lower-case the scheme and authority, keep the path as
 * written.
 *
 * ⚠ The PATH keeps its case deliberately — a path is case-sensitive, and lower-casing it
 * would silently rewrite an agent deployed under `/API`.
 */
export function normalizeOrigin(url: string): string {
  const trimmed = url.trim().replace(/\/+$/, '')
  const i = trimmed.indexOf('://')
  if (i < 0) return trimmed
  const scheme = trimmed.slice(0, i)
  const rest = trimmed.slice(i + 3)
  const slash = rest.indexOf('/')
  const authority = slash < 0 ? rest : rest.slice(0, slash)
  const path = slash < 0 ? '' : rest.slice(slash)
  return `${scheme.toLowerCase()}://${authority.toLowerCase()}${path}`
}

/**
 * The OAuth audience the tenant registers with its IdP and every rule pins:
 * `{origin}/authz/{chainId}`.
 *
 * The chain id is in it so a token minted for a testnet deployment of the same platform
 * cannot authorize on mainnet.
 */
export function platformAudience(origin: string, chainId: number | bigint): string {
  return `${normalizeOrigin(origin)}/${AUDIENCE_PATH}/${chainId.toString()}`
}

/**
 * The `htu` (RFC 9449 §4.2) a DPoP proof for an OAuth response must carry:
 * `{origin}/v1/sessions/oauth-response`.
 *
 * Session-INDEPENDENT, deliberately: RFC 9449 defines `htu` as the request URI WITHOUT query
 * or fragment, and a client library that derives it from the URL it is about to call — which
 * every conformant one does — produces this string, not one carrying a session id. The
 * session is already bound by the `nonce`.
 */
export function dpopHtu(origin: string): string {
  return `${normalizeOrigin(origin)}${OAUTH_RESPONSE_PATH}`
}
