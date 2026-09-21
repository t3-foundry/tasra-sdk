// The signed Request Object (JAR) the Verifier Agent serves at `request_uri`, verified the way a
// standards wallet verifies it: `iss` is the platform's `did:web`, the JWS `kid` names one of that
// document's verification methods, `client_id` is the DID under the `decentralized_identifier:`
// prefix, `typ` is `oauth-authz-req+jwt`. Nothing here is Tasra-specific; the committee
// binding rides in the `nonce`, which the wallet copies into its KB-JWT without interpreting it.

import {resolveDidWeb, verificationKey, type ResolveOpts} from './did-web.js'
import {decodeJson, jwkFromDid, verifyCompactJws, type EcJwk, type Jwk} from './jose.js'
import type {Query as DcqlQuery} from '../auth/oid4vp.js'

export const REQUEST_OBJECT_TYP = 'oauth-authz-req+jwt'
export const CLIENT_ID_PREFIX_DID = 'decentralized_identifier:'

export interface RequestObjectClaims {
  iss: string
  client_id: string
  response_type?: string
  /** `direct_post.jwt` (the verifier-agent always) or `direct_post`. */
  response_mode?: string
  response_uri: string
  nonce: string
  state: string
  iat?: number
  exp?: number
  dcql_query: DcqlQuery
  client_metadata?: {
    jwks?: {keys: Jwk[]}
    vp_formats_supported?: Record<string, unknown>
    encrypted_response_enc_values_supported?: string[]
    [k: string]: unknown
  }
  transaction_data?: string[]
  [k: string]: unknown
}

export interface VerifiedRequestObject {
  jwt: string
  header: {alg: string; typ?: string; kid?: string}
  claims: RequestObjectClaims
  /** The DID `iss` names, after the `client_id` prefix agreed with it. */
  signerDid: string
  signerKey: Jwk
}

/** `openid4vp://?client_id=…&request_uri=…` (a QR payload or deep link) → its two parameters. */
export function parseOpenid4vpUri(uri: string): {clientId?: string; requestUri: string} {
  const q = uri.includes('?') ? uri.slice(uri.indexOf('?') + 1) : ''
  const params = new URLSearchParams(q)
  const requestUri = params.get('request_uri')
  if (!requestUri) throw new Error('openid4vp URI carries no request_uri')
  return {clientId: params.get('client_id') ?? undefined, requestUri}
}

/** Resolve the signing key a JAR's `kid` names: `did:web` documents online, `did:key`/`did:jwk` offline. */
export type KeyResolver = (did: string, kid: string | undefined) => Promise<Jwk>

export function defaultKeyResolver(opts: ResolveOpts = {}): KeyResolver {
  return async (did, kid) => {
    if (did.startsWith('did:web:')) {
      const doc = await resolveDidWeb(did, opts)
      return verificationKey(doc, kid ?? `${did}#`)
    }
    return jwkFromDid(did)
  }
}

export interface VerifyRequestObjectOpts {
  resolveKey?: KeyResolver
  nowSecs?: number
  /** Seconds of clock skew tolerated on `exp`. */
  leewaySecs?: number
}

/** Verify a JAR: signature under the key its `kid` names in the `iss` DID, `typ`, `exp`, `client_id` ↔ `iss`. */
export async function verifyRequestObject(jwt: string, opts: VerifyRequestObjectOpts = {}): Promise<VerifiedRequestObject> {
  const [h, p, s] = jwt.split('.')
  if (!h || !p || !s) throw new Error('request object is not a compact JWS')
  const header = decodeJson<VerifiedRequestObject['header']>(h)
  if (header.typ !== REQUEST_OBJECT_TYP) throw new Error(`request object typ must be ${REQUEST_OBJECT_TYP}`)
  const claims = decodeJson<RequestObjectClaims>(p)
  if (typeof claims.iss !== 'string' || !claims.iss.startsWith('did:')) throw new Error('request object iss is not a DID')
  const bareClientId = claims.client_id.startsWith(CLIENT_ID_PREFIX_DID) ? claims.client_id.slice(CLIENT_ID_PREFIX_DID.length) : claims.client_id
  if (bareClientId !== claims.iss) throw new Error('request object client_id does not name its iss')
  if (header.kid && !header.kid.startsWith(claims.iss)) throw new Error('request object kid belongs to a different DID than iss')
  const signerKey = await (opts.resolveKey ?? defaultKeyResolver())(claims.iss, header.kid)
  verifyCompactJws(jwt, signerKey)
  const now = opts.nowSecs ?? Math.floor(Date.now() / 1000)
  if (typeof claims.exp === 'number' && claims.exp + (opts.leewaySecs ?? 60) < now) throw new Error('request object expired')
  if (typeof claims.nonce !== 'string' || !claims.nonce) throw new Error('request object has no nonce')
  if (typeof claims.response_uri !== 'string') throw new Error('request object has no response_uri')
  if (!claims.dcql_query) throw new Error('request object has no dcql_query')
  return {jwt, header, claims, signerDid: claims.iss, signerKey}
}

/** The ephemeral P-256 key the wallet must encrypt its response to, when the verifier-agent served one. */
export function responseEncryptionKey(ro: Pick<VerifiedRequestObject, 'claims'>): EcJwk | undefined {
  const k = ro.claims.client_metadata?.jwks?.keys?.[0]
  return k && k.kty === 'EC' && k.crv === 'P-256' ? k : undefined
}

/** Fetch a JAR from `request_uri` (`Accept: application/oauth-authz-req+jwt`) and verify it. */
export async function fetchRequestObject(requestUri: string, opts: VerifyRequestObjectOpts & {fetchImpl?: typeof fetch} = {}): Promise<VerifiedRequestObject> {
  const f = opts.fetchImpl ?? fetch
  const res = await f(requestUri, {headers: {Accept: `application/${REQUEST_OBJECT_TYP}`}})
  if (!res.ok) throw new Error(`request_uri ${requestUri} → HTTP ${res.status}: ${(await res.text().catch(() => '')).slice(0, 200)}`)
  return verifyRequestObject((await res.text()).trim(), opts)
}
