// IETF SD-JWT VC (`dc+sd-jwt`) as the Hovi profile uses it: issuance with top-level selectively
// disclosable claims, parsing, a `CredentialView` for the DCQL evaluator, and presentation with a
// Key Binding JWT (`typ kb+jwt`, `sd_hash`, `nonce`, `aud`). Mirrors what the verifier checks in
// the reference SD-JWT verifier: the issuer's `kid` resolves to the DID
// that `iss` names, `cnf.kid` is a `did:jwk`, `sd_hash` = base64url(sha256(issuer~disclosures~)).
//
// Scope: top-level `_sd` only (no nested `_sd`, no `...` array decoys) — the shapes the health
// app issues and the platform evaluates. `claims[].path` in a rule addresses these top-level names.

import {sha256} from '@noble/hashes/sha256'
import {jsonCredential, FORMAT_DC_SD_JWT, type CredentialView} from '../auth/oid4vp.js'
import {b64url, b64urlDecode, decodeJson, didJwk, holderSigner, jwkFromDid, p256DidKey, p256PublicJwk, signCompactJws, utf8, verifyCompactJws, type HolderKey, type JwsAlg, type JwsSigner, type Jwk} from './jose.js'

export const SD_JWT_TYP = 'dc+sd-jwt'
export const KB_JWT_TYP = 'kb+jwt'

export interface Disclosure {
  /** base64url(JSON([salt, name, value])) — what travels on the wire. */
  encoded: string
  salt: string
  name: string
  value: unknown
  /** base64url(sha256(encoded)) — what the issuer JWT's `_sd` array holds. */
  digest: string
}

export interface ParsedSdJwt {
  compact: string
  /** The issuer-signed JWT (first `~`-segment). */
  issuerJwt: string
  header: Record<string, unknown>
  payload: Record<string, unknown>
  disclosures: Disclosure[]
  /** The Key Binding JWT, when the compact carries one (a presentation). */
  kbJwt?: string
}

export function disclosureDigest(encoded: string): string {
  return b64url(sha256(utf8(encoded)))
}
function decodeDisclosure(encoded: string): Disclosure {
  const arr = decodeJson<unknown[]>(encoded)
  if (!Array.isArray(arr) || arr.length !== 3 || typeof arr[0] !== 'string' || typeof arr[1] !== 'string') {
    throw new Error('SD-JWT disclosure is not [salt, name, value]')
  }
  return {encoded, salt: arr[0], name: arr[1], value: arr[2], digest: disclosureDigest(encoded)}
}

/** Split a compact SD-JWT (`issuer~d1~…~[kb]`) into its parts, checking every disclosure against `_sd`. */
export function parseSdJwt(compact: string): ParsedSdJwt {
  const parts = compact.split('~')
  const issuerJwt = parts[0]
  if (!issuerJwt || issuerJwt.split('.').length !== 3) throw new Error('SD-JWT: first segment is not a compact JWS')
  const [h, p] = issuerJwt.split('.')
  const header = decodeJson<Record<string, unknown>>(h!)
  const payload = decodeJson<Record<string, unknown>>(p!)
  const trailing = compact.endsWith('~')
  const middle = trailing ? parts.slice(1, -1) : parts.slice(1, -1)
  const kbJwt = trailing ? undefined : parts[parts.length - 1]
  if (kbJwt !== undefined && kbJwt.split('.').length !== 3) throw new Error('SD-JWT: trailing segment is neither empty nor a KB-JWT')
  const sd = new Set<string>(Array.isArray(payload._sd) ? (payload._sd as string[]) : [])
  const disclosures = middle.filter(d => d !== '').map(decodeDisclosure)
  for (const d of disclosures) {
    if (!sd.has(d.digest)) throw new Error(`SD-JWT: disclosure ${JSON.stringify(d.name)} is not in the issuer's _sd`)
  }
  return {compact, issuerJwt, header, payload, disclosures, kbJwt}
}

/** The credential's claims as the verifier sees them: plain payload claims + disclosed ones. */
export function sdJwtClaims(parsed: ParsedSdJwt): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(parsed.payload)) {
    if (k === '_sd' || k === '_sd_alg') continue
    out[k] = v
  }
  for (const d of parsed.disclosures) out[d.name] = d.value
  return out
}

/** A {@link CredentialView} for the DCQL evaluator: format `dc+sd-jwt`, `types` = [`vct`]. */
export function sdJwtCredentialView(parsed: ParsedSdJwt): CredentialView {
  const claims = sdJwtClaims(parsed)
  const vct = typeof claims.vct === 'string' ? [claims.vct] : []
  return jsonCredential({format: FORMAT_DC_SD_JWT, types: vct, body: claims})
}

/** `base64url(sha256(prefix))` where `prefix` is everything before the KB-JWT, trailing `~` included. */
export function sdHash(prefix: string): string {
  return b64url(sha256(utf8(prefix)))
}

// ─── issuance ───────────────────────────────────────────────────────────────────────────

export interface SdJwtIssuer {
  /** The issuer DID the credential's `iss` names; `kid` = `${did}#${fragment}` unless given. */
  did: string
  kid?: string
  signer: JwsSigner
}
export interface IssueSdJwtVcOpts {
  issuer: SdJwtIssuer
  vct: string
  /** Every claim goes into a disclosure unless named in `plain` (which then travels in the clear). */
  claims: Record<string, unknown>
  plain?: string[]
  /** The holder's key binding: `{kid: did:jwk…#0}` (Hovi's shape) or `{jwk}`. */
  cnf: {kid: string} | {jwk: Jwk}
  /** Subject DID, when the credential names one (`sub`); the verifier derives the holder from it first. */
  sub?: string
  nowSecs?: number
  ttlSecs?: number
  /** Extra header members (e.g. a `typ` override); `alg` and `kid` are set here. */
  header?: Record<string, unknown>
  random?: () => Uint8Array
}

/** Mint a compact SD-JWT VC `issuer~d1~…~` with one disclosure per selectively disclosable claim. */
export function issueSdJwtVc(opts: IssueSdJwtVcOpts): string {
  const now = opts.nowSecs ?? Math.floor(Date.now() / 1000)
  const random = opts.random ?? (() => crypto.getRandomValues(new Uint8Array(16)))
  const plain = new Set(opts.plain ?? [])
  const disclosures: Disclosure[] = []
  const clear: Record<string, unknown> = {}
  for (const [name, value] of Object.entries(opts.claims)) {
    if (plain.has(name)) {
      clear[name] = value
      continue
    }
    const encoded = b64url(JSON.stringify([b64url(random()), name, value]))
    disclosures.push({encoded, salt: '', name, value, digest: disclosureDigest(encoded)})
  }
  const payload: Record<string, unknown> = {
    iss: opts.issuer.did,
    iat: now,
    exp: now + (opts.ttlSecs ?? 365 * 86400),
    vct: opts.vct,
    cnf: opts.cnf,
    ...(opts.sub !== undefined ? {sub: opts.sub} : {}),
    ...clear,
    _sd_alg: 'sha-256',
    _sd: disclosures.map(d => d.digest).sort(),
  }
  const kid = opts.issuer.kid ?? `${opts.issuer.did}#${opts.issuer.did.split(':').pop()}`
  const jwt = signCompactJws({typ: SD_JWT_TYP, kid, ...(opts.header ?? {})}, payload, opts.issuer.signer)
  return `${jwt}~${disclosures.map(d => d.encoded).join('~')}${disclosures.length ? '~' : ''}`
}

/** The `cnf` a holder key binds to: `{kid: "<did:jwk>#0"}`, exactly as the Hovi wallet presents. */
export function holderCnf(holder: Pick<HolderKey, 'did'>): {kid: string} {
  return {kid: `${holder.did}#0`}
}

/** A P-256 issuer as `did:key` (Hovi Studio's issuer shape) from a private scalar. */
export function p256DidKeyIssuer(privateKey: Uint8Array, opts: {fragmentKid?: boolean} = {}): SdJwtIssuer {
  const pub = p256PublicJwk(privateKey)
  const raw = new Uint8Array([0x04, ...b64urlDecode(pub.x), ...b64urlDecode(pub.y)])
  const did = p256DidKey(raw)
  const fragment = did.slice('did:key:'.length)
  return {did, kid: opts.fragmentKid ? `#${fragment}` : `${did}#${fragment}`, signer: {alg: 'ES256', privateKey}}
}

/** A `did:jwk` issuer (any key the app already holds, e.g. a patient's vault key granting a consent). */
export function didJwkIssuer(privateKey: Uint8Array, alg: JwsAlg = 'ES256'): SdJwtIssuer {
  if (alg !== 'ES256') throw new Error('didJwkIssuer: only P-256 / ES256 is supported')
  const did = didJwk(p256PublicJwk(privateKey))
  return {did, kid: `${did}#0`, signer: {alg, privateKey}}
}

// ─── presentation (holder side) ─────────────────────────────────────────────────────────

export interface PresentSdJwtOpts {
  parsed: ParsedSdJwt
  /** Which disclosures to reveal: claim names, or `'all'`. Undisclosed claims stay hidden. */
  disclose: 'all' | readonly string[]
  holder: HolderKey
  /** The JAR's `nonce`. */
  nonce: string
  /** The JAR's `client_id`, VERBATIM (prefix included). */
  aud: string
  nowSecs?: number
  /** Extra KB-JWT claims (e.g. `transaction_data_hashes`). */
  extraKbClaims?: Record<string, unknown>
}

/** Build the presentation `issuer~selected…~kb-jwt`, the KB-JWT signed by the holder's own key. */
export function presentSdJwt(opts: PresentSdJwtOpts): string {
  const want = opts.disclose === 'all' ? null : new Set(opts.disclose)
  const selected = opts.parsed.disclosures.filter(d => want === null || want.has(d.name))
  const prefix = `${opts.parsed.issuerJwt}~${selected.map(d => d.encoded).join('~')}${selected.length ? '~' : ''}`
  const kb = signCompactJws(
    {typ: KB_JWT_TYP},
    {
      nonce: opts.nonce,
      aud: opts.aud,
      iat: opts.nowSecs ?? Math.floor(Date.now() / 1000),
      sd_hash: sdHash(prefix),
      ...(opts.extraKbClaims ?? {}),
    },
    holderSigner(opts.holder),
  )
  return `${prefix}${kb}`
}

/** What the verifier checks of a presentation's KB-JWT, mirrored for tests and wallet self-checks. */
export function verifyKbJwt(presentation: string, expected: {nonce: string; aud: string}): {holderJwk: Jwk; claims: Record<string, unknown>} {
  const parsed = parseSdJwt(presentation)
  if (!parsed.kbJwt) throw new Error('presentation carries no KB-JWT')
  const cnf = parsed.payload.cnf as {kid?: string; jwk?: Jwk} | undefined
  if (!cnf) throw new Error('issuer JWT has no cnf claim')
  if (!cnf.jwk && !cnf.kid) throw new Error('cnf has neither jwk nor kid')
  const holderJwk: Jwk = cnf.jwk ?? jwkFromDid(cnf.kid!)
  const {header, payload} = verifyCompactJws<Record<string, unknown>>(parsed.kbJwt, holderJwk)
  if (header.typ !== KB_JWT_TYP) throw new Error(`KB-JWT typ must be ${KB_JWT_TYP}`)
  if (payload.nonce !== expected.nonce) throw new Error('KB-JWT nonce mismatch')
  const aud = payload.aud
  const audOk = typeof aud === 'string' ? aud === expected.aud : Array.isArray(aud) && aud.includes(expected.aud)
  if (!audOk) throw new Error('KB-JWT aud mismatch')
  const prefix = presentation.slice(0, presentation.length - parsed.kbJwt.length)
  if (payload.sd_hash !== sdHash(prefix)) throw new Error('KB-JWT sd_hash mismatch')
  return {holderJwk, claims: payload}
}

/** Decode (no verification) the issuer JWT's payload of a compact SD-JWT — for display. */
export function peekSdJwt(compact: string): {iss?: string; vct?: string; exp?: number; sub?: string} {
  const p = parseSdJwt(compact).payload
  return {iss: p.iss as string | undefined, vct: p.vct as string | undefined, exp: p.exp as number | undefined, sub: p.sub as string | undefined}
}

