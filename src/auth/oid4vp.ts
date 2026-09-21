// OID4VP-DCQL — the OpenID Foundation's Digital Credentials Query Language.
//
// The rule IS the wallet query. A third-party credential wallet can only be asked for
// a presentation via a standard request, so making the policy language BE the standard
// deletes the compiler between policy and wallet request.
//
// THIS FILE MUST AGREE WITH THE RUST CRATE EXACTLY. Both gate the same slots: the
// keeper and accountant run the reference evaluator, recipients and this SDK run this.
// The guard is the shared corpus: test/oid4vp-vectors.json, a byte-identical copy of
// the vendored vector file, run by test/oid4vp.conformance.ts on every `npm test`.

import {TasraError} from '../errors.js'
import {MAX_IDENTITY_LEN, scopeCovers} from './identityScope.js'

/**
 * The rule is not a well-formed OID4VP-DCQL query (or exceeds `MAX_RULE_LEN`).
 * Never retryable — the same rule fails identically. Extends
 * {@link TasraError} so one `instanceof` catches every SDK error.
 */
export class DcqlMalformedError extends TasraError {
  constructor(message: string) {
    super(message, {retryable: false})
  }
}

/** W3C JWT-VC JSON credential format. */
export const FORMAT_JWT_VC_JSON = 'jwt_vc_json'
/** IETF SD-JWT VC credential format (selective disclosure) — the Hovi / EUDI wallet format. */
export const FORMAT_DC_SD_JWT = 'dc+sd-jwt'
/**
 * An OAuth 2.0 access token from the slot owner's own IdP, sender-constrained
 * with DPoP (RFC 9449). Not a credential format in the OID4VP sense — a wallet never
 * presents one — but it reaches the evaluator as one claim set, so it is one `format`.
 */
export const FORMAT_OAUTH_AT_DPOP = 'oauth+access-token+dpop'
/**
 * Prefix of the OAuth family. Written as a prefix so a later tier (a bearer
 * artifact, deliberately NOT built) is one constant and one row, never a second set of
 * validator rules that could disagree with this one.
 */
export const OAUTH_FORMAT_PREFIX = 'oauth+'
/** Mirrors the reference evaluator's `ACCEPTED_FORMATS` . */
export const ACCEPTED_FORMATS: readonly string[] = [
  FORMAT_JWT_VC_JSON,
  FORMAT_DC_SD_JWT,
  FORMAT_OAUTH_AT_DPOP,
]

/** Whether `format` is in the OAuth family. */
export function isOauthFormat(format: string): boolean {
  return format.startsWith(OAUTH_FORMAT_PREFIX)
}

/** Bounds on `meta.max_age_secs`, mirroring the reference implementation `MAX_AGE_SECS_RANGE`. */
export const MAX_AGE_SECS_MIN = 1
export const MAX_AGE_SECS_MAX = 86_400

/**
 * Cap on a rule, in BYTES, before parsing.
 *
 * ⚠ Deliberately the same 4096 as the legacy grammar for now, and it is not yet a
 * justified number: 4096 was chosen against a terse five-clause language and an
 * OID4VP-DCQL query expressing the same policy is several times larger. The keeper
 * re-parses the rule on every request, so this bounds real per-request work.
 */
export const MAX_RULE_LEN = 4096

// ─── the query, as an ALLOW-LIST ─────────────────────────────────────────────
//
// ⚠ Every object below is validated against a closed key set, mirroring the reference implementation
// crate's `#[serde(deny_unknown_fields)]`. That is the fail-closed property and it
// does NOT come free in TypeScript: `JSON.parse` happily accepts extra keys and an
// interface is erased at runtime, so a rule carrying `trusted_authorities` or
// `require_cryptographic_holder_binding: false` would be silently IGNORED — i.e. a
// constraint the author wrote, and believes is enforced, would not be. Every
// unsupported construct must be REFUSED, never dropped.

export interface Meta {
  /** `jwt_vc_json`: outer array = alternatives; inner array = types that must ALL be present. */
  type_values?: string[][]
  /** `dc+sd-jwt`: acceptable Verifiable Credential Type (`vct`) values — a flat list of alternatives. */
  vct_values?: string[]
  /**
   * `oauth+*` ONLY (and REQUIRED there): how old the token's authentication may
   * be, in seconds.
   *
   * An OAuth access token carries no status list, so freshness IS the revocation signal: a
   * leaver's session stops minting tokens, and this bounds how long an already-minted one
   * stays usable. `exp` cannot serve — the IdP picks it, and a tenant issuing 24-hour tokens
   * would silently widen every slot's revocation window.
   */
  max_age_secs?: number
}

/**
 * A segment in a DCQL Claims Path Pointer (OID4VP §7.1.1).
 *
 * `null` selects EVERY element of an array, which is what makes a group/role claim
 * expressible: `["permissions", null]` against an array claim asks "does ANY element
 * match", which whole-value equality never could. An integer index is REFUSED by
 * {@link validate} — it addresses a position in a list whose order no format we admit
 * guarantees.
 *
 * ⚠ The TypeScript validator has to refuse the integer form BY HAND: `JSON.parse` admits
 * `["roles", 0]` silently, and an interface is erased at runtime, so a path the author
 * believes is constrained would resolve to nothing and read as "the claim is absent".
 */
export type ClaimPathSegment = string | null

export interface ClaimQuery {
  /** Path components into the credential: object keys, and `null` for every array element. */
  path: ClaimPathSegment[]
  /** Allowed values. Absent ⇒ the claim need only be PRESENT. */
  values?: unknown[]
}

/** Whether `path` selects across an array anywhere (a `null` segment). */
function selectsMany(path: readonly ClaimPathSegment[]): boolean {
  return path.some((s) => s === null)
}

/**
 * How a `kk_identity_scope_claim` grant is bound to a grantor.
 *
 * The binding is deliberately application-agnostic — no namespace vocabulary. An
 * identity is an opaque `/`-segmented string; the mechanism only relates a grant to the
 * credential's verified issuer, and applications choose what the segments mean.
 *
 *  - `"issuer"` (the only self-service-safe form): a grant reaches only the granting
 *    credential's VERIFIED issuer's namespace — the requested identity's first
 *    `/`-segment must byte-equal the issuer DID, so each namespace is rooted at its
 *    grantor's own DID (`<issuer>/…`). A human label belongs in the slot (policy
 *    class) or a deeper segment, never in this binding position.
 *  - `"any"`: administrative delegation — the credential may grant over any namespace.
 *    The validator REFUSES `"any"` combined with an open issuer set.
 */
export type ScopeNamespace = 'issuer' | 'any'

export interface CredentialQuery {
  /** Unique within the query; referenced by `credential_sets.options`. */
  id: string
  format: string
  meta?: Meta
  claims?: ClaimQuery[]
  /**
   * The claim path holding this credential's identity-scope grant (a scope
   * string or array of scope strings, matched by {@link scopeCovers}). Present ⇒ a
   * satisfied match of this query authorizes an identity-scoped operation ONLY for
   * identities the grant covers. The named path must also appear as a `claims` entry;
   * `kk_scope_namespace` is a required companion.
   */
  kk_identity_scope_claim?: string[]
  /** whose grant power the scope claim carries. Required whenever
   *  `kk_identity_scope_claim` is present; refused without it. */
  kk_scope_namespace?: ScopeNamespace
}

export interface CredentialSetQuery {
  /** Each option is a list of credential-query ids that must ALL match. */
  options: string[][]
  /** Default `true`. */
  required?: boolean
  /**
   * Display-only, passed through to the wallet's consent screen.
   *
   * ⚠ Deliberately allowed where every other unsupported field is refused: it cannot
   * affect the decision, and it is what explains the request to the user. It sits
   * inside the committed bytes, so an owner cannot change what the user is told
   * without changing the slot's `ruleCommitment`.
   */
  purpose?: unknown
}

/** A DCQL query. `credential_sets` absent ⇒ EVERY entry in `credentials` is required. */
export interface Query {
  credentials: CredentialQuery[]
  credential_sets?: CredentialSetQuery[]
}

// ─── what a consumer must expose ─────────────────────────────────────────────

/**
 * The result of a claim lookup.
 *
 * ⚠ NOT `unknown | undefined`, and that is load-bearing: JSON `null` is a PRESENT
 * claim whose value is null. Collapsing "absent" and "present-but-null" into
 * `undefined` would make `{"path":["x"]}` (presence-only) deny a credential the reference implementation
 * side grants — `Value::Null` is `Some`, not `None`.
 */
export type ClaimResult = {found: true; value: unknown} | {found: false}

const ABSENT: ClaimResult = {found: false}

/**
 * One verified credential, as the evaluator needs to see it.
 *
 * One verified credential, as the evaluator needs to see it. A consumer must expose
 * the credential's actual shape: its parsed payload, not a flat string set.
 */
export interface CredentialView {
  /** The credential's format identifier, e.g. `"jwt_vc_json"`. */
  readonly format: string
  /** The credential's type list (for `jwt_vc_json`, its `type` array). */
  readonly types: readonly string[]
  /**
   * The claim at `path`, or absent when the path does not resolve. A `null` segment selects
   * every element of an array, so the answer may be an array the credential does not
   * literally hold.
   */
  claim(path: readonly ClaimPathSegment[]): ClaimResult
}

/**
 * A {@link CredentialView} over a parsed JSON credential body.
 *
 * Path resolution walks object keys, plus `null` for "every element of this array". A path
 * that runs into the wrong shape is ABSENT rather than an error, which is what makes the
 * evaluator fail closed.
 */
export function jsonCredential(args: {
  format: string
  types: readonly string[]
  body: unknown
}): CredentialView {
  const {format, types, body} = args
  return {
    format,
    types,
    claim(path) {
      return resolvePath(body, path)
    },
  }
}

/**
 * Walk a JSON value by DCQL path segments. Mirrors the reference `resolve_path` EXACTLY,
 * including its one-result collapse: when a `null` segment is followed by more segments and
 * exactly one element resolves, the element's value is returned rather than a one-element
 * array. A port that "tidied" that up would disagree with the keeper about whether a rule
 * matches.
 */
export function resolvePath(value: unknown, path: readonly ClaimPathSegment[]): ClaimResult {
  const segment = path[0]
  if (segment === undefined) return {found: true, value}
  const rest = path.slice(1)
  if (segment === null) {
    if (!Array.isArray(value)) return ABSENT
    if (rest.length === 0) return {found: true, value}
    const results: unknown[] = []
    for (const elem of value) {
      const r = resolvePath(elem, rest)
      if (r.found) results.push(r.value)
    }
    if (results.length === 0) return ABSENT
    if (results.length === 1) return {found: true, value: results[0]}
    return {found: true, value: results}
  }
  if (!isPlainObject(value) || !Object.hasOwn(value, segment)) return ABSENT
  return resolvePath(value[segment], rest)
}

// ─── parse / validate ────────────────────────────────────────────────────────

const encoder = new TextEncoder()

/** UTF-8 byte length — the cap is defined in bytes, and JS `.length` counts UTF-16
 *  code units, which diverges for any non-ASCII rule. */
function byteLen(s: string): number {
  return encoder.encode(s).length
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function malformed(msg: string): DcqlMalformedError {
  return new DcqlMalformedError(msg)
}

/** Refuse any key outside the allow-list, naming the offender. */
function denyUnknownFields(what: string, o: Record<string, unknown>, allowed: string[]): void {
  for (const k of Object.keys(o)) {
    if (!allowed.includes(k)) {
      throw malformed(
        `not a supported DCQL query: ${what} has unknown field ${JSON.stringify(k)} ` +
          `(supported: ${allowed.join(', ')})`,
      )
    }
  }
}

function asObject(what: string, v: unknown): Record<string, unknown> {
  if (!isPlainObject(v)) throw malformed(`not a supported DCQL query: ${what} must be an object`)
  return v
}

function asArray(what: string, v: unknown): unknown[] {
  if (!Array.isArray(v)) throw malformed(`not a supported DCQL query: ${what} must be an array`)
  return v
}

function asString(what: string, v: unknown): string {
  if (typeof v !== 'string') throw malformed(`not a supported DCQL query: ${what} must be a string`)
  return v
}

function asStringArray(what: string, v: unknown): string[] {
  return asArray(what, v).map((x, i) => asString(`${what}[${i}]`, x))
}

/** A claim path: object keys and `null` wildcards. Anything else is refused by name. */
function asClaimPath(what: string, v: unknown): ClaimPathSegment[] {
  return asArray(what, v).map((x, i) => {
    if (typeof x === 'string' || x === null) return x
    throw malformed(
      `not a supported DCQL query: ${what}[${i}] must be a string key or null`,
    )
  })
}

/** Exactly the top-level `iss` claim — a nested path does not count. */
function isIssuerPath(q: ClaimQuery): boolean {
  return q.path.length === 1 && q.path[0] === 'iss'
}

/**
 * The extra rules an `oauth+*` credential query must satisfy (Decision 3).
 *
 * All three exist because an OAuth access token is a bearer-shaped artifact from a tenant's
 * OWN IdP, with none of the trust scaffolding a credential brings: no issuer registry, no
 * status list, and an audience the IdP chooses. The slot's rule is therefore the ONLY place
 * those can be pinned, so the validator makes pinning mandatory rather than optional.
 */
function validateOauthQuery(
  id: string,
  claims: ClaimQuery[] | undefined,
  meta: Meta | undefined,
): void {
  // 1. The issuer set must be PINNED. the "explicitly open" form is sound for
  //    credentials; for OAuth it would mean "any IdP on the internet that will mint a token
  //    naming our audience".
  const issuerEntry = (claims ?? []).find(isIssuerPath)
  const issuerValues = issuerEntry?.values
  if (issuerValues === undefined) {
    throw malformed(
      `credential ${JSON.stringify(id)} is an oauth+* query with an open issuer set; the ` +
        `accepted issuers must be pinned (add \`values\` to the ["iss"] entry)`,
    )
  }
  for (const v of issuerValues) {
    if (typeof v !== 'string') {
      throw malformed(
        `credential ${JSON.stringify(id)} pins a non-string issuer; an OIDC issuer is a URL`,
      )
    }
    if (!v.startsWith('https://')) {
      throw malformed(
        `credential ${JSON.stringify(id)} pins issuer ${JSON.stringify(v)}, which is not https://`,
      )
    }
    // The issuer is concatenated with `/.well-known/openid-configuration` at discovery and
    // compared BYTE-FOR-BYTE with the document's own `issuer`; a `?`/`#` makes both meaningless.
    if (v.includes('?') || v.includes('#')) {
      throw malformed(
        `credential ${JSON.stringify(id)} pins issuer ${JSON.stringify(v)}, which carries a ` +
          `query or fragment; an OIDC issuer identifier has neither`,
      )
    }
  }

  // 2. The audience must be constrained. Without it a token minted for ANOTHER relying
  //    party of the same IdP authorizes here — the classic confused deputy.
  const audEntry = (claims ?? []).find(
    (q) => q.path.length === 2 && q.path[0] === 'aud' && q.path[1] === null,
  )
  if (audEntry === undefined) {
    throw malformed(
      `credential ${JSON.stringify(id)} is an oauth+* query with no audience constraint: add ` +
        `a claims entry with path ["aud", null] and the platform audience in \`values\``,
    )
  }
  if (audEntry.values === undefined || audEntry.values.length === 0) {
    throw malformed(
      `credential ${JSON.stringify(id)} has an ["aud", null] entry with no \`values\`; the ` +
        `accepted audience must be named`,
    )
  }

  // 3. Freshness IS the revocation signal (no status list exists for an access token).
  const maxAge = meta?.max_age_secs
  if (maxAge === undefined) {
    throw malformed(
      `credential ${JSON.stringify(id)} is an oauth+* query without meta.max_age_secs; an ` +
        `access token has no status list, so the rule must bound how stale an ` +
        `authentication may be`,
    )
  }
  if (maxAge < MAX_AGE_SECS_MIN || maxAge > MAX_AGE_SECS_MAX) {
    throw malformed(
      `credential ${JSON.stringify(id)} has meta.max_age_secs ${maxAge}, outside ` +
        `${MAX_AGE_SECS_MIN}..=${MAX_AGE_SECS_MAX}`,
    )
  }
  // `type_values`/`vct_values` describe credential typing an access token does not have;
  // accepting them silently would let a rule look constrained while constraining nothing.
  if (meta?.type_values !== undefined || meta?.vct_values !== undefined) {
    throw malformed(
      `credential ${JSON.stringify(id)} is an oauth+* query carrying type_values/vct_values; ` +
        `an access token has no credential type`,
    )
  }
}

/**
 * Parse and structurally validate a rule. Looks at no credential.
 *
 * Throws {@link DcqlMalformedError} — which is a 400 (the rule is broken), never a
 * 403 (the request is denied). Conflating them sends an operator to debug the wrong
 * thing entirely.
 */
/** Validation options. */
export interface ValidateOptions {
  /**
   * When true (the default), an `["iss"]` claims entry is MANDATORY on every credential
   * query — issuer acceptance is slot policy, so a rule the platform commits must pin it.
   *
   * A WALLET planning a presentation must still be able to read an older rule that carries
   * no issuer entry, so it passes `false`. That never widens anything: the drawn verifiers
   * decide, not the wallet.
   */
  requireIssuer?: boolean
}

export function validate(rule: string, opts: ValidateOptions = {}): Query {
  const n = byteLen(rule)
  if (n > MAX_RULE_LEN) {
    throw malformed(`rule is ${n} bytes (max ${MAX_RULE_LEN})`)
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(rule)
  } catch (e) {
    throw malformed(`not a supported DCQL query: ${e instanceof Error ? e.message : String(e)}`)
  }

  const root = asObject('query', parsed)
  denyUnknownFields('query', root, ['credentials', 'credential_sets'])

  const rawCreds = asArray('credentials', root['credentials'])
  if (rawCreds.length === 0) {
    throw malformed('query has no credentials; an empty query would authorize everyone')
  }

  const ids = new Set<string>()
  const credentials: CredentialQuery[] = rawCreds.map((rc, i) => {
    const c = asObject(`credentials[${i}]`, rc)
    denyUnknownFields(`credentials[${i}]`, c, [
      'id',
      'format',
      'meta',
      'claims',
      'kk_identity_scope_claim',
      'kk_scope_namespace',
    ])

    const id = asString(`credentials[${i}].id`, c['id'])
    if (id === '') throw malformed('credential query has an empty id')
    if (ids.has(id)) throw malformed(`duplicate credential id ${JSON.stringify(id)}`)
    ids.add(id)

    const format = asString(`credentials[${i}].format`, c['format'])
    if (!ACCEPTED_FORMATS.includes(format)) {
      throw malformed(
        `unsupported credential format ${JSON.stringify(format)} ` +
          `(supported: ${ACCEPTED_FORMATS.join(', ')})`,
      )
    }

    let meta: Meta | undefined
    if (c['meta'] !== undefined) {
      const m = asObject(`credentials[${i}].meta`, c['meta'])
      denyUnknownFields(`credentials[${i}].meta`, m, [
        'type_values',
        'vct_values',
        'max_age_secs',
      ])
      meta = {}
      if (m['type_values'] !== undefined) {
        meta.type_values = asArray(`credentials[${i}].meta.type_values`, m['type_values']).map((alt, j) =>
          asStringArray(`credentials[${i}].meta.type_values[${j}]`, alt),
        )
      }
      if (m['vct_values'] !== undefined) {
        meta.vct_values = asStringArray(`credentials[${i}].meta.vct_values`, m['vct_values'])
      }
      if (m['max_age_secs'] !== undefined) {
        const v = m['max_age_secs']
        if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) {
          throw malformed(
            `not a supported DCQL query: credentials[${i}].meta.max_age_secs must be a ` +
              `non-negative integer`,
          )
        }
        meta.max_age_secs = v
      }
    }

    let claims: ClaimQuery[] | undefined
    if (c['claims'] !== undefined) {
      claims = asArray(`credentials[${i}].claims`, c['claims']).map((rq, j) => {
        const q = asObject(`credentials[${i}].claims[${j}]`, rq)
        denyUnknownFields(`credentials[${i}].claims[${j}]`, q, ['path', 'values'])
        const path = asClaimPath(`credentials[${i}].claims[${j}].path`, q['path'])
        if (path.length === 0) {
          throw malformed(
            `credential ${JSON.stringify(id)} has a claim query with an empty path`,
          )
        }
        // An integer index addresses a POSITION in a list. No format we admit fixes the
        // order of an array claim, so a rule that matched at issuance could silently stop
        // matching on the next one — fail at provisioning instead. ⚠ Enforced by hand:
        // `JSON.parse` admits the number and nothing else would notice.
        if ((q['path'] as unknown[]).some((seg) => typeof seg === 'number')) {
          throw malformed(
            `credential ${JSON.stringify(id)} has an integer index in a claim path; array ` +
              `positions are not addressable (use null to select every element)`,
          )
        }
        // A leading `null` would select over the credential body, which is an object.
        if (path[0] === null) {
          throw malformed(
            `credential ${JSON.stringify(id)} has a claim path starting with null; the ` +
              `credential body is an object, so a leading wildcard can never select anything`,
          )
        }
        let values: unknown[] | undefined
        if (q['values'] !== undefined) {
          values = asArray(`credentials[${i}].claims[${j}].values`, q['values'])
          // An explicit empty `values` can never match — almost certainly a mistake
          // rather than an intentional deny-all, and far better refused at
          // provisioning than at 3am.
          if (values.length === 0) {
            throw malformed(
              `credential ${JSON.stringify(id)} has a claim query with an empty \`values\` ` +
                `list, which no credential can satisfy`,
            )
          }
        }
        return values === undefined ? {path} : {path, values}
      })
    }

    // Issuer acceptance is slot policy, so the constraint is MANDATORY —
    // `{"path":["iss"],"values":[…]}` pins the accepted issuers; the same entry
    // without `values` is the explicitly-open form (any verifiable issuer, stated in
    // the committed rule rather than implied by silence).
    const hasIssuerEntry = (claims ?? []).some(isIssuerPath)
    if (!hasIssuerEntry && opts.requireIssuer !== false) {
      throw malformed(
        `credential ${JSON.stringify(id)} has no issuer constraint: add a claims entry ` +
          `with path ["iss"] — with \`values\` to pin the accepted issuers, or without ` +
          `\`values\` to accept any verifiable issuer (explicitly)`,
      )
    }

    // ── the oauth+* family carries its own mandatory constraints ──
    if (isOauthFormat(format)) {
      validateOauthQuery(id, claims, meta)
    } else if (meta?.max_age_secs !== undefined) {
      throw malformed(
        `credential ${JSON.stringify(id)} sets meta.max_age_secs, which only the oauth+* ` +
          `formats accept — a credential format carries its own revocation signal`,
      )
    }

    // ── identity-scope binding validation (mirrors the reference order) ──
    // The namespace governs a scope claim, so it is meaningless alone.
    if (c['kk_scope_namespace'] !== undefined && c['kk_identity_scope_claim'] === undefined) {
      throw malformed(
        `credential ${JSON.stringify(id)} has kk_scope_namespace without kk_identity_scope_claim`,
      )
    }
    let scopeClaim: string[] | undefined
    let scopeNamespace: ScopeNamespace | undefined
    if (c['kk_identity_scope_claim'] !== undefined) {
      scopeClaim = asStringArray(
        `credentials[${i}].kk_identity_scope_claim`,
        c['kk_identity_scope_claim'],
      )
      if (scopeClaim.length === 0) {
        throw malformed(
          `credential ${JSON.stringify(id)} has an empty kk_identity_scope_claim path`,
        )
      }
      // The scope claim must be part of the credential match itself, so a query cannot
      // be satisfied without the grant being present to check.
      const path = scopeClaim
      const scopeClaimPresent = (claims ?? []).some(
        (q) => q.path.length === path.length && q.path.every((p, k) => p === path[k]),
      )
      if (!scopeClaimPresent) {
        throw malformed(
          `credential ${JSON.stringify(id)} names kk_identity_scope_claim ` +
            `${JSON.stringify(scopeClaim)} but has no matching claims entry for that path`,
        )
      }
      // The namespace is a required companion — it says whose grant power the claim
      // carries. (The reference implementation refuses a value outside the enum at parse time; the verdict class
      // is the same malformed either way.)
      const ns = c['kk_scope_namespace']
      if (ns === undefined) {
        throw malformed(
          `credential ${JSON.stringify(id)} has kk_identity_scope_claim but no ` +
            `kk_scope_namespace (required — "issuer" or "any")`,
        )
      }
      if (ns !== 'issuer' && ns !== 'any') {
        throw malformed(
          `not a supported DCQL query: kk_scope_namespace must be "issuer" or "any"`,
        )
      }
      // `"any"` (grant over any namespace) with an OPEN issuer set would let anyone
      // self-issue a credential granting scope over anyone. Refuse the pairing.
      if (ns === 'any') {
        const issuerPinned = (claims ?? []).some(
          (q) => isIssuerPath(q) && q.values !== undefined,
        )
        if (!issuerPinned) {
          throw malformed(
            `credential ${JSON.stringify(id)} pairs kk_scope_namespace "any" with an open ` +
              `issuer set; unscoped grant power must come from pinned issuers (add ` +
              `\`values\` to the ["issuer"] entry)`,
          )
        }
      }
      scopeNamespace = ns
    }

    const out: CredentialQuery = {id, format}
    if (meta !== undefined) out.meta = meta
    if (claims !== undefined) out.claims = claims
    if (scopeClaim !== undefined) out.kk_identity_scope_claim = scopeClaim
    if (scopeNamespace !== undefined) out.kk_scope_namespace = scopeNamespace
    return out
  })

  let credential_sets: CredentialSetQuery[] | undefined
  if (root['credential_sets'] !== undefined) {
    credential_sets = asArray('credential_sets', root['credential_sets']).map((rs, i) => {
      const s = asObject(`credential_sets[${i}]`, rs)
      denyUnknownFields(`credential_sets[${i}]`, s, ['options', 'required', 'purpose'])

      const options = asArray(`credential_sets[${i}].options`, s['options']).map((o, j) =>
        asStringArray(`credential_sets[${i}].options[${j}]`, o),
      )
      if (options.length === 0) {
        throw malformed('credential_set has no options; it could never be satisfied')
      }
      for (const opt of options) {
        if (opt.length === 0) {
          throw malformed('credential_set option is empty, which would match vacuously')
        }
        for (const id of opt) {
          if (!ids.has(id)) {
            throw malformed(`credential_set references unknown credential id ${JSON.stringify(id)}`)
          }
        }
      }

      const out: CredentialSetQuery = {options}
      if (s['required'] !== undefined) {
        if (typeof s['required'] !== 'boolean') {
          throw malformed(
            `not a supported DCQL query: credential_sets[${i}].required must be a boolean`,
          )
        }
        out.required = s['required']
      }
      if (s['purpose'] !== undefined) out.purpose = s['purpose']
      return out
    })
  }

  return credential_sets === undefined ? {credentials} : {credentials, credential_sets}
}

// ─── evaluate ────────────────────────────────────────────────────────────────

/**
 * Does `credentials` satisfy `rule`?
 *
 * Returns `true` to grant and `false` to deny; throws {@link DcqlMalformedError} when
 * the rule itself is broken. ⚠ Takes NO holder identity — DCQL constrains credentials,
 * and holder identity is established by the presentation's holder binding. That is why
 * the legacy `required_sub_in` clause has no encoding here.
 */
export function evaluate(rule: string, credentials: readonly CredentialView[]): boolean {
  const q = validate(rule)

  // ⚠ an identity-scoped rule constrains WHICH identity may be operated on,
  // so authorizing it here — with no identity to check — would silently ignore that
  // constraint. Denied, mirroring the reference implementation; use evaluateIdentityScoped.
  if (q.credentials.some(c => c.kk_identity_scope_claim !== undefined)) return false

  return evaluateWho(q, credentials) !== null
}

/**
 * The WHO gate shared by {@link evaluate} and {@link evaluateIdentityScoped}, so the
 * two can never disagree about which credential queries are satisfied. Returns the
 * satisfied-query id set, or `null` when the rule as a whole is unsatisfied (the reference implementation
 * side's `Err(Reject)`).
 */
function evaluateWho(q: Query, credentials: readonly CredentialView[]): Set<string> | null {
  // Which credential queries are satisfied by at least one presented credential.
  const satisfied = new Set<string>()
  for (const cq of q.credentials) {
    if (credentials.some(c => matches(cq, c))) satisfied.add(cq.id)
  }

  if (q.credential_sets === undefined) {
    // Absent ⇒ every credential query is required.
    return q.credentials.every(c => satisfied.has(c.id)) ? satisfied : null
  }

  // ⚠ Present ⇒ ONLY the sets decide. A credential query not named by any satisfied
  // option is not independently required — that is what makes `options` alternatives
  // rather than extra conditions.
  for (const set of q.credential_sets) {
    if (set.required === false) continue
    const ok = set.options.some(opt => opt.every(id => satisfied.has(id)))
    if (!ok) return null
  }
  return satisfied
}

/** The result of credential selection against a rule. */
export interface Selection {
  /** Whether the rule can be satisfied by the given credentials. */
  satisfied: boolean
  /** The minimal set of credentials that satisfy the rule (empty when unsatisfied). */
  credentials: CredentialView[]
  /** Credential query ids that no presented credential satisfies. */
  unsatisfied: string[]
}

/**
 * Select the minimal set of credentials that satisfy `rule` — the inverse of
 * {@link evaluate}. Given a rule and held credentials, returns which to present.
 *
 * When `credential_sets` are present, picks the cheapest satisfying option
 * (fewest credential queries). When absent, every credential query must be
 * satisfied.
 */
export function select(rule: string, credentials: readonly CredentialView[], opts: ValidateOptions = {}): Selection {
  const q = validate(rule, opts)

  // Map each credential query to its matching credentials.
  const matchMap = new Map<string, CredentialView[]>()
  for (const cq of q.credentials) {
    const matching = credentials.filter(c => matches(cq, c))
    matchMap.set(cq.id, matching)
  }

  const satisfied = new Set<string>()
  for (const [id, creds] of matchMap) {
    if (creds.length > 0) satisfied.add(id)
  }

  // Determine which credential query ids are needed.
  let neededIds: string[]

  if (q.credential_sets === undefined) {
    // No sets ⇒ every credential query is required.
    neededIds = q.credentials.map(c => c.id)
  } else {
    // Pick the cheapest satisfying option per required set.
    const picked = new Set<string>()
    const unsatisfiable = new Set<string>()
    for (const set of q.credential_sets) {
      if (set.required === false) continue
      // Find the satisfying option with the fewest queries.
      let bestOption: string[] | null = null
      for (const opt of set.options) {
        if (opt.every(id => satisfied.has(id))) {
          if (bestOption === null || opt.length < bestOption.length) {
            bestOption = opt
          }
        }
      }
      if (bestOption !== null) {
        for (const id of bestOption) picked.add(id)
      } else {
        // A required set with NO satisfiable option denies (as `evaluate` does); name every
        // query the set could have been answered with so the caller can say what is missing.
        for (const opt of set.options) for (const id of opt) if (!satisfied.has(id)) unsatisfiable.add(id)
      }
    }
    if (unsatisfiable.size > 0) {
      return {satisfied: false, credentials: [], unsatisfied: [...unsatisfiable]}
    }
    neededIds = [...picked]
  }

  const unsatisfied = neededIds.filter(id => !satisfied.has(id))
  if (unsatisfied.length > 0) {
    return {satisfied: false, credentials: [], unsatisfied}
  }

  // Collect one matching credential per needed query (deduplicated).
  const selected = new Set<CredentialView>()
  for (const id of neededIds) {
    const creds = matchMap.get(id)
    if (creds && creds.length > 0) selected.add(creds[0]!)
  }

  return {satisfied: true, credentials: [...selected], unsatisfied: []}
}

/**
 * Does `credentials` authorize an identity-scoped operation on `identity`?
 *
 * The {@link evaluate} WHO gate PLUS the WHICH gate: a satisfied credential query
 * carrying `kk_identity_scope_claim` must have a matching credential whose scope grant
 * (a string or array at that path) covers `identity` ({@link scopeCovers}) and — under
 * `kk_scope_namespace: "issuer"` — whose verified issuer owns the identity's namespace
 * (its first `/`-segment must byte-equal the issuer DID, the self-grant-over-others
 * gate). A rule with no scope binding on any satisfied query denies: an unscoped rule
 * can never authorize a scoped operation.
 *
 * ⚠ Local evaluation is ADVISORY here as everywhere in this SDK — the verifier
 * committee runs the authoritative check; a wrong local answer costs a wasted request,
 * never access.
 */
export function evaluateIdentityScoped(
  rule: string,
  credentials: readonly CredentialView[],
  identity: string,
): boolean {
  // Mirrors the reference order: the identity's own shape is checked BEFORE the rule parses
  // — an oversize or NUL-bearing identity is a DENY, not a malformed rule.
  if (byteLen(identity) > MAX_IDENTITY_LEN || identity.includes('\0')) return false

  const q = validate(rule)
  const satisfied = evaluateWho(q, credentials)
  if (satisfied === null) return false

  for (const cq of q.credentials) {
    if (!satisfied.has(cq.id)) continue
    const scopePath = cq.kk_identity_scope_claim
    if (scopePath === undefined) continue
    // validate() guarantees a namespace whenever the scope claim is present.
    const namespace = cq.kk_scope_namespace
    if (namespace === undefined) continue
    // Every credential MATCHING this query is a candidate grantor.
    for (const c of credentials) {
      if (matches(cq, c) && credentialGrantCovers(c, scopePath, namespace, identity)) {
        return true
      }
    }
  }
  // "No scope binding on any satisfied query" and "no covering grant" are both
  // denials — the reference implementation distinguishes them only in the Reject message.
  return false
}

/**
 * Whether credential `c`'s scope claim at `scopePath` covers `identity`, honoring the
 * namespace binding. Under `"issuer"` the identity's first `/`-segment must byte-equal
 * `c`'s verified issuer DID; under `"any"` no such gate (the validator already required
 * a pinned issuer set for `"any"`).
 */
function credentialGrantCovers(
  c: CredentialView,
  scopePath: readonly string[],
  namespace: ScopeNamespace,
  identity: string,
): boolean {
  if (namespace === 'issuer') {
    const issuer = c.claim(['iss'])
    if (!issuer.found || typeof issuer.value !== 'string') return false
    const firstSegment = identity.split('/')[0]
    if (firstSegment !== issuer.value) return false
  }
  const got = c.claim(scopePath)
  if (!got.found) return false
  if (typeof got.value === 'string') return scopeCovers(got.value, identity)
  if (Array.isArray(got.value)) {
    return got.value.some(g => typeof g === 'string' && scopeCovers(g, identity))
  }
  return false
}

/** One credential query against one credential. */
/** One credential query against one credential — exported for the wallet's per-query planning. */
export function credentialMatches(q: CredentialQuery, c: CredentialView): boolean {
  return matches(q, c)
}

function matches(q: CredentialQuery, c: CredentialView): boolean {
  if (c.format !== q.format) return false

  const typeValues = q.meta?.type_values
  if (typeValues !== undefined) {
    // Outer = alternatives (any), inner = all-required.
    const ok = typeValues.some(alt => alt.every(t => c.types.includes(t)))
    if (!ok) return false
  }
  // `dc+sd-jwt`: the view's `types` carry the credential's `vct`; any listed value matches.
  const vctValues = q.meta?.vct_values
  if (vctValues !== undefined && !c.types.some(t => vctValues.includes(t))) return false

  for (const claim of q.claims ?? []) {
    const got = c.claim(claim.path)
    if (!got.found) return false
    if (!claimValueMatches(claim.path, claim.values, got.value)) return false
  }
  return true
}

/**
 * Whether a resolved claim value satisfies a claim query's `values`.
 *
 * Without a `null` segment this is whole-value equality, unchanged. WITH one, the resolved
 * value is the SELECTION, so the question becomes "does ANY selected element match ANY
 * listed value" — the only reading under which a rule can say "this role is among the
 * holder's roles".
 */
function claimValueMatches(
  path: readonly ClaimPathSegment[],
  values: readonly unknown[] | undefined,
  actual: unknown,
): boolean {
  const wildcard = selectsMany(path)
  // A wildcard that selected nothing is ABSENT, not present-and-empty: `resolvePath`
  // answers `[]` for `null` over an empty array, and treating that as "present" would let a
  // values-less entry match a holder with no roles at all.
  if (wildcard && Array.isArray(actual) && actual.length === 0) return false
  if (values === undefined) return true
  if (wildcard && Array.isArray(actual)) {
    return actual.some((elem) => values.some((v) => jsonEqual(v, elem)))
  }
  return values.some((v) => jsonEqual(v, actual))
}

/**
 * Structural JSON equality, via the canonical form.
 *
 * Reusing JCS rather than hand-rolling a deep-equal keeps ONE notion of "the same JSON
 * value" shared with the commitment, and it is key-order insensitive by construction.
 *
 * ⚠ A KNOWN, UNFIXABLE CROSS-LANGUAGE EDGE: the reference JSON parser distinguishes the
 * integer `3` from the float `3.0`, so a rule allowing `3.0` does not match a
 * credential carrying `3`. JavaScript has ONE number type — `JSON.parse('3')` and
 * `JSON.parse('3.0')` are indistinguishable — so this file cannot reproduce that
 * distinction, and would grant where the reference implementation denies. Do not write a rule whose
 * correctness depends on it. (`"3"` vs `3` — string vs number — IS distinguished on
 * both sides, and the corpus pins it.)
 */
function jsonEqual(a: unknown, b: unknown): boolean {
  return jcs(a) === jcs(b)
}

// ─── canonicalisation + commitment ───────────────────────────────────────────

/**
 * RFC 8785 (JCS) canonical form: sorted keys, no insignificant whitespace, ECMAScript
 * number formatting, UTF-8.
 *
 * ⚠ Why the commitment needs this at all: the rule stops being an opaque string the
 * moment it becomes the `dcql_query` inside a signed OID4VP request object. It must be
 * parsed and re-serialised, and any JSON library may reorder keys or restyle
 * whitespace. Hashing raw bytes would break the commitment at exactly the point the
 * rule is used for its new purpose.
 */
export function canonicalize(rule: string): string {
  let v: unknown
  try {
    v = JSON.parse(rule)
  } catch (e) {
    throw malformed(`rule is not valid JSON: ${e instanceof Error ? e.message : String(e)}`)
  }
  return jcs(v)
}

/**
 * RFC 8785 serialisation of an already-parsed JSON value.
 *
 * Three details do the work, and each is a place a hand-rolled canonicaliser goes
 * wrong:
 *  - **Key order** is by UTF-16 code unit. JS's default `Array.prototype.sort()` on
 *    strings compares exactly that, so a bare `.sort()` is correct — but only because
 *    it is the default comparator; a locale-aware one would NOT be.
 *  - **Numbers** use ECMAScript `Number::toString`, which is what `JSON.stringify`
 *    emits for a number. RFC 8785 chose that algorithm precisely so JS needs no
 *    special casing.
 *  - **Strings** use JSON escaping with the shortest form, and lone surrogates escaped
 *    as `\uXXXX` — which is well-formed `JSON.stringify` (ES2019) exactly.
 */
function jcs(v: unknown): string {
  if (v === null) return 'null'
  switch (typeof v) {
    case 'boolean':
      return v ? 'true' : 'false'
    case 'number':
      if (!Number.isFinite(v)) {
        throw malformed(`rule could not be canonicalised: ${String(v)} is not a JSON number`)
      }
      return JSON.stringify(v)
    case 'string':
      return JSON.stringify(v)
  }
  if (Array.isArray(v)) return `[${v.map(jcs).join(',')}]`
  if (isPlainObject(v)) {
    const keys = Object.keys(v).sort()
    return `{${keys.map(k => `${JSON.stringify(k)}:${jcs(v[k])}`).join(',')}}`
  }
  throw malformed(`rule could not be canonicalised: unsupported value of type ${typeof v}`)
}

/**
 * True when `rule` parses as a supported OID4VP-DCQL query.
 *
 * This is the grammar dispatch used by the commitment. It must stay a TOTAL function —
 * a legacy kk-DCQL rule is not an error here, it is simply "not OID4VP".
 */
export function isOid4vpRule(rule: string): boolean {
  try {
    validate(rule)
    return true
  } catch {
    return false
  }
}
