// The OID4VP-DCQL evaluator's REFUSALS, and the path resolver's one-result collapse.
//
// This is the authorization language. `validate` is the gate that decides whether a rule is
// admissible at all, and every branch of it that goes untested is a malformed rule that might
// be accepted — which for an access-control grammar is the failure that matters. The
// conformance vectors (test/oid4vp.conformance.ts) pin agreement with the reference
// implementation on rules that ARE valid; this covers the ones that must not be.
//
// Three groups carry the weight:
//
//   • THE OAUTH+DPOP FORMAT's four mandatory constraints. An access token comes from the
//     tenant's OWN IdP with none of a credential's trust scaffolding — no issuer registry, no
//     status list, and an audience the IdP chooses. So the rule is the only place those can be
//     pinned, and the validator makes pinning mandatory: pinned https issuers with no query or
//     fragment, a constrained audience, and a max_age (freshness IS the revocation signal).
//
//   • THE SCOPE-GRANT PAIRING. `kk_scope_namespace: "any"` with an open issuer set would let
//     anyone self-issue a credential granting scope over anyone, so the validator refuses the
//     combination outright rather than leaving it to the evaluator.
//
//   • THE PATH RESOLVER's one-result collapse. A `null` segment followed by more segments
//     returns the single element rather than a one-element array — deliberately, to match the
//     reference. A port that "tidied" that up would disagree with the keeper about whether a
//     rule matches, which is a silent authorization difference.
//
// Run: tsx test/oid4vp.dcql-validation.ts — exits non-zero on any failure.

import {
  DcqlMalformedError,
  canonicalize,
  credentialMatches,
  evaluate,
  evaluateIdentityScoped,
  isOid4vpRule,
  jsonCredential,
  resolvePath,
  select,
  validate,
} from '../src/auth/oid4vp.ts'
import {scopeCovers} from '../src/auth/identityScope.ts'

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
/** Assert the rule is refused as MALFORMED and that the message names the reason. */
function refused(name: string, re: RegExp, rule: unknown): void {
  try {
    validate(typeof rule === 'string' ? rule : JSON.stringify(rule))
    ok(name, false, 'was accepted')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    ok(name, error instanceof DcqlMalformedError && re.test(message), `message was ${JSON.stringify(message)}`)
  }
}
function accepted(name: string, rule: unknown): void {
  try {
    validate(typeof rule === 'string' ? rule : JSON.stringify(rule))
    passed++
  } catch (error) {
    failures.push(`${name} — was refused: ${error instanceof Error ? error.message : String(error)}`)
  }
}

// ─── the path resolver ────────────────────────────────────────────────────────
{
  const body = {
    iss: 'did:web:hr.example',
    roles: ['engineer', 'reviewer'],
    one: ['only'],
    nested: [{k: 'a'}, {k: 'b'}],
    single: [{k: 'just-one'}],
    empty: [],
    holes: [{k: 'a'}, {other: 1}],
  }

  eq('an empty path returns the whole value', resolvePath(body, []), {found: true, value: body})
  eq('a key path resolves', resolvePath(body, ['iss']), {found: true, value: 'did:web:hr.example'})
  eq('a missing key is absent', resolvePath(body, ['nope']).found, false)
  eq('a key path into a non-object is absent', resolvePath(body, ['iss', 'deeper']).found, false)

  // A trailing `null` returns the ARRAY itself — there are no further segments to select with.
  eq('a trailing null returns the whole array', resolvePath(body, ['roles', null]), {found: true, value: ['engineer', 'reviewer']})
  eq('a null on a non-array is absent', resolvePath(body, ['iss', null]).found, false)

  // ⚠ THE ONE-RESULT COLLAPSE. With further segments, `null` selects across elements — and
  // when exactly ONE resolves, the ELEMENT is returned, not a one-element array. This mirrors
  // the reference exactly; tidying it into an array would disagree with the keeper about
  // whether a rule matches.
  eq('null + segment with several matches returns an array', resolvePath(body, ['nested', null, 'k']), {found: true, value: ['a', 'b']})
  eq('null + segment with ONE match collapses to the element', resolvePath(body, ['single', null, 'k']), {found: true, value: 'just-one'})
  // Elements that do not resolve are skipped, so a mixed array collapses to the one that did.
  eq('unresolvable elements are skipped', resolvePath(body, ['holes', null, 'k']), {found: true, value: 'a'})
  // Nothing resolving at all is absent, not an empty array — an empty array would be a VALUE
  // and could satisfy a presence check.
  eq('no element resolving is absent, not an empty array', resolvePath(body, ['nested', null, 'nope']).found, false)
  eq('a null over an empty array is absent', resolvePath(body, ['empty', null, 'k']).found, false)
}

// ─── the shape of the query itself ────────────────────────────────────────────
{
  const valid = {
    credentials: [{id: 'c1', format: 'jwt_vc_json', claims: [{path: ['iss'], values: ['did:web:hr.example']}]}],
  }
  accepted('a minimal well-formed rule is accepted', valid)

  // ⚠ EVERY credential query must carry an ["iss"] entry. Openness has to be STATED: with
  // `values` it pins the accepted issuers, without `values` it accepts any verifiable issuer
  // — but the entry itself is mandatory, so a rule cannot be silently issuer-blind. This is
  // the first thing to check when a rule that looks fine is refused.
  refused('a credential query with NO issuer entry is refused', /has no issuer constraint: add a claims entry with path \["iss"\]/, {
    credentials: [{id: 'c1', format: 'jwt_vc_json'}],
  })
  refused('…and so is one whose only claim is something else', /has no issuer constraint/, {
    credentials: [{id: 'c1', format: 'jwt_vc_json', claims: [{path: ['dept'], values: ['Engineering']}]}],
  })
  accepted('an explicitly OPEN issuer set (no values) is accepted', {
    credentials: [{id: 'c1', format: 'jwt_vc_json', claims: [{path: ['iss']}]}],
  })
  // An empty `values` list is not "open" — it is a constraint nothing can satisfy.
  refused('an empty values list is refused as unsatisfiable', /empty `values` list, which no credential can satisfy/, {
    credentials: [{id: 'c1', format: 'jwt_vc_json', claims: [{path: ['iss'], values: []}]}],
  })

  refused('a non-JSON rule is refused, naming the parse error', /not a supported DCQL query: Expected property name/, '{not json')
  refused('a rule that is not an object is refused', /must be an object/, '[]')
  refused('a rule with no credentials array is refused', /must be an array/, {})
  refused('credentials as an object is refused', /must be an array/, {credentials: {}})
  refused('a credential entry that is not an object is refused', /credentials\[0\] must be an object/, {credentials: ['c1']})
  // An unknown field is refused and NAMED, with the supported set — a typo'd key that was
  // ignored would read as a constraint that is silently absent.
  refused('an unknown credential field is named, with the supported set', /credentials\[0\] has unknown field "form"/, {
    credentials: [{id: 'c1', format: 'jwt_vc_json', form: 'x'}],
  })
  refused('an unknown root field is named', /has unknown field "extra"/, {...valid, extra: 1})
  refused('an unknown meta field is named', /meta has unknown field "vct"/, {
    credentials: [{id: 'c1', format: 'jwt_vc_json', meta: {vct: 'x'}}],
  })
  refused('an unknown claims field is named', /claims\[0\] has unknown field "value"/, {
    credentials: [{id: 'c1', format: 'jwt_vc_json', claims: [{path: ['iss'], value: 'x'}]}],
  })

  // Ids: present, non-empty, unique. A duplicate id would make credential_sets ambiguous.
  refused('an empty credential id is refused', /empty id/, {credentials: [{id: '', format: 'jwt_vc_json'}]})
  refused('a duplicate credential id is refused, naming it', /duplicate credential id "c1"/, {
    credentials: [valid.credentials[0], valid.credentials[0]],
  })
  refused('a non-string id is refused', /id must be a string/, {credentials: [{id: 1, format: 'jwt_vc_json'}]})

  // The format allow-list — three formats, and nothing else.
  refused('an unsupported format is refused, listing the supported ones', /unsupported credential format "ldp_vc".*supported:/s, {
    credentials: [{id: 'c1', format: 'ldp_vc'}],
  })
  for (const format of ['jwt_vc_json', 'dc+sd-jwt']) {
    accepted(`${format} is accepted`, {credentials: [{...valid.credentials[0], format}]})
  }

  // meta.max_age_secs is a non-negative integer.
  for (const [label, v] of [['a string', '600'], ['a float', 1.5], ['negative', -1]] as const) {
    refused(`meta.max_age_secs as ${label} is refused`, /max_age_secs must be a non-negative integer/, {
      credentials: [{id: 'c1', format: 'jwt_vc_json', meta: {max_age_secs: v}}],
    })
  }

  // Claim paths.
  refused('an empty claim path is refused', /claim query with an empty path/, {
    credentials: [{id: 'c1', format: 'jwt_vc_json', claims: [{path: []}]}],
  })
  // ⚠ An INTEGER index addresses a position in a list, and no admitted format fixes array
  // order — so a rule that matched at issuance could silently stop matching on the next one.
  // Refused at provisioning instead, and the message says to use `null`.
  // An integer index addresses a POSITION in a list, and no admitted format fixes array order,
  // so a rule that matched at issuance could silently stop matching on the next one. Caught by
  // the path grammar itself: a segment is a string key or null, nothing else.
  refused('an integer index in a claim path is refused', /path\[1\] must be a string key or null/, {
    credentials: [{id: 'c1', format: 'jwt_vc_json', claims: [{path: ['roles', 0]}]}],
  })
  accepted('a null segment is the supported way to select elements', {
    credentials: [
      {id: 'c1', format: 'jwt_vc_json', claims: [{path: ['iss']}, {path: ['roles', null], values: ['engineer']}]},
    ],
  })

  // credential_sets.
  refused('a credential_set with no options is refused', /no options; it could never be satisfied/, {
    ...valid,
    credential_sets: [{options: []}],
  })
  refused('an empty option is refused as vacuous', /option is empty, which would match vacuously/, {
    ...valid,
    credential_sets: [{options: [[]]}],
  })
  refused('an option naming an unknown id is refused', /references unknown credential id "c9"/, {
    ...valid,
    credential_sets: [{options: [['c9']]}],
  })
  refused('a non-boolean `required` is refused', /required must be a boolean/, {
    ...valid,
    credential_sets: [{options: [['c1']], required: 'yes'}],
  })
  accepted('a well-formed credential_set is accepted', {...valid, credential_sets: [{options: [['c1']], required: true, purpose: 'access'}]})
}

// ─── oauth+access-token+dpop: the four mandatory constraints ──────────────────
{
  const AUD = 'https://agent.example/authz/43113'
  const oauth = (over: Record<string, unknown> = {}) => ({
    credentials: [
      {
        id: 'tok',
        format: 'oauth+access-token+dpop',
        claims: [
          {path: ['iss'], values: ['https://idp.example']},
          {path: ['aud', null], values: [AUD]},
        ],
        meta: {max_age_secs: 300},
        ...over,
      },
    ],
  })
  accepted('a fully-constrained oauth query is accepted', oauth())

  // 1. The issuer set must be PINNED. "Explicitly open" is sound for a credential; for OAuth
  //    it means any IdP on the internet that will mint a token naming our audience.
  refused('an oauth query with no issuer entry is refused', /has no issuer constraint/, {
    credentials: [{id: 'tok', format: 'oauth+access-token+dpop', claims: [{path: ['aud', null], values: [AUD]}], meta: {max_age_secs: 300}}],
  })
  refused('an issuer entry with no values is refused', /open issuer set/, {
    credentials: [
      {id: 'tok', format: 'oauth+access-token+dpop', claims: [{path: ['iss']}, {path: ['aud', null], values: [AUD]}], meta: {max_age_secs: 300}},
    ],
  })
  refused('a non-string issuer is refused', /pins a non-string issuer; an OIDC issuer is a URL/, {
    credentials: [
      {id: 'tok', format: 'oauth+access-token+dpop', claims: [{path: ['iss'], values: [42]}, {path: ['aud', null], values: [AUD]}], meta: {max_age_secs: 300}},
    ],
  })
  refused('a non-https issuer is refused', /which is not https:\/\//, oauth({
    claims: [{path: ['iss'], values: ['http://idp.example']}, {path: ['aud', null], values: [AUD]}],
  }))
  // ⚠ The issuer is concatenated with /.well-known/openid-configuration at discovery and
  // compared byte-for-byte with the document's own `issuer`, so a query or fragment makes both
  // meaningless.
  for (const [label, iss] of [['a query', 'https://idp.example?x=1'], ['a fragment', 'https://idp.example#f']] as const) {
    refused(`an issuer with ${label} is refused`, /carries a query or fragment/, oauth({
      claims: [{path: ['iss'], values: [iss]}, {path: ['aud', null], values: [AUD]}],
    }))
  }

  // 2. The audience must be constrained, or a token minted for ANOTHER relying party of the
  //    same IdP authorizes here — the confused deputy.
  refused('no audience constraint is refused, naming the entry to add', /no audience constraint: add a claims entry with path \["aud", null\]/, oauth({
    claims: [{path: ['iss'], values: ['https://idp.example']}],
  }))
  refused('an aud entry with no values is refused', /\["aud", null\] entry with no `values`/, oauth({
    claims: [{path: ['iss'], values: ['https://idp.example']}, {path: ['aud', null]}],
  }))
  refused('an aud entry with empty values is refused as unsatisfiable', /empty `values` list, which no credential can satisfy/, oauth({
    claims: [{path: ['iss'], values: ['https://idp.example']}, {path: ['aud', null], values: []}],
  }))

  // 3. Freshness IS the revocation signal — an access token has no status list.
  refused('no max_age_secs is refused, explaining why', /without meta\.max_age_secs; an access token has no status list/, {
    credentials: [
      {id: 'tok', format: 'oauth+access-token+dpop', claims: [{path: ['iss'], values: ['https://idp.example']}, {path: ['aud', null], values: [AUD]}]},
    ],
  })
  refused('a max_age_secs outside the range is refused, naming the range', /outside \d+\.\.=\d+/, oauth({meta: {max_age_secs: 0}}))
  refused('a very large max_age_secs is refused', /outside \d+\.\.=\d+/, oauth({meta: {max_age_secs: 999_999_999}}))

  // 4. Credential typing an access token does not have.
  for (const meta of [{max_age_secs: 300, type_values: [['X']]}, {max_age_secs: 300, vct_values: ['X']}]) {
    refused('type_values/vct_values on an oauth query are refused', /an access token has no credential type/, oauth({meta}))
  }
}

// ─── the identity-scope grant pairing ─────────────────────────────────────────
{
  const scoped = (over: Record<string, unknown> = {}) => ({
    credentials: [
      {
        id: 'grant',
        format: 'jwt_vc_json',
        claims: [{path: ['iss'], values: ['did:web:hr.example']}, {path: ['scopes']}],
        kk_identity_scope_claim: ['scopes'],
        kk_scope_namespace: 'issuer',
        ...over,
      },
    ],
  })
  accepted('a well-formed issuer-namespaced scope grant is accepted', scoped())

  refused('a namespace without a scope claim is refused', /kk_scope_namespace without kk_identity_scope_claim/, {
    credentials: [{id: 'c1', format: 'jwt_vc_json', claims: [{path: ['iss']}], kk_scope_namespace: 'issuer'}],
  })
  refused('an empty scope-claim path is refused', /empty kk_identity_scope_claim path/, scoped({kk_identity_scope_claim: []}))
  // ⚠ The scope claim must also be part of the credential MATCH, so a query cannot be
  // satisfied without the grant being present to check.
  refused('a scope claim with no matching claims entry is refused', /but has no matching claims entry for that path/, scoped({
    kk_identity_scope_claim: ['elsewhere'],
  }))
  refused('a scope claim without a namespace is refused', /but no kk_scope_namespace \(required — "issuer" or "any"\)/, scoped({
    kk_scope_namespace: undefined,
  }))
  refused('a namespace outside the enum is refused', /kk_scope_namespace must be "issuer" or "any"/, scoped({kk_scope_namespace: 'everyone'}))

  // ⚠ THE PAIRING. `"any"` grants scope over any namespace; with an OPEN issuer set anyone
  // could self-issue a credential granting scope over anyone. Refused as a combination.
  refused('"any" with an open issuer set is refused', /pairs kk_scope_namespace "any" with an open issuer set/, {
    credentials: [
      {
        id: 'grant',
        format: 'jwt_vc_json',
        claims: [{path: ['iss']}, {path: ['scopes']}],
        kk_identity_scope_claim: ['scopes'],
        kk_scope_namespace: 'any',
      },
    ],
  })
  accepted('"any" WITH a pinned issuer set is accepted', scoped({kk_scope_namespace: 'any'}))
}

// ─── satisfaction: credential_sets and the unsatisfiable report ────────────────
{
  const rule = JSON.stringify({
    credentials: [
      {id: 'emp', format: 'jwt_vc_json', claims: [{path: ['iss'], values: ['did:web:hr.example']}]},
      {id: 'gym', format: 'jwt_vc_json', claims: [{path: ['iss'], values: ['did:web:gym.example']}]},
      {id: 'opt', format: 'jwt_vc_json', claims: [{path: ['iss'], values: ['did:web:opt.example']}]},
    ],
    credential_sets: [
      {options: [['emp'], ['gym']]},
      // ⚠ `required: false` — an optional set. It must not make the whole rule unsatisfiable
      // when nothing answers it, which is the difference between "nice to have" and "required".
      {options: [['opt']], required: false},
    ],
  })
  const emp = jsonCredential({format: 'jwt_vc_json', types: ['Employee'], body: {iss: 'did:web:hr.example'}})
  const gym = jsonCredential({format: 'jwt_vc_json', types: ['Gym'], body: {iss: 'did:web:gym.example'}})

  const withEmp = select(rule, [emp])
  ok('a required set satisfied by one option is satisfied', withEmp.satisfied)
  eq('…and only that credential is selected', withEmp.credentials.length, 1)
  eq('…with the optional set left unanswered and unreported', withEmp.unsatisfied, [])
  ok('the other option also satisfies', select(rule, [gym]).satisfied)
  // Holding BOTH options still picks one — the cheapest satisfying option.
  eq('holding both options still selects one credential', select(rule, [emp, gym]).credentials.length, 1)
  // Nothing answering a REQUIRED set denies, and names every id the set could have used.
  const none = select(rule, [])
  ok('a required set with no satisfiable option denies', !none.satisfied)
  eq('…naming every id it could have been answered with', none.unsatisfied.slice().sort(), ['emp', 'gym'])
  ok('…and not naming the optional set', !none.unsatisfied.includes('opt'))

  // `evaluate` is the boolean form of the same question.
  ok('evaluate agrees with select on a satisfied rule', evaluate(rule, [emp]))
  ok('evaluate agrees on an unsatisfied rule', !evaluate(rule, []))
}

// ─── credentialMatches: formats, typing and array claims ──────────────────────
{
  const q = {id: 'c1', format: 'jwt_vc_json' as const, meta: {type_values: [['Employee', 'Staff'], ['Contractor']]}}
  const staff = jsonCredential({format: 'jwt_vc_json', types: ['Employee', 'Staff'], body: {iss: 'did:web:hr.example'}})
  const contractor = jsonCredential({format: 'jwt_vc_json', types: ['Contractor'], body: {iss: 'did:web:hr.example'}})
  const partial = jsonCredential({format: 'jwt_vc_json', types: ['Employee'], body: {iss: 'did:web:hr.example'}})

  // type_values: outer = alternatives (ANY), inner = all-required (ALL).
  ok('the first alternative matches when every inner type is held', credentialMatches(q, staff))
  ok('a second alternative matches on its own', credentialMatches(q, contractor))
  ok('holding only part of an alternative does not match', !credentialMatches(q, partial))
  // The format must match before anything else is considered.
  ok('a credential of another format never matches', !credentialMatches(q, jsonCredential({format: 'dc+sd-jwt', types: ['Employee', 'Staff'], body: {}})))

  // vct_values: any listed value matching the view's types is enough.
  const vctQ = {id: 'c1', format: 'dc+sd-jwt' as const, meta: {vct_values: ['https://example.com/A', 'https://example.com/B']}}
  ok('a vct in the list matches', credentialMatches(vctQ, jsonCredential({format: 'dc+sd-jwt', types: ['https://example.com/B'], body: {}})))
  ok('a vct outside the list does not', !credentialMatches(vctQ, jsonCredential({format: 'dc+sd-jwt', types: ['https://example.com/C'], body: {}})))

  // ⚠ With a `null` segment the resolved value is a SELECTION, so the question is "does ANY
  // selected element match ANY listed value" — the only reading under which a rule can say
  // "this role is among the holder's roles". Without one it is whole-value equality.
  const roleQ = {id: 'c1', format: 'jwt_vc_json' as const, claims: [{path: ['roles', null], values: ['reviewer']}]}
  const multi = jsonCredential({format: 'jwt_vc_json', types: [], body: {roles: ['engineer', 'reviewer']}})
  ok('a null segment matches any element', credentialMatches(roleQ, multi))
  ok('…and fails when no element matches', !credentialMatches(roleQ, jsonCredential({format: 'jwt_vc_json', types: [], body: {roles: ['engineer']}})))
  // Whole-value equality without the null: an array is NOT equal to one of its elements.
  const wholeQ = {id: 'c1', format: 'jwt_vc_json' as const, claims: [{path: ['roles'], values: ['reviewer']}]}
  ok('without a null segment it is whole-value equality', !credentialMatches(wholeQ, multi))
  // A presence-only claim (no `values`) matches whatever is there.
  ok('a presence-only claim matches any value', credentialMatches({id: 'c1', format: 'jwt_vc_json', claims: [{path: ['roles']}]}, multi))
  ok('…and fails when the claim is absent', !credentialMatches({id: 'c1', format: 'jwt_vc_json', claims: [{path: ['nope']}]}, multi))
}

// ─── identity-scoped evaluation: does a grant cover THIS identity? ────────────
{
  // The scoped rule: a grant credential from hr.example whose `scopes` claim says which
  // identities it may act for. The namespace is "issuer", so the identity's first
  // `/`-segment must byte-equal the grantor's own issuer DID — the self-grant-over-others gate.
  const rule = JSON.stringify({
    credentials: [
      {
        id: 'grant',
        format: 'jwt_vc_json',
        claims: [{path: ['iss'], values: ['did:web:hr.example']}, {path: ['scopes']}],
        kk_identity_scope_claim: ['scopes'],
        kk_scope_namespace: 'issuer',
      },
    ],
  })
  const grantOf = (scopes: unknown, iss = 'did:web:hr.example') =>
    jsonCredential({format: 'jwt_vc_json', types: ['Grant'], body: {iss, scopes}})

  // A string grant covering the identity exactly, and by segment prefix.
  ok('an exact string grant covers the identity', evaluateIdentityScoped(rule, [grantOf('did:web:hr.example/imaging')], 'did:web:hr.example/imaging'))
  ok('a `/*` grant covers a child', evaluateIdentityScoped(rule, [grantOf('did:web:hr.example/*')], 'did:web:hr.example/imaging'))
  ok('…and the prefix itself', evaluateIdentityScoped(rule, [grantOf('did:web:hr.example/*')], 'did:web:hr.example'))
  // ⚠ The segment boundary: a longer SIBLING must not be covered. `p/*` covers `p` and things
  // strictly beneath `p/`, so the byte after the prefix has to be `/`.
  ok('a sibling with a longer segment is NOT covered', !evaluateIdentityScoped(rule, [grantOf('did:web:hr.example/imag/*')], 'did:web:hr.example/imaging'))
  ok('an unrelated identity is not covered', !evaluateIdentityScoped(rule, [grantOf('did:web:hr.example/billing')], 'did:web:hr.example/imaging'))

  // ⚠ An ARRAY-valued scope claim: any element covering the identity is enough. A credential
  // carrying several grants is the normal shape, so reading only the string case would deny
  // every multi-grant credential.
  ok('an array grant matches on any element', evaluateIdentityScoped(rule, [grantOf(['did:web:hr.example/billing', 'did:web:hr.example/imaging'])], 'did:web:hr.example/imaging'))
  ok('…and denies when no element covers', !evaluateIdentityScoped(rule, [grantOf(['did:web:hr.example/billing'])], 'did:web:hr.example/imaging'))
  // A non-string, non-array grant value cannot cover anything.
  ok('a numeric grant value denies', !evaluateIdentityScoped(rule, [grantOf(42)], 'did:web:hr.example/imaging'))
  // An array holding non-strings is skipped element-wise rather than throwing.
  ok('non-string array elements are skipped', evaluateIdentityScoped(rule, [grantOf([7, 'did:web:hr.example/imaging'])], 'did:web:hr.example/imaging'))

  // ⚠ The grant claim must be PRESENT. A credential that satisfies the query but carries no
  // scope claim grants nothing — the query matched on issuer alone.
  ok('a credential with no scope claim denies', !evaluateIdentityScoped(
    JSON.stringify({credentials: [{id: 'grant', format: 'jwt_vc_json', claims: [{path: ['iss'], values: ['did:web:hr.example']}, {path: ['other']}], kk_identity_scope_claim: ['other'], kk_scope_namespace: 'issuer'}]}),
    [jsonCredential({format: 'jwt_vc_json', types: [], body: {iss: 'did:web:hr.example', other: null}})],
    'did:web:hr.example/x',
  ))

  // ⚠ The "issuer" namespace gate: the identity's first segment must equal the grantor's own
  // issuer. Otherwise anyone could issue themselves a grant over someone else's namespace.
  ok('a grantor cannot cover another issuer\'s namespace', !evaluateIdentityScoped(
    rule,
    [grantOf('did:web:other.example/*', 'did:web:hr.example')],
    'did:web:other.example/imaging',
  ))

  // A query the credentials do NOT satisfy is skipped — the loop only considers satisfied
  // queries, so an unsatisfied scoped query cannot grant.
  ok('an unsatisfied query grants nothing', !evaluateIdentityScoped(rule, [grantOf('*', 'did:web:someone-else.example')], 'did:web:hr.example/x'))

  // An unscoped rule can never authorize a scoped operation, however well it is satisfied.
  ok('a rule with no scope binding denies', !evaluateIdentityScoped(
    JSON.stringify({credentials: [{id: 'c1', format: 'jwt_vc_json', claims: [{path: ['iss'], values: ['did:web:hr.example']}]}]}),
    [grantOf('*')],
    'did:web:hr.example/x',
  ))

  // ⚠ The identity's own shape is checked BEFORE the rule parses, so an oversize or
  // NUL-bearing identity is a DENY rather than a malformed-rule throw.
  ok('an oversize identity denies rather than throwing', !evaluateIdentityScoped(rule, [grantOf('*')], 'a'.repeat(5000)))
  ok('a NUL-bearing identity denies', !evaluateIdentityScoped(rule, [grantOf('*')], 'did:web:hr.example/\0evil'))

  // scopeCovers on its own, including the explicit-open form.
  ok('`*` is the explicit-open grant', scopeCovers('*', 'anything/at/all'))
  ok('an exact match covers', scopeCovers('a/b', 'a/b'))
  ok('a prefix grant covers beneath it', scopeCovers('a/*', 'a/b/c'))
  ok('…but not a longer sibling segment', !scopeCovers('a/*', 'ab/c'))
  ok('a NUL in either side denies', !scopeCovers('a/*', 'a/\0'))
}

// ─── canonicalize (RFC 8785) and the grammar dispatch ─────────────────────────
{
  // Key order is by UTF-16 code unit, and the output is byte-stable — this is what the salted
  // rule commitment hashes, so two orderings of the same rule must commit identically.
  eq('keys are sorted', canonicalize('{"b":1,"a":2}'), '{"a":2,"b":1}')
  eq('nested objects are sorted too', canonicalize('{"b":{"d":1,"c":2},"a":3}'), '{"a":3,"b":{"c":2,"d":1}}')
  eq('array order is preserved', canonicalize('[3,1,2]'), '[3,1,2]')
  eq('booleans and null canonicalise', canonicalize('{"t":true,"f":false,"n":null}'), '{"f":false,"n":null,"t":true}')
  eq('numbers use the JS algorithm RFC 8785 chose', canonicalize('{"n":1.0}'), '{"n":1}')
  eq('an exponent is normalised', canonicalize('{"n":1e2}'), '{"n":100}')
  eq('strings keep JSON escaping', canonicalize('{"s":"a\\"b"}'), '{"s":"a\\"b"}')
  eq('whitespace is removed', canonicalize('{ "a" : 1 }'), '{"a":1}')
  // ⚠ `JSON.parse` happily produces Infinity from an out-of-range exponent, and Infinity is
  // NOT a JSON number — so it cannot be canonicalised and must be refused rather than
  // serialised as `null` (which is what JSON.stringify would do, silently changing the rule
  // the commitment covers).
  try {
    canonicalize('{"n":1e999}')
    ok('an out-of-range exponent is refused', false, 'was accepted')
  } catch (error) {
    ok(
      'an out-of-range exponent is refused as not-a-JSON-number',
      error instanceof DcqlMalformedError && /Infinity is not a JSON number/.test(String(error)),
      `message was ${JSON.stringify(String(error))}`,
    )
  }
  // A non-JSON input is a malformed rule, not a crash.
  try {
    canonicalize('{nope')
    ok('canonicalize refuses non-JSON', false, 'was accepted')
  } catch (error) {
    ok('canonicalize refuses non-JSON, naming the parse error', error instanceof DcqlMalformedError && /rule is not valid JSON/.test(String(error)))
  }

  // ⚠ The grammar dispatch the commitment uses. It must be TOTAL — never throw — because the
  // commitment falls back to raw bytes for anything that is not an OID4VP rule, and a throw
  // here would make a valid kk-DCQL rule uncommittable.
  ok('an OID4VP rule is recognised', isOid4vpRule('{"credentials":[{"id":"c1","format":"jwt_vc_json","claims":[{"path":["iss"]}]}]}'))
  ok('a kk-DCQL string is not', !isOid4vpRule('verify:demo'))
  ok('the universal grant is not', !isOid4vpRule('any'))
  ok('an empty string is not', !isOid4vpRule(''))
  ok('malformed JSON is not, and does not throw', !isOid4vpRule('{not json'))
  ok('a JSON array is not', !isOid4vpRule('[]'))
  // A rule that parses as JSON but fails validation is not an OID4VP rule either — the
  // dispatch is about admissibility, not about resembling one.
  ok('a JSON object with no credentials is not', !isOid4vpRule('{"foo":1}'))
}

if (failures.length > 0) {
  console.error(`✗ oid4vp.dcql-validation: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ oid4vp.dcql-validation: ${passed} checks passed`)
