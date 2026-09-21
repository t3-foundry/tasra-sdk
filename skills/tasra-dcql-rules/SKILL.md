---
name: tasra-dcql-rules
description: Write, validate, canonicalise and evaluate a Tasra slot access rule in OID4VP-DCQL with tasra-sdk — the required shape, the mandatory issuer entry, validateDcql, evaluateDcql, selectDcql, canonicalizeDcql, the rule commitment, identity-scoped rules, and oauth+access-token+dpop rules for your own identity provider. Use for "DCQL", "access rule", "dcqlRule", "DcqlMalformedError", "credential_sets", "ruleCommitment", "oauth rule", "DPoP", "max_age_secs", "bring your own IdP".
metadata:
  package: tasra-sdk
  sources:
    - docs/capabilities.md
    - dist/auth/oid4vp.d.ts
    - dist/chain/write.d.ts
    - dist/committee/oauth.d.ts
---

# DCQL rules

A slot's access policy is a DCQL query (the OpenID Foundation's Digital
Credentials Query Language, as used by OpenID4VP). The rule *is* the wallet
request: what the policy asks for is exactly what a wallet is asked to present.
The SDK's evaluator mirrors the network's reference implementation and is pinned
to it by a shared conformance corpus.

## Shape of a rule

```json
{
  "credentials": [{
    "id": "e",
    "format": "jwt_vc_json",
    "meta": {"type_values": [["EmployeeOf"]]},
    "claims": [
      {"path": ["iss"], "values": ["did:web:hr.acme.example"]},
      {"path": ["credentialSubject", "dept"], "values": ["Engineering"]}
    ]
  }]
}
```

Rules that the validator enforces:

- Every credential query must carry an issuer constraint: a `claims` entry with
  path exactly `["iss"]`. With `values` it pins the accepted issuers; without
  `values` it explicitly accepts any verifiable issuer. A rule without it throws
  `DcqlMalformedError` with a message that names the credential id and says to
  add the entry.
- `format` is one of **three** values; any other is rejected as malformed.
  `jwt_vc_json` matches `meta.type_values` (`[["EmployeeOf"]]`), `dc+sd-jwt` matches
  `meta.vct_values` (`["EmployeeOf"]`), and `oauth+access-token+dpop` authorizes with an
  access token from the slot owner's own identity provider (see below). **Claim paths
  follow the format**: a `jwt_vc_json` credential nests its subject claims
  (`["credentialSubject", "dept"]`, as above), while an SD-JWT VC carries them at the
  top level (`["dept"]`). Copying the nested path into a `dc+sd-jwt` rule produces a
  rule nothing can satisfy, and it fails at the verifier, not at `validateDcql`.
- A claim entry with `values` matches on JSON equality (`"3"` does not match `3`).
  `values` is a **set of accepted values**, so one rule can admit several distinct
  holders — `{"path":["sub"],"values":["did:demo:alice","did:demo:bob"]}` lets either
  of them satisfy the query on their own. That is how several people share one slot
  (one treasury EOA, one archive) without sharing key material and without either
  needing the other's consent; it is *not* a quorum — for "two must approve", see the
  dual-control policy in `tasra-sign-and-decrypt`.
- Several credentials are combined with `credential_sets`; absent, every listed
  credential is required.
- Whole rule ≤ `DCQL_MAX_RULE_LEN` (4096 bytes, measured on the raw text before
  parsing; the constant is exported from `tasra-sdk`).
- Identity-scoped rules add `kk_identity_scope_claim` and `kk_scope_namespace` —
  see the next section; a slot that serves IBE extraction needs them.

## OAuth rules — bring your own identity provider

A rule may authorize with an access token your users already hold from your own IdP,
sender-constrained with DPoP (RFC 9449), instead of a verifiable credential. It is
ordinary DCQL over the token's own claims — the format is the only thing that changes:

```json
{"credentials": [{
  "id": "t",
  "format": "oauth+access-token+dpop",
  "meta": {"max_age_secs": 300},
  "claims": [
    {"path": ["iss"], "values": ["https://idp.example.com/realms/acme"]},
    {"path": ["aud", null], "values": ["https://agent.example/authz/43113"]},
    {"path": ["realm_access", "roles", null], "values": ["tasra-user"]}
  ]
}]}
```

⚠ **Four extra constraints are MANDATORY here, and each throws `DcqlMalformedError`.**
An access token is a bearer-shaped artifact from a tenant's own IdP with none of a
credential's trust scaffolding — no issuer registry, no status list, and an audience the
IdP chooses — so the rule is the only place any of it can be pinned:

1. **The issuer set must be pinned.** The `["iss"]` entry needs `values`; the
   "explicitly open" form that is fine for credentials would mean "any IdP on the
   internet willing to mint a token naming our audience". Each value must be `https://`
   and carry no query or fragment — the issuer is concatenated with
   `/.well-known/openid-configuration` and compared byte-for-byte at discovery.
2. **The audience must be constrained** — a claims entry with path exactly
   `["aud", null]` and non-empty `values`. Without it, a token minted for another
   relying party of the same IdP authorizes here: the classic confused deputy.
3. **`meta.max_age_secs` is required**, within `1..=86400`. There is no status list for
   an access token, so freshness *is* the revocation signal: a leaver's session stops
   minting tokens, and this bounds how long an already-minted one keeps working.
4. **`type_values` / `vct_values` are forbidden.** An access token has no credential
   type, and accepting them would let a rule look constrained while constraining nothing.

Derive the audience rather than typing it: `platformAudience(origin, chainId)` from
`tasra-sdk/committee`, which also has the DPoP `htu` derivation. `isOauthFormat(format)`
tells you whether a format is in this family.

**Authorizing against such a slot is a different surface**, not `openSession`: it runs
through the verifier agent as an `oauth` session kind — see
`tasra-oid4vp-wallet-and-verifier-agent`.

## Identity-scoped rules

A plain rule answers *who* may operate. An identity-scoped rule also answers *which
identity they may operate on*, and it is what IBE extraction requires: against a plain
rule every keeper refuses an extraction with HTTP 403 `rule carries no identity-scope
binding on any satisfied credential query; it cannot authorize an identity-scoped
operation` (`tasra-ibe-identity-scoped`).

```json
{
  "credentials": [{
    "id": "officer",
    "format": "dc+sd-jwt",
    "meta": {"vct_values": ["EmployeeOf"]},
    "claims": [
      {"path": ["iss"], "values": ["did:web:hr.acme.example"]},
      {"path": ["dept"], "values": ["Procurement"]},
      {"path": ["scope"]}
    ],
    "kk_identity_scope_claim": ["scope"],
    "kk_scope_namespace": "issuer"
  }]
}
```

- `kk_identity_scope_claim` is the **path** of the claim carrying this holder's grant.
  It must **also appear under `claims`** — as `{"path": ["scope"]}` does above, with no
  `values`, so any grant matches — or the rule is malformed: a query must not be
  satisfiable without the grant being present to check.
- `kk_scope_namespace` is required alongside it and is `"issuer"` or `"any"`.
  Under `"issuer"` the requested identity's **first `/`-segment must byte-equal the
  credential's verified `iss`**, so identities root at whoever granted them —
  `did:web:hr.acme.example/tender/acme-rfp-014/2026-Q4` for the rule above.
  `"any"` lifts that gate and therefore requires a pinned issuer set (`values` on the
  `["iss"]` entry), or anyone could self-issue a credential granting scope over anyone.
- The **grant grammar is three forms and nothing else** (`scopeCovers`, exported):
  `g` covers exactly `g`; `p/*` covers `p` and anything strictly beneath `p/`; bare
  `*` covers everything. The `/` boundary is load-bearing — `patient:12/*` does **not**
  cover `patient:123`. No mid-path wildcards, no regex. A grant or identity over
  `MAX_IDENTITY_LEN` (1024 bytes, exported) or containing NUL matches nothing.

```ts
import {evaluateIdentityScoped, scopeCovers, MAX_IDENTITY_LEN} from 'tasra-sdk'

scopeCovers('did:web:hr.acme.example/tender/*', 'did:web:hr.acme.example/tender/acme-rfp-014/2026-Q4')  // true
scopeCovers('did:web:hr.acme.example/tender/acme-rfp-099/*', 'did:web:hr.acme.example/tender/acme-rfp-014')  // false
evaluateIdentityScoped(rule, views, identity)   // the whole check: rule + credentials + this identity
```

Because the rule is committed at slot creation, an IBE slot must be created with the
scope binding already in it (`tasra-create-slot`).

## Using the evaluator

Every function takes the rule as **JSON text (a string)**, never as an object.

```ts
import {validateDcql, evaluateDcql, selectDcql, canonicalizeDcql, jsonCredential, DcqlMalformedError} from 'tasra-sdk'
import type {CredentialView, DcqlQuery, DcqlSelection} from 'tasra-sdk'   // DcqlQuery types the object BEFORE you JSON.stringify it

const rule = JSON.stringify({credentials: [/* as above */]})   // or the raw JSON string you store

try { validateDcql(rule) } catch (e) { if (e instanceof DcqlMalformedError) showError(e.message) }

// A CredentialView is built from a decoded credential: `types` is matched against
// meta.type_values, and claim paths such as ["iss"] or ["credentialSubject","dept"]
// resolve against `body`. `decoded` here is the parsed JWT-VC payloads:
// Array<{iss: string, vc: {type: string[], credentialSubject: Record<string, unknown>}}>
const views: CredentialView[] = decoded.map(p =>
  jsonCredential({format: 'jwt_vc_json', types: p.vc.type, body: {iss: p.iss, ...p.vc}}),
)
const ok    = evaluateDcql(rule, views)     // boolean: do these credentials satisfy the rule?
const pick  = selectDcql(rule, views)       // {satisfied, credentials, unsatisfied}: `credentials` are the
                                            // same view objects you passed in (the minimal satisfying set),
                                            // `unsatisfied` the credential-query ids nothing satisfied;
                                            // with no credentials, `satisfied: false` and every query id
                                            // in `unsatisfied`
const canon = canonicalizeDcql(rule)        // string: RFC 8785 form — what is committed on-chain
```

`evaluateIdentityScoped(rule, views, identity)` is the identity-scoped variant
(see `tasra-ibe-identity-scoped`). `RecipientStore` / `canAccess` gate a
recipient's own store against a rule client-side.

## The rule commitment

The chain never stores the rule, only `ruleCommitment(salt, rule)` from
`tasra-sdk/chain`, a salted hash over the canonical bytes. `createSlot`
mints the salt and returns it; `verifyRuleCommitment(dcqlRule, ruleSalt, onChainRuleCommitment)`
checks a candidate rule against a slot. The clear rule is provisioned to the
keepers separately (see `tasra-create-slot`).

## Common mistakes

- ❌ Passing the rule as an object. Every function wants the JSON string.
- ❌ Omitting the `["iss"]` entry. The rule is rejected as malformed.
- ❌ Writing `["issuer"]` or a nested issuer path. Only exactly `["iss"]` counts.
- ❌ Expecting `"3"` to match `3`, or whitespace/key order to change the
  commitment. Values compare as JSON; canonicalisation removes formatting.
- ❌ Listing two entries under `credentials` without `credential_sets`: that
  requires both in one presentation, and wallets present one credential at a
  time. Declare `credential_sets` with single-credential options instead.
- ❌ Evaluating an identity-scoped rule with plain `evaluateDcql`. It refuses;
  use `evaluateIdentityScoped`.
- ❌ Naming a claim in `kk_identity_scope_claim` that is not also in `claims`.
  `DcqlMalformedError`: the grant has to be part of the match.
- ❌ Expecting a scope grant to be a prefix match. `p` does not cover `p/x`; write
  `p/*`. And `p/*` never reaches a longer sibling segment.
- ❌ Writing an identity that does not start with the granting issuer's DID under
  `kk_scope_namespace: "issuer"`. The committee authorizes nothing.
- ❌ Writing an `oauth+access-token+dpop` query the way you would a credential one —
  leaving `["iss"]` open, omitting `["aud", null]`, forgetting `meta.max_age_secs`, or
  carrying `type_values`. All four are malformed for this format specifically; the
  relaxations that are safe for a credential are not safe for a bearer token.

## Where to read more

- `node_modules/tasra-sdk/dist/auth/oid4vp.d.ts` for `Query`, `CredentialView`,
  `Selection`, `ValidateOptions` — re-exported from `tasra-sdk` as `DcqlQuery`,
  `CredentialView`, `DcqlSelection`. `types` may be a superset of a `type_values`
  option; `body` needs only the keys the rule's claim paths reference.
