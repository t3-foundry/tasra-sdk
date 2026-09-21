---
name: tasra-hovi-issuer
description: Get the credentials a Tasra slot rule can be satisfied with, using Hovi — sign up for the Hovi Studio trial, create an organization and its issuer DID, get the OpenID ecosystem API key, create an SD-JWT credential template and issue credentials through the Hovi Business Wallet API, then receive them with tasra-sdk and pin the issuer in a DCQL rule. Use for "how do I get a credential", "Hovi", "Hovi Studio", "issuer", "credential template", "issue a credential to a wallet", "trial account", "no credentials to test with".
metadata:
  package: tasra-sdk
  sources:
    - https://docs.hovi.id/intro/quickstart
    - https://hovi.blob.core.windows.net/api-swagger/1.0.0/open-id.json
    - docs/api.md
    - dist/oid4vp/oid4vci.d.ts
---

# Getting credentials from Hovi

Nothing credential-gated in Tasra runs without an issuer: `vpJwt`
sessions, the committee path, the Verifier Agent and the wallet flow all present
verifiable credentials. Hovi is the issuer and wallet platform the SDK's
OpenID4VC implementation mirrors, so a Hovi trial is the fastest way to have
real credentials to test against. Everything here is Hovi's API, not the SDK's;
the SDK enters at the end, when the holder receives the credential.

Facts marked *observed* were true for a trial account on 2026-09-11 and may
change with Hovi's plans.

## 0. Do you need Hovi at all?

- **Unit tests and local demos:** `issueSdJwtVc` in `tasra-sdk/oid4vp`
  issues a valid SD-JWT VC offline from a key you generate (see
  `tasra-oid4vp-wallet-and-verifier-agent`). No account needed.
- **A wallet a human can scan, or issuer trust that survives a restart:** Hovi.
- **Hovi-compatible without the cloud:** a local implementation of the same
  API subset exists in the platform's health demo (`/api/issuer`, keys start
  with `openId-local-`); the client below works against it by changing the
  base URL, and the trial limits do not apply there.

## 1. Trial account

1. Open `https://studio.hovi.id/`, click **Get started**, create the account.
2. *Observed trial limits:* **2 organizations, 1 credential template each**,
   and **credential revocation disabled** (`POST /credential/revoke` answers
   403 "not available during the trial period"). Exceeding a limit answers
   403 with a message containing "limit exceeded".

## 2. Organization and issuer DID

In Studio: **Organizations → Create Organization**. On creation the
organization's secret and DID seed phrase are shown **once**; copy them.

Or through the API:

```http
POST https://api.hovi.id/organization/create
Authorization: Bearer <OPENID_ECOSYSTEM_API_KEY>
Content-Type: application/json

{"name": "Acme HR", "label": "acme-hr", "secret": "<your secret>", "imageUrl": "https://…/logo.png"}
```

The 201 response carries the organization id, a tenant id, an access token and
the organization's DIDs, each with its private key — returned **only in this
response**. Store it like a signing key. `GET /organization/` lists your
organizations without secrets:

```json
{"success": true, "response": [{
  "organizationId": "ff64…", "tenantId": "…", "name": "Acme HR",
  "dids": [{"did": "did:key:zDna…", "method": "key"}],
  "openIdWellKnownCredentialIssuerUrl": "https://core-agent.hovi.id/oid4vci/ff64…/.well-known/openid-credential-issuer"
}]}
```

The organization's first DID is the **issuer DID**: it is what a Tasra
rule pins with `{"path": ["iss"], "values": ["<issuer DID>"]}`. It is the same
value that later appears as the credential's `iss` claim; decoding that claim
is a check, not a second source.

## 3. API key and request shape

Studio → **API Keys** → *Active API Keys*. Use the **OpenID ecosystem** key;
it starts with `openId-`. Every call:

- `Authorization: Bearer <key>`
- `x-organization-id: <organization id>` on every call except `/organization/*`
- base URL `https://api.hovi.id`; configure your app with `HOVI_API_KEY`, an
  optional `HOVI_BASE_URL` (the local Hovi-compatible issuer, for instance), and
  the organization and template it works with — the demo deployment's env names
  them `HOVI_ORGANIZATION_NAME` (matched against `GET /organization/`, whose
  `organizationId` is the header value) and `HOVI_TEMPLATE_SCHEMA_TYPE` (a
  template's `schemaType`)
- JSON envelope in every reply: `{"success": true, "response": …}` or
  `{"success": false, "message": "…"}`; check `success`, not only the status.

Keep the key server-side. It is an issuance authority; anyone holding it can
mint credentials your slots trust.

## 4. Credential template

One template per credential type. Its `schemaType` becomes the SD-JWT `vct`
that a DCQL rule matches; use `dc+sd-jwt`, and give every attribute a type
(`string`, `number`, `list`). Give credentials a numeric `exp` claim in Unix
seconds — declare `exp` among the template's attributes, since `credentialValues`
fills those. Rules need not mention it: a wallet drops an expired credential
from its plan before the rule is evaluated.

```http
POST https://api.hovi.id/credential-template/sd-jwt/create
Authorization: Bearer <key>
x-organization-id: <organization id>
Content-Type: application/json

{
  "name": "Acme Employee",
  "version": "1.0.0",
  "schemaType": "EmployeeOf",
  "description": "Employment credential issued by Acme HR",
  "sdJwtHeader": "dc+sd-jwt",
  "supportRevocation": true,
  "attributes": [
    {"name": "dept",  "label": "Department", "type": "string", "description": "Department", "required": true},
    {"name": "level", "label": "Level",      "type": "number", "description": "Seniority",  "required": true},
    {"name": "exp",   "label": "Expires at", "type": "number", "description": "Unix seconds", "required": true}
  ]
}
```

The response is the template; `GET /credential-template/organization` (with
the organization header) lists them:

```json
{"success": true, "response": [{
  "credentialTemplateId": "ede0…", "credentialConfigurationId": "…", "tenantId": "ff64…",
  "name": "Acme Employee", "schemaType": "EmployeeOf", "type": "sd-jwt", "sdJwtHeader": "dc+sd-jwt",
  "supportRevocation": true,
  "attributes": [{"name": "dept", "type": "string", "required": true}, {"name": "exp", "type": "number", "required": true},
                 {"name": "holderDid", "type": "string", "required": false}]
}]}
```

Templates may carry an optional `holderDid` attribute; fill it at issuance to
pin the credential to one holder, which means the holder key has to exist
first — `randomHolderKey()` (§5), then `holderDid: holder.did`. Studio's
**Credential Templates → Create Template** does the same by hand.

## 5. Issue a credential

```http
POST https://api.hovi.id/credential/sd-jwt/offer
Authorization: Bearer <key>
x-organization-id: <organization id>
Content-Type: application/json

{
  "credentialTemplateId": "<template id>",
  "credentialValues": {"dept": "Engineering", "level": 3, "exp": 1790000000},
  "codeflow": "pre-authorized"
}
```

The response looks like this (ids shortened; the `//` notes are not part of it):

```jsonc
{"success": true, "response": {
  "credentialExchangeId": "b1f0…",                                   // the handle for find and revoke — keep it
  "credentialOfferUri": "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fcore-agent.hovi.id%2F…",
  "credentialOfferUrl": "https://…/qr/…",                            // a page showing the QR for a wallet
  "state": "pending", "isRevoked": false, "credentialType": "EmployeeOf"
}}
```

The offer is not the credential; a wallet redeems the offer URI. The exchange
state is `pending` until then and `done` once a wallet has redeemed it. `GET /credential/find?credentialExchangeId=…` returns an
**array**: `[{"credentialExchangeId": "…", "state": "done", "isRevoked": false}]`.

### The holder receives it with the SDK

```ts
import {randomHolderKey, receiveCredential} from 'tasra-sdk/oid4vp'

const holder = randomHolderKey()                                   // or the holder's persisted P-256 key
const {credential, issuer, format, configurationId} = await receiveCredential({offerUri: offer.credentialOfferUri, holder})
// credential: the compact SD-JWT VC (dc+sd-jwt) bound to holder.did
// issuer: the OpenID4VCI credential_issuer URL — NOT the DID. The issuer DID a rule pins is the
// credential's `iss` claim (the JWS `kid` carries it too): decode the first ~-separated segment.
const issuerDid = JSON.parse(Buffer.from(credential.split('~')[0]!.split('.')[1]!, 'base64url').toString()).iss as string   // throws on a malformed string
```

`receiveCredential` runs the OpenID4VCI pre-authorized flow the Hovi Wallet
runs: offer, issuer metadata, token, proof of possession, credential. It follows
whatever URLs the offer and the issuer metadata carry, `http://` included, so
the local Hovi-compatible issuer needs no opt-in: `ReceiveCredentialOpts` has no
switch for it, and `allowInsecureLoopback` belongs to `did:web` resolution on
the presentation side. A human with the Hovi Wallet scans the QR page from the
offer response instead.

## 6. Use it against Tasra

Write the slot rule for the template, pinning the issuer:

```json
{"credentials": [{
  "id": "e", "format": "dc+sd-jwt",
  "meta": {"vct_values": ["EmployeeOf"]},
  "claims": [{"path": ["iss"], "values": ["<issuer DID>"]}, {"path": ["dept"], "values": ["Engineering"]}]
}]}
```

Validate and canonicalise the rule string with `validateDcql` /
`canonicalizeDcql` from `tasra-sdk` (see `tasra-dcql-rules`; every
DCQL function takes the rule as a JSON string), and check the credential you
received against it before relying on it:

```ts
import {evaluateDcql} from 'tasra-sdk'
import {parseSdJwt, sdJwtCredentialView} from 'tasra-sdk/oid4vp'

// The view's `types` is [vct]; its claims are the issuer payload plus every disclosure, so `dept` resolves
// at ["dept"]. Build it with this, never by hand: a disclosed claim is not in the issuer JWT's payload.
const ok = evaluateDcql(rule, [sdJwtCredentialView(parseSdJwt(credential))])
```

Then either open a session with it —
`kk.openSession(slotId, {vpJwt: {dcqlRule, credentials: [credential], holderProof}})`
(`tasra-credentials-and-sessions`) — or let a wallet present it to the
Verifier Agent (`tasra-oid4vp-wallet-and-verifier-agent`), or use the committee path
(`tasra-committee-path`). The keepers accept the credential because the
verified issuer matches the rule; Hovi's own status lists
(`https://revocation.hovi.id`, `statuslist+jwt`) are **not** checked by the
SDK, so an application that needs revocation must verify them itself.

## Minimal server-side client (yours, not the SDK's)

```ts
async function hovi<T>(baseUrl: string, key: string, path: string, org?: string, body?: unknown): Promise<T> {
  const r = await fetch(baseUrl.replace(/\/$/, '') + path, {
    method: body === undefined ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(20_000),
    headers: {Authorization: `Bearer ${key}`, Accept: 'application/json', ...(org ? {'x-organization-id': org} : {}), ...(body !== undefined ? {'Content-Type': 'application/json'} : {})},
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await r.text()   // not r.json(): a wrong base URL answers HTML, and a SyntaxError loses the status
  let env: {success?: boolean; message?: string; response?: T}
  try { env = JSON.parse(text) } catch { throw new Error(`Hovi ${path} → HTTP ${r.status}, not JSON: ${text.slice(0, 200)}`) }
  if (!r.ok || env.success !== true) throw new Error(`Hovi ${path} → HTTP ${r.status}: ${env.message ?? ''}`)
  return env.response as T
}
```

## Common mistakes

- ❌ Using a key from another ecosystem. Only the OpenID key (`openId-…`)
  serves this API.
- ❌ Omitting `x-organization-id` on template and credential calls.
- ❌ Treating the offer response as the credential. The wallet, or
  `receiveCredential`, redeems the offer URI.
- ❌ Expecting revocation on a trial account. It answers 403; plan the
  revocation test for a paid plan, or use time-boxed `exp` values meanwhile.
- ❌ Putting the API key in a browser bundle. Issue from a server.
- ❌ `exp` in milliseconds. It is Unix seconds, kept verbatim in the credential.
- ❌ Pinning the wrong DID. The issuer DID is the organization's DID from
  `GET /organization/`, not the holder's, not the tenant id.
- ❌ Creating a third organization or a second template per organization on
  the trial. It fails with "limit exceeded".

## Where to read more

- Hovi quick start: `https://docs.hovi.id/intro/quickstart`; API reference:
  `https://docs.hovi.id/api/open-id`; the OpenAPI contract:
  `https://hovi.blob.core.windows.net/api-swagger/1.0.0/open-id.json`.
- SDK receive side: `node_modules/tasra-sdk/dist/oid4vp/oid4vci.d.ts`
  (`ReceiveCredentialOpts`, `ReceivedCredential`).
