---
name: tasra-credentials-and-sessions
description: Obtain and refresh the DCQL-gated JWT a Tasra session needs — the four SessionAuth modes, renewal tokens, redemption tokens, presenting verifiable credentials with a holder proof, admin issuance, revocation, JWT expiry checks, and why an IdP access token is NOT a SessionAuth mode but an oauth verifier-agent session. Use for "renewalToken vs redemptionToken", "vpJwt", "holder proof", "createHolderProof", "issueAdminCredential", "JWT expired", "revokeSlotUser", "oauth session vs openSession", "access token auth".
metadata:
  package: tasra-sdk
  sources:
    - docs/api.md
    - docs/architecture.md
    - dist/auth/verifier.d.ts
    - dist/auth/holderProof.d.ts
---

# Credentials and sessions

A keeper node releases shards or signs only for a short-lived JWT minted by a
verifier after checking credentials against the slot's DCQL rule. The managed
`Session` handles the JWT; this skill is about how you obtain it.

## The four auth modes for `openSession(slotId, auth)`

| Mode | You pass | Renews itself? | Use when |
|---|---|---|---|
| `{renewalToken}` | a long-lived renewal grant | **yes** | services and apps that stay open |
| `{redemptionToken}` | a single-use grant | no | onboarding, invites, scripts |
| `{vpJwt: {dcqlRule, credentials, holderProof}}` | signed VCs + proof-of-possession | no | wallet-held credentials |
| `{jwt}` | a JWT you obtained yourself | no | you drive the verifier directly |

Only `{renewalToken}` re-mints silently. The others resolve once; on expiry
`encrypt`/`decrypt`/`sign` fail loud and you open a new session.

⚠ **There is no `{oauth}` mode, and adding one would be wrong.** A slot can be authorized
by an access token from your own identity provider, DPoP-bound — but that is not a
`SessionAuth`. It runs through the **verifier agent** as an `oauth` *session kind*
(`createOauthSession` / `submitOauthResponse`), which yields a compound token for the
committee path rather than a JWT for `openSession`. Two different surfaces:

| You hold | Route | Yields |
|---|---|---|
| A renewal/redemption token, VCs, or a JWT | `openSession(slotId, auth)` — this skill | a session with `encrypt`/`decrypt`/`sign` |
| An access token from your own IdP | `createOauthSession` — `tasra-oid4vp-wallet-and-verifier-agent` | a compound token for the committee path |

Which one a slot accepts is decided by its rule: a rule naming the
`oauth+access-token+dpop` format takes the second route and nothing else
(`tasra-dcql-rules`). Reaching for `openSession` on such a slot fails at
authorization, not at compile time.

```ts
import {createTasraClient} from 'tasra-sdk'

const kk = createTasraClient({        // construction contacts nothing; config is validated in openSession
  nodes: ['https://node-1', 'https://node-2', 'https://node-3'],
  verifier: 'https://verifier',           // required for every mode except {jwt}
  identity: 'did:example:alice',          // the holder DID; REQUIRED for {redemptionToken} and {vpJwt}, harmless otherwise
})
const s = await kk.openSession(slotId, {renewalToken})
s.jwt                                     // the current JWT (auto-renewed under {renewalToken})
await s.ensureFresh()                     // renew now if near expiry; zero I/O otherwise
```

Renewal is lazy — `ensureFresh` runs before each `encrypt`/`decrypt`/`sign` and
re-mints only when the JWT is near expiry; no timers are held, so a CLI exits
on its own. `await s.close()` zeroizes the key and `await kk.closeAll()` closes
every session — both return `Promise<void>`.

## Getting the tokens

```ts
import {
  redeemCredential, redeemRenewalToken, createRenewal, revokeRenewal,
  issueAdminCredential, revokeSlotUser, decodeJwtClaims, jwtExpMs, isJwtExpiringSoon,
  type RedemptionGrant, type IssuedToken, type RenewalGrant, type JwtClaims,
} from 'tasra-sdk'

// `verifierUrl` is the verifier's base URL (a string) in every call below.

// operator-side: mint a redemption grant for a holder (needs the verifier's admin secret — a
// deployment that publishes none has no admin path at all; see the common mistakes below).
// `scopes` (non-empty) are rule strings the grant may satisfy — pass the slot's DCQL rule exactly as
// it was provisioned to the keepers. ttlSecs is optional (default 600).
const grant: RedemptionGrant =                             // {redemptionToken, expiresAt: Unix SECONDS}
  await issueAdminCredential(verifierUrl, adminSecret, {scopes: [dcqlRule], slotIds: [slotId], ttlSecs: 3600})

// holder-side: exchange it for a JWT (the managed client does this for {redemptionToken})
// the third argument is the recipient DID — exactly what config.identity supplies in {redemptionToken}
// mode (and what it sends as `holder` in {vpJwt} mode), so keep the two the same DID.
const issued: IssuedToken = await redeemCredential(verifierUrl, grant.redemptionToken, 'did:example:alice')
// issued.token, issued.holder, issued.exp (Unix SECONDS — jwtExpMs(issued.token) gives milliseconds)
const s2 = await kk.openSession(slotId, {jwt: issued.token})   // …or hand the JWT straight to a session

// long-lived access: a renewal grant, later redeemed as often as needed.
// This one argument is the POST /v1/renewals body, so its keys really are snake_case:
// {dcql_rule: string; presentation: unknown; credentials?: string[]; slot_ids?: string[]}
const renewal: RenewalGrant = await createRenewal(verifierUrl, {      // → {renewalToken, holder, expiresAt, scopes}
  dcql_rule: dcqlRule,
  presentation: {                        // described claims, not signatures
    holder: 'did:example:alice',
    credentials: [{issuer: 'did:web:hr.acme.example', credential_type: 'EmployeeOf', claims: {dept: 'Engineering'}}],
  },
  credentials: [signedJwtVc],            // compact JWS, signature-verified; replaces the presentation's
  slot_ids: [slotId],                    // optional; these slots are rotated when the renewal is revoked
})
// `presentation` is typed `unknown`, so TypeScript checks nothing there: /v1/renewals accepts only
// `holder` and `credentials` inside it, and no `holder_proof` — that field is flat on /v1/verify-vp-jwt,
// which takes no presentation object at all. Top-level `credentials` are optional in the type but are
// the production path: they carry the signatures the verifier checks against its trust anchor. There is
// NO admin-minted renewal grant: a script without signed VCs uses {redemptionToken} or {jwt} instead.
const fresh = await redeemRenewalToken(verifierUrl, renewal.renewalToken)                          // IssuedToken
await revokeRenewal(verifierUrl, renewal.renewalToken)

// revoke a holder's access to a slot; rotate: true re-keys so old keys stop working
await revokeSlotUser(verifierUrl, adminSecret, {slotId, did: 'did:example:alice', rotate: true})
```

`JwtClaims` carries optional `iss`, `sub`, `aud` (strings), `exp` and `iat`
(Unix seconds) and `scope` (`string | string[]`), plus an index signature for
whatever else the verifier put in the token.
`decodeJwtClaims(jwt): JwtClaims | null`, `jwtExpMs(jwt): number | null` and
`isJwtExpiringSoon(jwt, skewMs = 30_000): boolean` are client-side inspection for
UX only; the first two return `null` for a malformed token or a missing `exp`,
and `isJwtExpiringSoon` returns `false` in that case (it is not fail-safe).
They never verify a signature.

## Presenting verifiable credentials (`vpJwt`)

Verifiers that require holder binding demand a proof-of-possession signed by
the holder DID's authentication key, bound to a fresh nonce from that verifier:

```ts
import {createHolderProof, ed25519DidKey} from 'tasra-sdk'
import {ed25519} from '@noble/curves/ed25519'

// The holder DID is NOT a free choice — see "Which holder DID" below.
const did = ed25519DidKey(ed25519.getPublicKey(holderSeed))   // did:key for an Ed25519 key
const signer = {alg: 'EdDSA', did, secretKey: holderSeed} as const   // a HolderSigner, in full
const holderProof = {signer, audience: 'your-verifier-iss', slotId}
const s = await kk.openSession(slotId, {vpJwt: {dcqlRule, credentials, holderProof}})
```

`signer` is a `HolderSigner`, which is either of two plain objects — no factory
involved:

```ts
{alg: 'EdDSA', did, secretKey: Uint8Array, kid?}                       // the SDK signs
{alg: 'EdDSA' | 'ES256', did, sign: (input: Uint8Array) => …, kid?}    // an HSM, wallet or agent signs
```

`createHolderProof(verifierUrl, {signer, audience, credentials, slotId})` builds the
proof string directly when you are not going through the managed client. On the wallet
side the equivalent object is a `HolderKey` from `ed25519HolderKey(seed)` /
`randomHolderKey()` / `p256HolderKey(seed)` in `tasra-sdk/oid4vp` — a different type
for a different job (KB-JWTs), so do not mix them up.

### Which holder DID

A verifier enforces a configured **DID-method accept-list**, and the holder DID has to
agree with the key that signs the proof. Two refusals, in order:

- `HTTP 401 holder proof rejected: holder DID method not accepted: <did>` — the method
  is not on the list. `did:example:` and `did:demo:` never are. Deployments typically
  accept `did:key`, and may accept `did:jwk`, `did:web` or `did:pkh`.
- `HTTP 403 credentials[0]: holder binding violated` — the method passed, but the
  credential's `sub` is a different DID than the proof's holder.

So the holder DID, the holder key and the credential's `sub` are one decision, not
three. For `did:key` the DID is self-certifying: derive it from the key first with
`ed25519DidKey`, then have the credential issued **to** that DID. With the platform CLI
that is `tasra-cli vc issue-sd-jwt --holder <did:key…> --holder-key <same seed>`;
`--holder-key` is what makes the two agree, since without it the issuer mints a fresh
holder key and the binding check fails. The `did:example:alice` used as a readable
placeholder elsewhere in these skills is exactly what a real verifier turns away.

A proof is bound to one verifier's nonce and consumed atomically. One proof
cannot be fanned out to several verifiers; for the committee path use
`holderProofPerVerifier` from `tasra-sdk/committee`.

## Common mistakes

- ❌ Reusing a redemption token. It is single-use; keep the JWT or use a renewal.
- ❌ Treating `decodeJwtClaims` as verification. Signatures are checked by the
  nodes and the verifier, never client-side.
- ❌ Expecting first-credential issuance to be self-serve. `issueAdminCredential`
  and `revokeSlotUser` are the only two calls here that take an admin secret, and
  both send it as `X-Admin-Secret`. A production deployment often publishes no
  admin secret at all, and then neither call is open to you: the holder gets
  signed VCs from a credential issuer (`tasra-hovi-issuer`,
  `tasra-oid4vp-wallet-and-verifier-agent`) and opens the session with
  `{vpJwt}`, or turns the same VCs into a renewal grant with `createRenewal`.
  A renewal token is not self-serve either — it needs those credentials first.
- ❌ Sending one holder proof to several verifiers. Each verifier needs its own.
- ❌ Inventing a holder DID (`did:example:…`, `did:demo:…`) or choosing one independently
  of the holder key. See "Which holder DID".
- ❌ Ignoring `AuthDeniedError` and retrying. A 401/403 will repeat; re-claim
  a credential instead (see `tasra-handle-errors`).

## Where to read more

- `node_modules/tasra-sdk/docs/api.md` and `docs/architecture.md`.
- `node_modules/tasra-sdk/dist/auth/*.d.ts` (grants, tokens, holder proofs)
  and `dist/client/client.d.ts` (`TasraClientConfig`, `SessionAuth`).
