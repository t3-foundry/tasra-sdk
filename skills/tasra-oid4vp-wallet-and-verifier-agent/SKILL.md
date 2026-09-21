---
name: tasra-oid4vp-wallet-and-verifier-agent
description: "OpenID4VP and OpenID4VCI with tasra-sdk \u2014 act as the relying party (openVerifierAgentSession, awaitVerifierAgentResult, or the lower-level tasra-sdk/verifier-agent client) to turn a wallet presentation into a compound token, or act as a wallet (receiveCredential, presentToRequestUri) with SD-JWT VC, KB-JWT, JWE and did:web. Also the oauth session kind: an access token from your own IdP, DPoP-bound (RFC 9449), createOauthSession, submitOauthResponse, createDpopKey, auth0DpopSigner. Use for \"OID4VP\", \"OpenID4VP\", \"wallet\", \"SD-JWT\", \"Verifier Agent\", \"openid4vp:// QR\", \"issue a credential\", \"VerifierAgentSessionError\"."
metadata:
  package: tasra-sdk
  sources:
    - docs/api.md
    - dist/oid4vp/index.d.ts
    - dist/verifier-agent/index.d.ts
    - dist/auth/dpop.d.ts
    - dist/committee/oauth.d.ts
---

# OpenID4VP wallets and the Verifier Agent

The platform speaks the OpenID4VP 1.0 wallet contract (DCQL queries, SD-JWT VC
with key binding, JARM `direct_post.jwt`, OpenID4VCI pre-authorized issuance).
`tasra-sdk/oid4vp` implements both sides; `tasra-sdk/verifier-agent` is the thin
session client under the verifier-agent side.

## Relying party (your app)

```ts
import {openVerifierAgentSession, awaitVerifierAgentResult} from 'tasra-sdk/oid4vp'
import {privateKeyToAccount} from 'viem/accounts'   // viem is an optional peer: install it for this

const creatorKey = process.env.KK_CREATOR_KEY as `0x${string}`   // the slot creator's EVM private key, 0x-hex
const session = await openVerifierAgentSession({
  verifierAgentUrl: process.env.KK_VERIFIER_AGENT_URL ?? process.env.KK_RP_URL!,   // deployments name it either way
  chainId: Number(process.env.KK_CHAIN_ID),      // number
  keyRegistry: process.env.KEY_REGISTRY as `0x${string}`,   // cast env strings
  slotId: process.env.KK_SLOT_ID as `0x${string}`,
  action: 'sign',                                // 'sign' | 'decrypt' | 'ibe-extract' | 'dual-approve'
  message: new TextEncoder().encode('…'),        // Uint8Array — the input 'sign' binds; see the table below
  description: 'Sign the Q3 report',             // required; shown to the holder
  signer: privateKeyToAccount(creatorKey),       // any TypedDataSigner: {address, signTypedData(...)}; a viem LocalAccount fits
})
showQr(session.qrPayload)                        // an openid4vp:// payload for the holder's wallet
const controller = new AbortController()                       // optional: abort if the user closes the prompt
const {token, verifierProofs} = await awaitVerifierAgentResult(session, {timeoutMs: 300_000, signal: controller.signal})
// verifierProofs is OPTIONAL (VerifierProof[] | undefined) — guard before you read it
// `token` is a CompoundTokenWire OBJECT for the committee client / keepers, not a string; credentials never reach you
```

Each `CommitteeAction` binds a different payload, and you pass the input for that
action — passing the wrong one produces a token the keeper's own recomputation rejects:

| `action` | you pass | the token binds |
|---|---|---|
| `sign` | `message: Uint8Array` | `sha256(message)` |
| `ibe-extract` | `identity: string` | `sha256(identity)` — see `tasra-ibe-identity-scoped` |
| `decrypt` | `payloadDigest` from `decryptPayloadDigest(u, aeadCt)` | that digest |
| `dual-approve` | `payloadDigest: Uint8Array` | that digest |

This is the flow to use whenever the keepers enforce `api.require_request_binding`:
the verifier agent is the only party that sees the request, so it is the only one that
can bind it. The direct committee path (`tasra-committee-path`) cannot.

The operation is signed by the slot creator's EVM key as EIP-712 typed data
(`presentationOperationTypedData`), so the verifier-agent can prove who asked. `awaitVerifierAgentResult`
checks the token's request binding against the session. Errors are
`VerifierAgentSessionError` with `kind` `timeout | refused | unavailable | protocol | cancelled`
(see `tasra-handle-errors`); pass an `AbortSignal` to cancel.

Lower level, `tasra-sdk/verifier-agent`: `createOid4vpSession(verifierAgentUrl, {operation,
operationSig, messageHex})`, `pollOid4vpSession(verifierAgentUrl, sessionId, pollSecret)`,
`waitForSession(...)` with bounded jittered polling, and
`payloadDigest(action, messageHex)`.

## The `oauth` session kind — your own identity provider

A session has two kinds. The default above is `oid4vp`: a wallet presents a credential.
The other is **`oauth`**: the user brings an access token their own IdP already minted,
sender-constrained with DPoP (RFC 9449). Same creator authorisation, same committee draw,
same derived nonce, same poll contract — **no QR, no Request Object, no JWE key**, because
there is no wallet in the loop.

Use it when the slot's rule names the `oauth+access-token+dpop` format
(`tasra-dcql-rules`). The two have to agree: an `oauth` session against a
credential-format rule authorizes nothing.

```ts
import {createOauthSession, submitOauthResponse, waitForSession} from 'tasra-sdk/verifier-agent'
import {createDpopKey} from 'tasra-sdk'

const session = await createOauthSession(verifierAgentUrl, {
  operation, operationSig, messageHex,      // identical to createOid4vpSession
})
// Returns sessionId, pollSecret, nonce, dpopHtu and platformAudience — the `aud` your
// tenant must have registered with its IdP. A token whose `aud` omits it is refused by
// every drawn verifier.

const key = await createDpopKey()            // ES256, non-extractable — see below
// …obtain an access token from your IdP bound to `await key.thumbprint()` (the IdP puts
//   that value in the token's `cnf.jkt`)…

await submitOauthResponse(verifierAgentUrl, {
  sessionId: session.sessionId,
  pollSecret: session.pollSecret,
  accessToken,
  nonce: session.nonce,
  dpopHtu: session.dpopHtu,
  signer: key.signer,
})
const {token} = await waitForSession(verifierAgentUrl, session.sessionId, session.pollSecret)
```

Four things that bite:

- **The proof must be signed by the key the token is bound to.** Any other key is refused
  with `DPoP proof jwk is not the key the access token is bound to`. That is the whole
  point of sender constraining, so the token and the signer travel together.
- **`createDpopKey()` is non-extractable** — the private half never leaves WebCrypto, so
  it cannot be lifted out of a compromised page alongside the token.
- **`submitOauthResponse` handles the `use_dpop_nonce` challenge itself.** On a `401`
  carrying `DPoP-Nonce` it re-mints the proof with the server's nonce and resends **once**.
  One retry, not a loop: a server that keeps challenging is broken, and retrying forever
  would hide that. You do not need a challenge round trip — `createOauthSession` already
  returned the nonce.
- **Auth0 holds its own key**, so you cannot sign with `DpopKey` there. Wrap its generator:
  `auth0DpopSigner((args) => auth0.generateDpopProof(args))`, which is the only way an
  Auth0 app produces a proof whose `jkt` matches its token's `cnf.jkt`.

`dpopHtu` is session-independent by RFC 9449 (`htu` excludes query and fragment), which
is why any conformant client library derives the same string from the URL it is about to
call. `accessTokenHash`, `jwkThumbprint` and `isHeaderSafeNonce` are exported if you are
building a proof by hand; `platformAudience(origin, chainId)` and `dpopHtu(origin)` from
`tasra-sdk/committee` derive the two strings rather than hardcoding them.

Errors are the same `VerifierAgentSessionError` kinds. A verifier-agent too old for this
kind refuses the session saying it does not support it, rather than failing obscurely
later.

## Wallet

```ts
import {ed25519HolderKey, randomHolderKey, receiveCredential, presentToRequestUri, defaultKeyResolver, planPresentation, buildResponse, submitResponse} from 'tasra-sdk/oid4vp'
import {hexToBytes} from 'tasra-sdk'

// A WALLET PRESENTS WHAT IT HOLDS. Where a deployment issues the credential its slots ask for, it
// hands you that credential and the holder key it is bound to — read them (KK_CREDENTIALS and the
// holder's key in this sandbox's .env) instead of minting your own, which answers no existing rule:
const holder = process.env.KK_HOLDER_SECRET_KEY
  ? ed25519HolderKey(hexToBytes(process.env.KK_HOLDER_SECRET_KEY)) // the key the credential is bound to
  : randomHolderKey()                                              // {did: 'did:jwk:…', …} a fresh P-256 holder
const credential = process.env.KK_CREDENTIALS?.split(',')[0]
  ?? (await receiveCredential({offerUri, holder})).credential      // OpenID4VCI pre-authorized flow
// first argument: the full openid4vp://… string from the QR, or just its request_uri
const {ro, plan, built, redirectUri} = await presentToRequestUri(qrPayload, [{sdJwt: credential}], holder, {   // see the note below on `ro`
  // `choose` receives the PresentationPlan ({satisfies, candidates, chosen?, unmatched}) and
  // returns one PresentationCandidate, or undefined to abort — aborting THROWS, it is not a result
  choose: plan => plan.chosen,   // the default when `choose` is absent: the evaluator's pick, set only when
                                 // the request is satisfied. `candidates[0]` is no fallback — a candidate
                                 // answers some query, which is not the same as satisfying the request.
  resolveKey: defaultKeyResolver({allowInsecureLoopback: true}),   // ONLY for a loopback agent serving
                                 // did:web over PLAIN HTTP: downgrades localhost / 127.0.0.1, no other
                                 // host. Omit it when the agent serves HTTPS — see below.
})   // → {ro, plan, built, redirectUri?}
// `ro` is the VERIFICATION result — {jwt, header, claims, signerDid, signerKey} — not the request object itself:
// the OID4VP fields live on `ro.claims` (`ro.claims.dcql_query`, `ro.claims.nonce`).
```

`presentToRequestUri` fetches and verifies the request object (JAR, via the
verifier-agent's `did:web` document), plans against its `dcql_query`, lets the user pick one
credential, discloses only the requested claims, binds with a KB-JWT, encrypts
the response and POSTs it. `planPresentation` / `buildResponse` /
`submitResponse` are the same steps split for a consent screen.

Both fetches — the `request_uri` and the `did:web` document — use the global
`fetch`, so a verifier-agent serving them over HTTPS from a private CA needs
that CA trusted by the process: `NODE_EXTRA_CA_CERTS=/path/to/ca.pem` for a Node
wallet, or the call fails with `UNABLE_TO_VERIFY_LEAF_SIGNATURE` before it plans
anything. A client of your own goes in `fetchImpl` (the JAR and the POST) and in
`defaultKeyResolver({fetchImpl})` (the `did:web` document).

**`allowInsecureLoopback` and `NODE_EXTRA_CA_CERTS` are alternatives, not a pair —
and a local fleet usually wants the CA.** A fleet on loopback that terminates TLS
(the common case: its `did:web` is `did:web:localhost%3A19444`) is broken by the
downgrade, which retries the document over plain `http` against a TLS-only port:

```
Error: did:web resolution http://localhost:19444/.well-known/did.json → HTTP 400
```

Trust the CA and drop `allowInsecureLoopback`. Reach for the downgrade only when the
loopback agent genuinely serves plain HTTP.

A holder key is P-256 (`randomHolderKey`, `p256HolderKey`) or Ed25519 (`ed25519HolderKey`), and the
KB-JWT is signed with that key's own algorithm — ES256 or EdDSA. Which one you need is not a choice:
a credential is bound to one key through `cnf`, so present it with that key or not at all. Credentials
from `tasra-cli vc issue-sd-jwt` are Ed25519-bound; Hovi's are P-256.

The request's `dcql_query` is the slot's rule, so a held credential answers it
only if that rule names its `vct` and accepts its issuer. When none answers,
nothing is sent: `presentToRequestUri` throws
`no held credential answers: <query id>`, or `presentation declined` when
`choose` returned undefined with candidates on the table.

## Issuer (offline)

```ts
import {issueSdJwtVc, p256DidKeyIssuer, holderCnf, randomHolderKey} from 'tasra-sdk/oid4vp'

const issuer = p256DidKeyIssuer(crypto.getRandomValues(new Uint8Array(32)))   // {did, signer}; or didJwkIssuer(...)
                                                                              // global crypto: Node >= 19, or lib 'DOM' in tsconfig
const holder = randomHolderKey()
const credential = issueSdJwtVc({                 // synchronous; returns the compact SD-JWT VC string: issuer JWT ~ disclosure ~ … ~ (trailing tilde)
  issuer,
  vct: 'EmployeeOf',
  claims: {dept: 'Engineering', level: 3},        // each claim becomes a disclosure unless listed in `plain`
  cnf: holderCnf(holder),                         // key binding: {kid: `${holder.did}#0`}
})
```

Everything in this subpath is exported (`export *`), including JOSE, JWE and
`did:web` helpers.

Issuing a credential does not make it answer an existing slot. A credential
from a fresh issuer like this one is accepted only where the slot's rule names
its `vct` and either pins this `issuer.did` under `["iss"]` or accepts any
issuer (`tasra-dcql-rules`); against any other slot the wallet refuses
before it presents.

## Common mistakes

- ❌ Expecting credentials back at the verifier-agent. Only the compound token returns.
- ❌ Asking for two credentials in one presentation. One per presentation; a
  rule needing two uses `credential_sets` with single-credential options.
- ❌ Interpreting the nonce in the wallet. It is copied into the KB-JWT verbatim.
- ❌ Fetching `did:web` over plain HTTP. Only loopback may downgrade, and only
  with an explicit `allowInsecureLoopback` opt-in — a `ResolveOpts` field in
  `did-web.ts`, not an option of `presentToRequestUri`: it reaches the wallet as
  `resolveKey: defaultKeyResolver({allowInsecureLoopback: true})`.
- ❌ Polling the verifier-agent in a tight loop. Use `awaitVerifierAgentResult` or `waitForSession`.
- ❌ Awaiting the result only after the wallet has presented. Start
  `awaitVerifierAgentResult` first and `await` it after — the result exists only once a
  wallet has answered, and in a single process the two must overlap.
- ❌ Setting `allowInsecureLoopback` on a loopback fleet that serves HTTPS. It
  downgrades the `did:web` fetch to a port that does not speak HTTP; trust its CA instead.
- ❌ Reading `no held credential answers: <id>` as a bug. It is the wallet refusing to
  present, and it is a plain `Error`, not a `TasraError` (`tasra-handle-errors`).

## Where to read more

- `dist/oid4vp/request-object.d.ts` (the verified request object, `KeyResolver`,
  `defaultKeyResolver`), `did-web.d.ts` (`ResolveOpts`, where
  `allowInsecureLoopback` is declared), `wallet.d.ts` (plan and candidates),
  `verifier-agent.d.ts` and `dist/verifier-agent/index.d.ts`.
  `dist/oid4vp/index.d.ts` is only a barrel of `export *` lines.
