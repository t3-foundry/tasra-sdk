# What's exported (main entry)

> The exported surface, grouped by what it is for — including IBE, OpenID4VP and the committee path.

| Group | Symbols |
|---|---|
| **Managed client** | `createTasraClient`, `TasraClient`, `Session`, `SessionAuth`, `VpJwtAuth`, `OpenSessionOpts`, `SignOpts` |
| **Errors** | `TasraError`, `TasraHttpError`, `AuthDeniedError`, `NodeUnreachableError`, `ThresholdNotMetError`, `SlotRotatedError`, `CommitteeAuthorizeError`, `DcqlMalformedError`, `VerifierAgentSessionError`, `isAuthDenied`, `isRetryable` |
| Crypto | `encryptEnvelope`, `decryptWithMasterKey`, `toBytes`, `fromBytes`, `buildTasraText`, `parseTasraPost`, `isTasraPost`, `GroupEnvelope` |
| Identity-scoped IBE | `ibeEncrypt`, `ibeCombineExtract`, `ibeCombineDecrypt`, `ibeDecryptWithKey`, `requestIbeExtractionPartials`; **large objects**: `ibeSealBlob`, `ibeOpenBlob`, `ibeUnwrapBlobKey`, `ibeBlobDecryptKey`, `ibeDecryptBlobChunk`, `ibeBlobChunkRange`, `ibeBlobDigest`, `IbeBlobHeader` |
| Node client | `fetchMpk`, `fetchAndAssembleKey` |
| Signing | `signCustody`, `signWithShardDelivery`, `signUserRequest`, `signEoaDigest`, `ethSignatureV`, `addressFromEoaPubkey`, `aggregateFrostSignature`, `verifyFrostSignature` |
| Decryption (threshold) | `decryptCustody`, `decryptWithShardDelivery`, `combineDecryptShares`, `verifyDecryptShare` |
| Verifier auth + JWT | `redeemCredential`, `redeemRenewalToken`, `createRenewal`, `revokeRenewal`, `issueAdminCredential`, `revokeSlotUser`, `verifyPresentation`, `verifyVpJwt`, `decodeJwtClaims`, `jwtExpMs`, `isJwtExpiringSoon` + `IssuedToken`, `JwtClaims` |
| DCQL (OID4VP-DCQL) | `validateDcql`, `evaluateDcql`, `selectDcql`, `canonicalizeDcql`, `isOid4vpRule`, `jsonCredential`, `evaluateIdentityScoped`, `scopeCovers`, `DcqlMalformedError`, `DCQL_MAX_RULE_LEN` + `DcqlQuery`, `CredentialView` |
| Verifier Agent sessions | `createOid4vpSession`, `pollOid4vpSession`, `waitForSession`, `payloadDigest`, `VerifierAgentSessionError`; `oauth` kind: `createOauthSession`, `submitOauthResponse` + `CreateSessionParams`, `CreateOauthSessionResult`, `SessionStatusResult` |
| DPoP (RFC 9449) | `createDpopKey`, `auth0DpopSigner`, `jwkThumbprint`, `accessTokenHash`, `isHeaderSafeNonce` + `DpopSigner`, `DpopKey` |
| Committee tokens | not on the main entry — see [`tasra-sdk/committee`](#tasra-sdkcommittee--protocol-internals) |
| Slot funding | `httpFaucet` (sovereign slot creation lives in `tasra-sdk/chain`) |
| Utils | `hexToBytes` |

Use `createCommitteeSlotClient` for credential-gated threshold custody. Managed
`Session.decrypt` requires an exportable personal-vault slot; the session primitives,
verifier-auth helpers, and crypto are what it composes (use them directly when you
need finer control). To resolve endpoints from chain instead of hardcoding them, use the
`tasra-sdk/chain` clients (`createTasraSlotClient` / `createCommitteeSlotClient`).
Verifier-auth helpers are pure HTTP/JSON; JWT inspection is client-side only (expiry/UX),
never a signature check. DCQL is a **generic** evaluator — scope *semantics* are the
consuming product's concern.

## Large objects under IBE — `ibeSealBlob` / `ibeOpenBlob`

`ibeEncrypt` is a KEM for a small payload. For an image, a scan series or any multi-megabyte
object, seal an **envelope**: a fresh 32-byte data key IBE-wrapped to the identity, the body
AES-256-GCM in fixed chunks (WebCrypto, default 1 MiB), each chunk's nonce
`blobId[0..8] ‖ be32(i)` and its AAD `"keykeeper/ibe-blob/v1" ‖ blobId ‖ be32(i) ‖ last ‖ identity`
— so a chunk cannot be reordered, dropped, truncated or replayed under another identity.

```ts
import {ibeSealBlob, ibeOpenBlob, ibeUnwrapBlobKey, ibeBlobDecryptKey, ibeDecryptBlobChunk, ibeBlobChunkRange} from 'tasra-sdk'

// producer (offline, nothing but the slot's public MPK)
const {header, body} = await ibeSealBlob(mpk, 'did:key:zPatient/imaging/2026-09', pngBytes, {contentType: 'image/png'})
// store `body` as a blob and `header` beside it (header.wrappedKey is the IBE ciphertext of the data key)

// consumer, after an identity-scoped extraction gave it sk_ID for that identity
const png = await ibeOpenBlob(skId, header, body)                    // whole object in memory, or …
const dek = ibeUnwrapBlobKey(skId, header)                           // … stream it:
const key = await ibeBlobDecryptKey(dek)
for (let i = 0; i < header.chunkCount; i++) {
  const {start, end} = ibeBlobChunkRange(header, i)                  // byte range of chunk i in `body`
  const plain = await ibeDecryptBlobChunk(key, header, i, await fetchRange(start, end))
}
```

`sk_ID` is a per-identity capability, so one extraction opens every object sealed to that
identity; time-box identities (`…/2026-09`) rather than expecting to revoke one. Pair the body
with a producer-signed digest (`ibeBlobDigest(body)`) so the consumer can reject a substituted
ciphertext before decrypting anything.

## `tasra-sdk/oid4vp` — credential wallets against the Verifier Agent

The wallet contract the platform speaks is the one the Hovi Wallet speaks (OpenID4VP 1.0 with
DCQL, SD-JWT VC + KB-JWT, JARM `direct_post.jwt`, OpenID4VCI pre-authorized issuance), and this
subpath is a clone of that behaviour — the Tasra Vault runs on it, and a test can play the wallet
against the real Verifier Agent . Two roles:

```ts
// APP / RELYING PARTY: sign the operation with the slot creator's EVM key (EIP-712
// PresentationOperation), open a session on the verifier-agent, hand the openid4vp:// payload to a wallet,
// collect the compound token — the credentials never come back here.
import {openVerifierAgentSession, awaitVerifierAgentResult} from 'tasra-sdk/oid4vp'
const session = await openVerifierAgentSession({verifierAgentUrl, chainId, keyRegistry, slotId, action: 'sign', message, description, signer: creatorAccount})
showQr(session.qrPayload)
const {token} = await awaitVerifierAgentResult(session)      // checks token.request_hash against the session

// WALLET: receive a credential from any OpenID4VCI issuer, then answer a request: fetch + verify
// the JAR (did:web → the verifier-agent's set document), plan against its dcql_query, let the user pick ONE
// credential, disclose only the claims asked for, bind with a KB-JWT, encrypt, POST.
import {randomHolderKey, receiveCredential, presentToRequestUri} from 'tasra-sdk/oid4vp'
const holder = randomHolderKey()                  // P-256 did:jwk, cnf.kid = did#0
const {credential} = await receiveCredential({offerUri, holder})
await presentToRequestUri(qrPayload, [{sdJwt: credential}], holder, {choose: askUser})
```

`planPresentation` / `buildResponse` / `submitResponse` are the steps behind `presentToRequestUri`
for a UI that wants a consent screen between them. One credential per presentation: a rule that
needs two credentials must use `credential_sets` with single-credential options (what the Hovi
Wallet can satisfy). Issuers use `issueSdJwtVc` (P-256 `did:key` or `did:jwk` issuer); the
request binding (`requestHash`, `derivedNonce`) lives in `binding` for the verifier-agent side and
tests — a wallet copies the nonce, it never interprets it. `test/live/verifierAgentWallet.ts` runs the
whole loop against a fleet.

## Bring your own identity provider — OAuth + DPoP against the Verifier Agent

A slot whose rule uses the `oauth+access-token+dpop` format is authorized by an access token
your users already get from your own IdP, sender-constrained with DPoP (RFC 9449). The rule is
ordinary OID4VP-DCQL over the token's own claims — `iss` pinned, `["aud", null]` containing the
platform audience, `meta.max_age_secs`, plus whatever roles you require:

```json
{"credentials":[{"id":"t","format":"oauth+access-token+dpop","meta":{"max_age_secs":300},
  "claims":[
    {"path":["iss"],"values":["https://idp.example.com/realms/acme"]},
    {"path":["aud",null],"values":["https://agent.tasra.example/authz/43114"]},
    {"path":["realm_access","roles",null],"values":["treasury-signer"]}]}]}
```

`validateDcql` refuses an `oauth+*` query without the pinned `iss`, the `["aud", null]` entry or
`meta.max_age_secs` (1–86400), exactly as the reference implementation validator does (shared corpus). The audience
is derived, never chosen — `platformAudience(agentOrigin, chainId)` from
`tasra-sdk/committee`, or read it back from any `createOauthSession` reply.

```ts
import {auth0DpopSigner, createOauthSession, submitOauthResponse, waitForSession} from 'tasra-sdk'
import {presentationOperationTypedData} from 'tasra-sdk/oid4vp'

const {typedData, operation, messageHex} = presentationOperationTypedData({
  chainId, keyRegistry, slotId, action: 'sign', message, description: 'Treasury payout #42',
})
const operationSig = await creatorSigner.signTypedData(typedData)

const session = await createOauthSession(verifierAgentUrl, {operation, operationSig, messageHex})
// → {sessionId, pollSecret, nonce, dpopHtu, platformAudience} — no QR, no Request Object

await submitOauthResponse(verifierAgentUrl, {
  sessionId: session.sessionId, pollSecret: session.pollSecret,
  accessToken, nonce: session.nonce, dpopHtu: session.dpopHtu,
  signer,                                   // MUST sign with the key the token is bound to
})
const result = await waitForSession(verifierAgentUrl, session.sessionId, session.pollSecret)
if (result.status !== 'done') throw new Error(`refused: ${result.error}`)
// result.compoundToken + result.verifierProofs → the keeper's /v1/committee/sign
```

**The signer is decided by where your token's DPoP key lives:**

| Your token came from | `signer` |
|---|---|
| `auth0-spa-js` with `useDpop` | `auth0DpopSigner((args) => auth0.generateDpopProof(args))` |
| `oidc-client-ts` with `dpop` enabled | `{proof: ({htm, htu, nonce}) => userManager.dpopProof(htu, user, htm, nonce)}` (it computes `ath` from the user's token) |
| your own token request with a key from `createDpopKey()` | `key.signer` |

⚠ **`createDpopKey().signer` mints resource-request proofs only** — it always sets `ath` and
`nonce` — and the SDK has no token-request proof helper, so it cannot obtain the token from the
IdP for you. Prefer letting your OIDC library own the key.

⚠ **Sign over `session.dpopHtu`, not the request URL.** The platform's `htu` is
`{agentOrigin}/v1/sessions/oauth-response` (no session id), while the request goes to
`/v1/sessions/{id}/oauth-response`. `submitOauthResponse` passes `dpopHtu` to the signer; a
generic DPoP fetch helper that derives `htu` from the request URL — including `auth0-spa-js`'s
`fetchWithAuth` — is refused.

⚠ **`submitOauthResponse` resolving does not mean authorized.** The agent accepts the delivery
and runs the committee; a refusal (wrong role, stale token, wrong audience…) surfaces from
`waitForSession` as `status: 'failed'` with the verifiers' reasons in `error` (it RETURNS a
failed session rather than throwing — check `status`). `submitOauthResponse` answers the agent's `use_dpop_nonce` challenge once by itself.

What the platform proves this way is PRESENCE, not intent — the user never sees the
operation; pin dual control on slots that need intent. Configuring a tenant identity
provider is a deployment task, documented by whoever operates the network.

## `tasra-sdk/committee` — protocol internals

The compound-token layer — committee draw, canonical hashing, ed25519 quorum
verification, verifier-set Merkle proofs, wire codecs, and the
`/v1/committee-authorize` orchestration — lives behind its own subpath:

```ts
import {verifyCompoundToken, selectVerifierCommittee} from 'tasra-sdk/committee'
```

It also carries the derivations `platformAudience(origin, chainId)` and
`dpopHtu(origin)` (+ `normalizeOrigin`, `OAUTH_RESPONSE_PATH`), vector-pinned byte for byte
against the reference OAuth derivations (`test/dpop.ts`).

**Most consumers never need it.** `createCommitteeSlotClient` from
`tasra-sdk/chain` drives the whole flow from a bare slot id; reach for these
only when you are re-implementing or auditing the protocol itself.

These ~35 symbols are deep protocol internals — canonical hashing, Merkle proofs,
the committee draw, wire codecs — and they are **not** on the main entry, so
`import {…} from 'tasra-sdk'` autocompletes to the managed surface rather
than to `compoundTokenCanonicalBytes`.

---

[← Back to the README](../README.md) · [Documentation index](README.md)
