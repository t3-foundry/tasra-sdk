---
name: tasra-ibe-identity-scoped
description: Identity-scoped encryption with tasra-sdk — encrypt offline to an identity string under a slot's public key (ibeEncrypt), obtain the identity's decryption capability through k-of-n extraction (ibeDecryptRequest, ibeExtractRequest, ibeCombineExtract), and seal or stream large objects (ibeSealBlob, ibeOpenBlob). Use for "IBE", "encrypt to an identity", "sk_ID", "identity scope", "consent-gated records", "large file encryption".
metadata:
  package: tasra-sdk
  sources:
    - docs/api.md
    - dist/crypto/ibe.d.ts
    - dist/crypto/ibe-blob.d.ts
    - dist/committee/request.d.ts
---

# Identity-scoped encryption (IBE)

With identity-based encryption a producer needs only the slot's public group
key and an identity string to encrypt. Decryption requires the identity's
private key `sk_ID`, which only exists after `k` keepers each contribute a
partial extraction that a verifier committee authorized against an
identity-scoped DCQL rule. The producer is offline and permissionless; the
consumer is authorized per identity.

## Encrypt (producer, offline)

```ts
import {ibeEncrypt} from 'tasra-sdk'
const ct = ibeEncrypt(mpkBytes, new TextEncoder().encode('did:key:zPatient/labs/2026-09'), plaintext)
// ct: {u: 96 B, nonce: 12 B, aeadCt}. `ibeEncrypt` takes the identity as BYTES; `ibeSealBlob` below takes it as a STRING.
```

The producer needs only the slot's public group key — `fetchMpk(nodeUrl, slotId)`
from `tasra-sdk` returns `{mpkBytes, epoch}`, the key as bytes (96-byte
compressed G2), for a `0x`-hex bytes32 `slotId`; `resolveSlotGroupKey` in
`tasra-sdk/chain` returns `{publicKey, epoch, mode}` with the key as a `0x`
hex string, so `hexToBytes` it first — and no credentials. IBE runs on a
BLS12-381 slot only: check `(await resolveSlotGroupKey(chain, slotId)).mode === 1`
(`0` is frost — an Ed25519 signing key, not an IBE master key). Use `node:crypto`
`randomBytes` for a multi-megabyte test payload; WebCrypto's `getRandomValues`
refuses buffers over 64 KiB. For a local test, mint a stand-in key pair as
`tasra-getting-started` step 5 shows.

Identities are hierarchical strings. Under the `"issuer"` namespace binding the
first `/` segment must equal the granting credential's verified issuer DID, so
namespaces root at their grantor. Time-box identities (`…/2026-09`) rather than
expecting to revoke one; `sk_ID` is a durable capability for that identity.

**One slot, many users.** The rule names no one: it requires a credential type, pins
the issuer, and points `kk_identity_scope_claim` at a claim. The issuer then decides
who gets what by what it writes into each credential — `mailbox=<issuer>/mail/alice`
for one holder, `<issuer>/mail/bob` for another. Both hold the same kind of credential
against the same slot and neither can read the other's identity. Make each grant
**exact** (`…/mail/alice`) unless you mean to hand over a whole subtree: `…/mail/*`
gives that holder every mailbox under it.

Anyone can encrypt to any identity — encryption needs only the group key — so a
producer needs no credential at all. Authorization is entirely on the read side, which
is what makes a drop-box or a mailbox natural here.

When a holder asks for an identity their grant does not cover, every verifier refuses
the authorization independently, before any keeper is contacted:

```
HTTP 403 no verified credential grants scope covering the requested identity
         "did:web:hr.acme.example/mail/alice"
```

It surfaces as `VerifierAgentSessionError` with `kind: 'refused'`.

## Decrypt (consumer, authorized)

**Two things about the slot, and one about the deployment, decide whether any of this
runs.** All three fail only here, at the first extraction, with a clear 403 each:

1. **The slot's rule must be identity-scoped** — `kk_identity_scope_claim` +
   `kk_scope_namespace`, and the grant in the credential must cover the identity you
   ask for. Otherwise: `rule carries no identity-scope binding on any satisfied
   credential query`. The rule is committed at creation and cannot be swapped, so this
   is a `tasra-create-slot` decision, not a fix-it-later one. Shape and grant
   grammar: `tasra-dcql-rules`, "Identity-scoped rules".
2. **The slot must have a verifier policy** — `writer.setVerifierPolicy(slotId,
   committee, quorum)`. Otherwise: `slot 0x… has no verifierPolicy (committee path not
   wired); use the JWT path`.
3. **The deployment must not enforce request binding** for the block below to work at
   all. A keeper in the production posture sets `api.require_request_binding` and
   refuses any token that does not carry the hash of this exact request:
   `request binding required (api.require_request_binding) but token carries no
   request_hash — use a token issued by the Verifier Agent`. The verifiers cannot bind
   that hash — only the verifier agent sees the request — so **`ibeDecryptRequest` and
   `ibeExtractRequest` cannot succeed there at all**. Use "Extraction through the
   Verifier Agent" below instead. Everything above this section (encrypting, sealing,
   reading the group key) needs no token and is unaffected.

```ts
import {ibeDecryptRequest, ibeExtractRequest, ibeDecryptWithKey} from 'tasra-sdk'
import {committeeChainReadsFromClient} from 'tasra-sdk/committee'
// tasra-sdk/chain needs the optional peer `viem`; `await import()` it on the consumer path
// if the same process also runs a producer without viem installed.
import {createTasraChainClient, addressBookFromEnv, resolveVerifierDirectory, resolveSlotKeeperUrls} from 'tasra-sdk/chain'

// inputs from env, by the names the other skills use: KK_RPC_URL, KK_CHAIN_ID (defaults to the local
// dev chain, 1337; pass it for any other deployment), KK_SLOT_ID, KK_HOLDER (the credentials' subject
// DID), KK_CREDENTIALS (comma-separated compact JWS), KK_HOLDER_PROOF. The IBE identity is a value of
// your own — KK_IDENTITY is the holder DID in the other skills, not the string encrypted to.
// Address book: extraction reads KEY_REGISTRY (slot record + verifier policy), NODE_REGISTRY (keeper
// and verifier URLs) and THRESHOLD_BEACON (the committee draw); VERIFIER_SET_REGISTRY anchors the
// snapshot the trustless verifier proofs are checked against.
const chainClient = createTasraChainClient({rpcUrl, addresses: addressBookFromEnv(process.env), chainId})
const extractOpts = {
  chain: committeeChainReadsFromClient(chainClient.readers),   // a CommitteeChainReads adapter — NOT the chain client itself
  verifiers: await resolveVerifierDirectory(chainClient),     // the on-chain verifier set
  nodeUrls: await resolveSlotKeeperUrls(chainClient, slotId), // the slot's keepers
  slotId,        // 0x-hex bytes32 string
  holder,        // the credentials' subject DID
  credentials,   // string[]: compact-JWS verifiable credentials
  holderProof,   // the proof STRING from createHolderProof(verifierUrl, {signer, audience: 'your-verifier-iss', credentials, slotId})
                 // — one verifier's single-use nonce, spent by the request that presents it. With several
                 // verifiers under require_holder_binding, or for more than one request, pass the function
                 // holderProofPerVerifier({signer, audience, credentials, slotId}) from tasra-sdk/committee
                 // instead: this field takes either, and the function mints a fresh proof per verifier per request
  identity,      // the string the producer encrypted to
}
const identityBytes = new TextEncoder().encode(identity)

// The two calls below are alternatives, one committee authorization each — a string holderProof is
// spent by whichever runs first, so making both needs a fresh proof (or the per-verifier function).

// one-shot: token → k partials → verify each → combine → decrypt; sk_ID never surfaces
const plain = await ibeDecryptRequest({...extractOpts, ciphertext: ct})

// or keep the capability: returns sk_ID (48-byte compressed G1) for that identity; zeroize when done
const skId = await ibeExtractRequest(extractOpts)
// ibeDecryptWithKey throws (AEAD authentication) when skId or identityBytes is not this
// ciphertext's — a wrong key fails loudly rather than returning garbage.
const plain2 = ibeDecryptWithKey(skId, ct, identityBytes)
skId.fill(0)
```

`IbeExtractRequestOpts` drives the committee authorization for you (the
holder proof comes from `createHolderProof`, see
`tasra-credentials-and-sessions`). The lower-level pieces are
`requestIbeExtractionPartials` (from `tasra-sdk/committee`), then
`ibeVerifyShare` per partial and `ibeCombineExtract` / `ibeCombineDecrypt`.

## Extraction through the Verifier Agent (request-binding deployments)

When the keepers enforce `api.require_request_binding` — the production posture — the
authorization has to come from the OID4VP flow, because only the verifier agent sees
the request and can bind its hash into the token. The holder presents a credential to
the agent; what comes back is a request-bound compound token the keepers accept.
Same result, `sk_ID`, and the slot key is still never assembled.

```ts
import {ibeCombineExtract, ibeCombineDecrypt} from 'tasra-sdk'
import {requestIbeExtractionPartials} from 'tasra-sdk/committee'
import {openVerifierAgentSession, awaitVerifierAgentResult, presentToRequestUri, ed25519HolderKey} from 'tasra-sdk/oid4vp'
import {privateKeyToAccount} from 'viem/accounts'

// The relying party asks for authorization over ONE identity. 'ibe-extract' binds
// sha256(identity), so pass `identity` — not `message`, which is the 'sign' action's input.
// CommitteeAction is 'sign' | 'decrypt' | 'ibe-extract' | 'dual-approve'.
const session = await openVerifierAgentSession({
  verifierAgentUrl,                              // KK_VERIFIER_AGENT_URL, or KK_RP_URL on older deployments
  chainId, keyRegistry, slotId,
  action: 'ibe-extract',
  identity,                                      // the string the producer encrypted to
  description: `Open ${identity}`,               // required; the wallet shows it to the holder
  signer: privateKeyToAccount(creatorKey),       // the SLOT CREATOR's EVM key signs the operation (EIP-712)
})
showQr(session.qrPayload)                        // or drive a local wallet, as below

// Start waiting BEFORE the wallet presents: the result only exists once it has.
const resultP = awaitVerifierAgentResult(session, {timeoutMs: 120_000})
await presentToRequestUri(session.qrPayload, [{sdJwt: credential}], ed25519HolderKey(holderSeed))
const {token, verifierProofs} = await resultP    // token is a CompoundTokenWire OBJECT

// The keepers serve extraction partials against that bound token.
const partials = await requestIbeExtractionPartials({
  nodeUrls, committeeToken: token, identity, verifierProofs,   // verifierProofs are required under api.require_verifier_proofs
})
const identityBytes = new TextEncoder().encode(identity)
const skId = ibeCombineExtract(
  new Map(partials.map(p => [p.identifier, p.verifyingShareG2])),
  partials.map(p => ({identifier: p.identifier, value: p.value})),
  identityBytes,
)
// …or ibeCombineDecrypt(vsMap, shares, ct, identityBytes) to decrypt without sk_ID surfacing.
skId.fill(0)
```

Wallet mechanics — holder keys, which key a credential may be presented with, the
private-CA and `did:web` pitfalls — are `tasra-oid4vp-wallet-and-verifier-agent`.

For offline tests only: `sk_ID = s · Q_ID`, where `s` is the master scalar
(the BIG-endian bytes `skBE` from the getting-started recipe — not the
little-endian `msk` the SDK consumes) and `Q_ID` is the identity hashed to G1
under the DST `keykeeper/BLS12381-BF-IBE-HashToG1-v1`:

```ts
import {bls12_381} from '@noble/curves/bls12-381'          // v1 API; npm install @noble/curves@1 (see getting-started step 5)
const skBE = bls12_381.utils.randomPrivateKey()             // 32 B big-endian; mpk = bls12_381.G2.ProjectivePoint.fromPrivateKey(skBE).toRawBytes(true)
const G1 = bls12_381.G1
const q = G1.hashToCurve(identityBytes, {DST: 'keykeeper/BLS12381-BF-IBE-HashToG1-v1'})
const skId = G1.ProjectivePoint.fromAffine(q.toAffine()).multiply(G1.normPrivateKeyToScalar(skBE)).toRawBytes(true)  // 48 B
```

(`@noble/curves` 1.x API; the SDK's own hash helper is internal.)

## Large objects: `ibeSealBlob` / `ibeOpenBlob`

`ibeEncrypt` is a KEM for small payloads. For images, scans or anything of
megabytes, seal an envelope: a fresh data key IBE-wrapped to the identity and
the body AES-256-GCM in fixed chunks (WebCrypto, default 1 MiB =
`IBE_BLOB_DEFAULT_CHUNK`, override with `opts.chunkSize`), each chunk bound to
its index, the blob id and the identity, so chunks cannot be reordered,
dropped, truncated or replayed.

```ts
import {ibeSealBlob, ibeOpenBlob, ibeUnwrapBlobKey, ibeBlobDecryptKey, ibeDecryptBlobChunk, ibeBlobChunkRange, ibeBlobDigest} from 'tasra-sdk'

const {header, body} = await ibeSealBlob(mpkBytes, identity, bytes, {contentType: 'image/png'})
// store body as a blob, header beside it, and a producer-signed ibeBlobDigest(body).
// Seal to the identity skId was extracted for: sk_ID opens only its own identity, so a blob sealed
// to did:key:zPatient/imaging/2026-09 needs its own extraction for that exact string.

const whole = await ibeOpenBlob(skId, header, body)               // the plaintext Uint8Array, all in memory — or stream:
// ibeBlobDigest(body) is synchronous and returns a Uint8Array
const key = await ibeBlobDecryptKey(ibeUnwrapBlobKey(skId, header))
for (let i = 0; i < header.chunkCount; i++) {
  const {start, end} = ibeBlobChunkRange(header, i)
  const plain = await ibeDecryptBlobChunk(key, header, i, body.subarray(start, end))   // or an HTTP Range fetch; end is exclusive
}
```

## Common mistakes

- ❌ Reusing one identity forever. Extraction yields a permanent capability for
  it; scope identities narrowly and by period.
- ❌ Using `ibeEncrypt` for large payloads. Use `ibeSealBlob`.
- ❌ Skipping `ibeVerifyShare` when combining partials by hand. A bad partial
  yields garbage silently; the one-shot helpers verify for you.
- ❌ Decrypting a blob before checking the producer's digest. Verify
  `ibeBlobDigest(body)` against the signed value first.
- ❌ Presenting one holder proof for two extractions. Its nonce is single-use:
  mint a fresh proof per request, or pass `holderProofPerVerifier`.
- ❌ Evaluating an identity-scoped rule with plain `evaluateDcql` (see
  `tasra-dcql-rules`).
- ❌ Reaching for `ibeExtractRequest` before checking the deployment's posture. Under
  `api.require_request_binding` it can never succeed; the verifier-agent flow can.
- ❌ Passing `message` instead of `identity` to an `ibe-extract` session. The binding
  hash is over `sha256(identity)`, so the keeper's recomputation will not match.
- ❌ Creating the slot and only then discovering it needs an identity-scoped rule or a
  verifier policy. Decide both before `createSlot`. Without an amendment policy
  configured at creation, the rule is immutable; replacing that slot also changes
  the key needed to open existing ciphertexts.

## Where to read more

- `node_modules/tasra-sdk/docs/api.md`, "Large objects under IBE".
- `node_modules/tasra-sdk/dist/crypto/ibe.d.ts`, `ibe-blob.d.ts`,
  `node_modules/tasra-sdk/dist/committee/request.d.ts` (`IbeExtractRequestOpts`).
- Skills `tasra-chain` (chain client, address book, discovery) and
  `tasra-committee-path` (verifier set, holder proofs).
