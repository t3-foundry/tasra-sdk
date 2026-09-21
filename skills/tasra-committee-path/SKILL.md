---
name: tasra-committee-path
description: Use the Tasra committee path with tasra-sdk — createCommitteeSlotClient from a bare slot id, where a beacon-drawn verifier committee co-signs one compound token and keepers sign or decrypt without ever reconstructing the key; holder proofs per verifier; and when to reach for tasra-sdk/committee internals. Use for "committee path", "compound token", "createCommitteeSlotClient", "VerifierSetRegistry", "verifyCompoundToken", "holderProofPerVerifier", "the key must never be reconstructed".
metadata:
  package: tasra-sdk
  sources:
    - docs/chain.md
    - docs/api.md
    - dist/chain/committeeClient.d.ts
---

# The committee path

The JWT path's `Session.decrypt` reconstructs the master key in your process.
The committee path never does: per request, a verifier committee drawn by the
on-chain beacon co-signs one compound authorization token, and the keepers run
the sign or decrypt ceremony themselves, authorized, metered and audited at the
node. Endpoints come only from chain; there is no static fallback, and the flow
refuses to run without trustless `VerifierSetRegistry` inclusion proofs.

**First check that the deployment accepts this flow.** A keeper running the
production posture sets `api.require_request_binding`, which means a token is
only good for the one request whose hash it carries. The verifiers cannot bind
that hash — only the verifier agent sees the request — so a token gathered here
is refused by the keeper with HTTP 403 `request binding required
(api.require_request_binding) but token carries no request_hash — use a token
issued by the Verifier Agent`. There is no way around it from this side: on such
a deployment the authorization comes from the OID4VP flow in
`tasra-oid4vp-wallet-and-verifier-agent`, and everything below applies to
deployments that do not enforce binding. What is below still holds for reading
the slot, resolving keepers and verifiers, and encrypting, none of which needs a
token.

**Then check the slot.** The committee path reads the slot's per-request verifier
policy, and a slot created without one has none: every call fails with
`slot 0x… has no verifierPolicy (committee path not wired); use the JWT path`. It is
set once, by the slot creator, with `writer.setVerifierPolicy(slotId, committee, quorum)`
(`tasra-create-slot`, step 8) — not something this side can work around.

```ts
import {createHolderProof, fromBytes, type HolderSigner} from 'tasra-sdk'
import {holderProofPerVerifier} from 'tasra-sdk/committee'
import {createTasraChainClient, createCommitteeSlotClient, addressBookFromEnv, VERIFIER_TAG} from 'tasra-sdk/chain'
import {ed25519ClientSigner} from 'tasra-sdk/committee'

// addressBookFromEnv reads KEY_REGISTRY, NODE_REGISTRY, VERIFIER_SET_REGISTRY, … and skips
// non-address values, so passing all of process.env is safe. chainId defaults to the local dev
// chain (1337); pass it for any other deployment.
const chain = createTasraChainClient({rpcUrl, addresses: addressBookFromEnv(process.env), chainId})   // chainId: number, e.g. 43112
// The committee path needs KEY_REGISTRY (slot record + verifier policy), NODE_REGISTRY (keeper and
// verifier URLs), THRESHOLD_BEACON (the per-request draw) and VERIFIER_SET_REGISTRY (the anchored
// snapshot) in the book; a missing one throws on the read that needs it, not at construction.
// verifierUrl below is one verifier from the on-chain directory — (await resolveVerifierDirectory(chain))[0].url
// (tasra-chain) — or the single verifier of a small deployment.

const holder = 'did:key:z6Mk…'                                     // the credentials' subject DID
const credentials: string[] = [...]                                 // compact-JWS verifiable credentials
const slotId: `0x${string}` = '0x…'                                 // bytes32 slot id, hex
const signer: HolderSigner = {alg: 'EdDSA', did: holder, secretKey}  // secretKey: Uint8Array, the DID's 32-byte Ed25519
                                                                    // authentication key; or {alg, did, sign(input)} for a callback/HSM
// ONE PROOF PER VERIFIER. A proof names its audience and burns a nonce that lives in that one
// verifier, so where the policy draws a committee the others answer 401 "aud does not include this
// verifier". Pass the function and each drawn verifier gets a fresh proof, on every request:
const holderProof = holderProofPerVerifier({signer, audience: 'your-verifier-iss', credentials, slotId})
// A single string — await createHolderProof(verifierUrl, {signer, audience, credentials, slotId}) —
// is enough only where the deployment has one verifier.
const kk = createCommitteeSlotClient({
  chain, holder, credentials, holderProof,
  clientSigner: ed25519ClientSigner(clientSecretKey),   // optional, 32-byte Ed25519 secret; attributes the request bundle
  ttlSecs: 300,                                         // compound-token TTL (default 300)
})

// This is a BLS slot. Signing needs a separate FROST slot and authorization for that slot.
const messageBytes = new TextEncoder().encode('hello')
const env = await kk.encrypt(slotId, messageBytes, {identity: new TextEncoder().encode(slotId)})                   // Uint8Array envelope; local, group key read from KeyRegistry

// decrypt takes the envelope's parts, not the bytes: split them with fromBytes —
// ciphertext is an opaque Ciphertext structure, identity the label bytes (Uint8Array), epoch a bigint
const {ciphertext, identity, epoch} = fromBytes(env)
const plaintext = await kk.decrypt(slotId, {                       // Uint8Array
  ciphertext, identity,
  ciphertextEpoch: epoch === null ? undefined : Number(epoch),
  decryptingSet,   // number[]: k..n distinct BLS identifiers asked to run the ceremony
  blsPeers,        // {id, peerId}[]: those keepers' libp2p peers — ceremony participants, not endpoints
})
```

`encrypt` needs no holder or credentials (it only reads the public group key), so
`createCommitteeSlotClient({chain})` alone is a valid encrypt-only client, built
without any network call; `sign` and `decrypt` need `holder`, `credentials` and
`holderProof`.
`decryptingSet` and `blsPeers` are the one input you still supply: they name
which keepers run the decryption ceremony — `k` to `n` distinct BLS identifiers,
where `k` is `(await chain.readers.keyRegistry.getKeySlot(slotId)).threshold.k`.
Take them from the slot's assigned keepers (`resolveSlotKeeperUrls`,
`tasra-chain`) and each keeper's `/v1/info` (`node_identifier` → `id`,
`peer_id` → `peerId`); both fields are optional in `NodeInfo`, so skip a keeper
whose info lacks either. Those on-chain URLs are often in-cluster names, and
`nodeApi.info` needs them reachable from where you run.
`VERIFIER_TAG` is `keccak256("verifier")`, the `NodeRegistry` role tag the
verifier set is discovered by.

Before the first request, the real slot must have a nonzero verifier committee
and quorum policy, a provisioned DCQL rule and funded usage. A BLS slot cannot
perform FROST signing. For a separate signing slot, obtain a fresh holder proof
bound to that slot; never reuse the encryption slot's proof. Advertised keeper
and verifier endpoints must be reachable from the application. This client
does not rewrite internal cluster hostnames into public URLs.

## Holder proofs and committees

A holder proof is bound to a nonce that lives in one verifier's store and is
consumed atomically: the verifier that validates it spends the nonce and refuses
that proof a second time, so one proof authorizes one request at one verifier.
A committee is several verifiers, so a single string cannot serve it — the ones
it does not name answer 401 `holder proof rejected: … aud does not include this
verifier`, and there is no quorum.

`holderProofPerVerifier({signer, audience, credentials, slotId})` is the answer
everywhere holder binding is enforced: it mints a fresh nonce-bound proof for
each drawn verifier, on every request. `createCommitteeSlotClient` takes it as
`holderProof`, and so do the lower-level flows (`requestCommitteeToken`,
`committeeSign`, `committeeDecrypt`) and the one-call `committeeSignRequest`,
`committeeDecryptRequest` and `ibeDecryptRequest` from `tasra-sdk/committee`.
A plain string still works where the deployment has a single verifier, and a
client built around one serves exactly one request.

## `tasra-sdk/committee`

The internals: `selectVerifierCommittee`, `compoundTokenHash`,
`assembleCompoundToken`, `verifyCompoundToken`, Merkle proof helpers, wire
codecs, and the orchestration (`committeeAuthorize`, `gatherCommitteeToken`,
`requestCommitteeToken`, `committeeSign`, `committeeDecrypt`,
`requestIbeExtractionPartials`). Most consumers never import it;
`createCommitteeSlotClient` drives all of it. Reach for it when auditing or
re-implementing the protocol, or to `verifyCompoundToken` offline.

## Common mistakes

- ❌ Passing `dcqlRule` in the config. It is unused: the verifier fetches the
  slot's rule from a keeper and hash-checks it. Remove it.
- ❌ Passing node or verifier URLs. There is no way to; they come from chain.
- ❌ Running against a deployment without an anchored `VerifierSetRegistry`
  snapshot. The client throws rather than degrade; ask the operator.
- ❌ One holder proof for several verifiers under `require_holder_binding`, or
  for a second request. Its nonce is single-use: mint a fresh proof, or use the
  lower-level flow with `holderProofPerVerifier`.
- ❌ Passing the envelope bytes to `decrypt`. Split them with `fromBytes` first.
- ❌ Passing a key string as `signer`. It is a `HolderSigner` object.
- ❌ Choosing this path for convenience. Choose it when the key must never be
  reconstructed; otherwise the JWT path is simpler.

## Where to read more

- `node_modules/tasra-sdk/dist/chain/committeeClient.d.ts`,
  `node_modules/tasra-sdk/dist/committee/index.d.ts`.
