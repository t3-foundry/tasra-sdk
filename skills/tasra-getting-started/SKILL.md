---
name: tasra-getting-started
description: Install tasra-sdk, choose the right client factory, open a session for a key slot, and do a first encrypt, decrypt and sign. Use for "how do I start with tasra", "which client should I use", "open a session", "npm install tasra-sdk", ESM/CommonJS questions, and Node/browser support questions.
metadata:
  package: tasra-sdk
  sources:
    - README.md#install
    - README.md#which-client-do-i-want
    - docs/api.md
---

# Getting started with tasra-sdk

tasra-sdk is the client side of a Tasra Network. A threshold key is shared
across `n` keeper nodes. Non-exportable slots require `k` keepers for each
operation; exportable sessions can reconstruct and cache the master key locally.
A DCQL rule controls credential-based access. Revoking access cannot revoke a
master key that an exportable session has already obtained.

## Which deployment are you on?

The SDK does not ship or host a network. The canonical deployment records are in
[t3-foundry/tasra-releases](https://github.com/t3-foundry/tasra-releases).
For Avalanche Fuji (chain ID **43113**), start with
[`networks/testnet/current.json`](https://github.com/t3-foundry/tasra-releases/blob/main/networks/testnet/current.json):
its `manifest` path is relative to `networks/testnet/`, and its `sha256` pins the exact
JSON bytes. The published deployment is
[`deployments/tasra-fuji-v1.json`](https://github.com/t3-foundry/tasra-releases/blob/main/networks/testnet/deployments/tasra-fuji-v1.json).
Read the pointer and record from the same reviewed commit; save that revision and
checksum with your app. Follow `tasra-chain`, "Public deployment manifest", for
the bootstrap. Do not copy contract addresses by hand.

The manifest includes public service URLs; select the verifier agent by
`services[].kind === 'verifier-agent'`. Keeper URLs come from the slot's on-chain
assignment. An active manifest is not a credential, a funded slot, or proof that
services are ready. See installed `node_modules/tasra-sdk/docs/prerequisites.md`
for the remaining enrollment and provisioning inputs. Offline examples need none.

`docs/DEVELOPER-EXPERIENCE.md` describes the intended public developer journey.
Live acceptance must exercise real credential issuance, decryption and issuer
revocation separately. Missing prerequisites are blocked checks, not passes;
offline examples establish local behavior only.

## 1. Install

```sh
npm install tasra-sdk
npm install tasra-sdk viem   # only if you will import tasra-sdk/chain
```

- ESM only: there is no CommonJS build and there will not be one. `import` works
  everywhere; `require('tasra-sdk')` also works on Node ≥ 22.12, because Node
  loads ES modules through `require` there.
- Runs in Node ≥ 22.12 and evergreen browsers. WebCrypto must exist.
- `viem` is an optional peer, needed only by the `tasra-sdk/chain` subpath.
- Entry points: `tasra-sdk` (managed client + primitives),
  `tasra-sdk/chain`, `tasra-sdk/committee`, `tasra-sdk/oid4vp`,
  `tasra-sdk/verifier-agent`, and `tasra-sdk/chain/node` — the Node-only
  transports (service discovery, gas relay, agent) that need `node:tls`.

## 2. What must exist before a session can open

The SDK does not ship or host a network. You need, from the network operator:
node URLs and a verifier URL (or an RPC + contract address book, and the SDK
discovers the rest on-chain), a `slotId`, and a credential that satisfies the
slot's rule. Apps in this ecosystem read them as `KK_NODE_URLS` (comma-separated),
`KK_VERIFIER_URL`, `KK_IDENTITY` (the holder DID; some apps and examples spell
the same value `KK_HOLDER`), `KK_SLOT_ID` and one of
`KK_JWT` (a session token, used as is), `KK_RENEWAL_TOKEN` (redeemed for a fresh
JWT as often as needed) or `KK_REDEMPTION_TOKEN` (redeemed once). The two tokens
come from the operator's verifier, see `tasra-credentials-and-sessions`. Use the same names so
your app and the fleet's own tooling agree. `KK_NODE_URLS` must be the keepers
that hold this slot, not every keeper in the fleet: `openSession` reads the
slot's public key from the first URL, and a node that does not hold the slot
answers 404. Pure functions (DCQL evaluation, envelope crypto, JWT inspection)
need nothing running — the offline round trip in step 5 is one of them and needs
none of the above: any 32 random bytes serve as a slot id, and you mint the key
pair yourself. A real `KK_SLOT_ID` is `0x` plus 64 hex characters: pass that
string to `openSession` as it stands, and `hexToBytes` (exported; the `0x`
prefix is optional) turns it into the 32 bytes the envelope functions take.

If the developer has none of these yet, point them at
`tasra-create-slot` (slot) and `tasra-credentials-and-sessions`
(credential) before this skill's step 4.

## 3. Choose a client

| Factory | Import | Endpoints come from | Key assembled locally? |
|---|---|---|---|
| `createTasraClient` | `tasra-sdk` | your config `{nodes, verifier}` | yes, lazily on first `decrypt` |
| `createTasraSlotClient` | `tasra-sdk/chain` | chain (slot committee + verifier set) | yes, lazily |
| `createCommitteeSlotClient` | `tasra-sdk/chain` | chain | never |
| `createTasraWriteClient` | `tasra-sdk/chain` | your config | n/a (on-chain writes) |
| `createTasraChainClient` | `tasra-sdk/chain` | your config | n/a (read client; input to the two slot clients) |

Rules of thumb:

- Known URLs, fastest start: `createTasraClient`.
- Exportable personal vault with discovered URLs: `createTasraSlotClient`
  (same `Session` API; its `decrypt` reconstructs the key).
- The key must never be reconstructed anywhere: `createCommitteeSlotClient`
  (see `tasra-committee-path`). Check the deployment authorization policy first:
  request-bound deployments require the verifier-agent flow in
  `tasra-oid4vp-wallet-and-verifier-agent`.
- `createTasraChainClient` is not an alternative; it is built first and
  passed as `chain` to the slot clients.

## 4. Open a session and use the key

```ts
import {createTasraClient} from 'tasra-sdk'

const kk = createTasraClient({
  nodes: ['https://node-1', 'https://node-2', 'https://node-3'],
  verifier: 'https://verifier',
  identity: 'did:example:alice',   // the holder DID; becomes the JWT subject. A PLACEHOLDER:
                                   // real verifiers enforce a DID-method accept-list and refuse
                                   // did:example — see tasra-credentials-and-sessions,
                                   // "Which holder DID", before you pick one.
})

const s = await kk.openSession(slotId, {renewalToken})   // slotId is the "0x…" string; auth modes below

const env = s.encrypt(new TextEncoder().encode('hello'))  // local, synchronous
const msg = await s.decrypt(env)                          // assembles the key on first use — ONLY on a slot created
                                                          // with exportable: true; other slots refuse (403) → use decryptCustody
// Signing requires a different slot: FROST for sign, threshold ECDSA for signDigest.
await s.close()                                           // zeroizes the assembled key
// kk.closeAll() closes every open session
```

`auth` is exactly one of:

- `{renewalToken}` — long-lived; the only mode that auto-renews the JWT.
- `{redemptionToken}` — single-use credential exchanged for a JWT.
- `{vpJwt: {dcqlRule, credentials, holderProof}}` — signed VCs plus a holder proof.
- `{jwt}` — a JWT you already hold.

Details and renewal behaviour: `tasra-credentials-and-sessions`.

## 5. Offline round trip (no network) — complete and runnable

Production threshold keys are created by the keeper fleet. Exportable sessions
can reconstruct them; the non-exportable committee path never does. For a
local test, mint a stand-in BLS12-381 key pair with `@noble/curves`. The SDK
depends on it, but your project does not, so run `npm install @noble/curves@1`
(the snippet uses the v1 names, `randomPrivateKey` and `G2.ProjectivePoint`, which
v2 renamed). Skipping the install works only while tasra-sdk happens to hoist
a v1 copy into your `node_modules`.
The two byte formats matter: `msk` is the scalar as **32 bytes little-endian**,
`mpk` is the **96-byte compressed G2** point.

```ts
import {encryptEnvelope, decryptWithMasterKey, toBytes, buildTasraText, parseTasraPost, isTasraPost} from 'tasra-sdk'
import {bls12_381} from '@noble/curves/bls12-381'

// stand-in key pair (tests only)
const skBE = bls12_381.utils.randomPrivateKey()                                  // 32 bytes, big-endian
const mpk  = bls12_381.G2.ProjectivePoint.fromPrivateKey(skBE).toRawBytes(true)  // 96-byte compressed G2
const msk  = skBE.slice().reverse()                                              // the SDK reads the scalar LITTLE-endian

const slotId = crypto.getRandomValues(new Uint8Array(32))     // exactly 32 bytes
const label  = slotId                                          // AEAD label bytes; conventionally the slot id.
                                                               // Unrelated to the client's `identity` DID in step 4.
const epoch  = 1n                                              // bigint (null = legacy v1 envelope)

const env    = encryptEnvelope(slotId, mpk, label, new TextEncoder().encode('hello'), epoch)
const wire   = buildTasraText(toBytes(env))    // "[KK]<base64>" — safe for any transport; one envelope holds
                                                   // up to MAX_PLAINTEXT_LEN (1 MiB − 16) bytes, chunk anything larger
isTasraPost(wire)                              // true; cheap check before parsing
const parsed = parseTasraPost(wire)            // null if not an envelope; .ciphertext is a structured Ciphertext (not bytes —
                                                   // pass it straight to decryptWithMasterKey), .identity = the label bytes
                                                   // (the AEAD label, never a DID), .epoch: bigint | null
if (!parsed) throw new Error('not a [KK] envelope')
const plain  = decryptWithMasterKey(msk, parsed.ciphertext, parsed.identity)   // Uint8Array
console.log(new TextDecoder().decode(plain))
msk.fill(0); skBE.fill(0)                          // wipe both copies of the secret when done
```

Argument constraints: `slotId` must be exactly 32 bytes; always pass `epoch` as
a `bigint` literal such as `1n` (a number slips through `encryptEnvelope` and
only fails later, at `toBytes`, with "Cannot convert 1 to a BigInt"); the label
is any bytes and comes back as `parsed.identity`. `decryptWithMasterKey`
**throws a plain `Error`** — message `decryptWithMasterKey: AEAD authentication
failed` — on a wrong key or tampered ciphertext; it never returns bad plaintext,
and it is not a `TasraError`, so catch it directly. A big-endian `msk` fails with either
"leToScalar: non-canonical scalar" (when the reversed bytes exceed the field
order) or "AEAD authentication failed"; keep the `.reverse()`.

## Common mistakes

- ❌ Passing two auth fields at once. `openSession` takes exactly one mode.
- ❌ Expecting `{jwt}` or `{redemptionToken}` sessions to renew. Only
  `{renewalToken}` re-mints; the others fail loud on expiry, open a new session.
- ❌ Importing `createTasraSlotClient` from `tasra-sdk`. It is on
  `tasra-sdk/chain` and needs `viem` installed.
- ❌ Calling `decrypt` and forgetting `close()`. The assembled key lives in
  memory until `close()` zeroizes it.
- ❌ Expecting `session.decrypt` to work on a group or credential slot. Keepers
  release raw shards only for slots created with `exportable: true`; otherwise
  they answer 403 and you decrypt over the threshold (`tasra-sign-and-decrypt`).
- ❌ Hardcoding `localhost` endpoints in application code. Endpoints belong in
  configuration, or use the slot client and discover them on-chain.
- ❌ Passing `epoch` as a number (fails later, at `toBytes`) or a big-endian
  secret key (fails with "non-canonical scalar" or "AEAD authentication failed");
  see step 5.

## Where to read more

- Installed README: `node_modules/tasra-sdk/README.md`, sections "Install",
  "Which client do I want?", "First result — no network required".
- Types: `node_modules/tasra-sdk/dist/index.d.ts` (`TasraClientConfig`,
  `SessionAuth`, `Session`); byte formats in `dist/crypto/envelope.d.ts` and
  `dist/crypto/kem.d.ts`.
- Runnable examples ship in `node_modules/tasra-sdk/examples/`. Start with
  `npx tsx node_modules/tasra-sdk/examples/minimal.ts`; see `docs/prerequisites.md`
  before running live examples.
