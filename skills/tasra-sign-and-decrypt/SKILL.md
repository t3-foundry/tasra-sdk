---
name: tasra-sign-and-decrypt
description: Threshold signing and decryption with tasra-sdk — FROST-Ed25519 custody and shard-delivery signing, threshold ECDSA for Ethereum accounts (signEoaDigest, ethers Signer and viem Account adapters), and the decrypt paths that never reconstruct the key (decryptCustody, decryptWithShardDelivery, combineDecryptShares). Use for "sign a transaction with tasra", "tECDSA slot as an Ethereum account", "ethers signer", "viem account", "decrypt without assembling the key".
metadata:
  package: tasra-sdk
  sources:
    - docs/signing.md
    - README.md#which-client-do-i-want
    - dist/signing/frost.d.ts
    - dist/signing/ecdsa.d.ts
    - dist/decryption/client.d.ts
---

# Sign and decrypt over the threshold

## Signing

Through a session: `s.sign(message, opts?)` returns a FROST-Ed25519 signature
with the node coordinating the ceremony (a `frost`-mode slot); `s.signDigest(digest)`
is threshold ECDSA over secp256k1 for a slot backing an EVM account, returning the
same `{groupPublicKey, r, s, yParity}` as `signEoaDigest` after refreshing the JWT.
It always asks the session's first node, so call `signEoaDigest` directly when you
have no session or need to choose the keeper. Both need
only the JWT; no key is assembled. A threshold-ECDSA slot is a distinct key type:
create it with `createSlot({..., mode: 'tecdsa'})` (`KeyRegistry.Mode` also has
`bls-bn254` and `tecdsa-p256`).

**FIRST: does this deployment still accept the JWT route at all?** `signEoaDigest`
and `s.signDigest` both POST to the keeper's legacy bearer-JWT route
`/v1/sign/eoa-digest`. A keeper running the production posture
(`api.production_posture = true`) refuses it outright, whatever you send:

```
HTTP 403 {"error":"legacy JWT eoa-digest cannot satisfy committee-only or
          holder-bound operation authorization"}
```

This is a **deployment-wide** refusal, not a fact about your slot: the same 403
comes back on a slot with no verifier policy and no dual-control policy, with a
rule-satisfying JWT and with an admin-scoped one. Read literally it looks like
tECDSA is unavailable. It is not — see "Threshold ECDSA under the production
posture" below, which is the path that works there. Everything in the rest of this
section applies to a deployment that has not enabled the posture.

Two further deployment-side conditions, and they are separate: the keepers must
**key** that mode (otherwise the slot never gets a group key), and they must be
able to **complete the signing ceremony** — `/v1/sign/eoa-digest` answers HTTP 504
with a ceremony-timeout error when they cannot reach each other well enough, even
though creation and DKG succeeded.
A third condition is per-request rather than per-deployment: a keeper that holds
the slot but is outside the chosen signing set answers HTTP 400 saying its local
node index is not in that set, so try the slot's keepers in turn instead of
pinning one. `signEoaDigest` throws `TasraHttpError` for all of them; its
`status` tells them apart: 400, try the next keeper; 403, the deployment refuses
the JWT route entirely (go to the committee path); 404, the route is disabled on
this deployment; 504, the ceremony timed out — `retryable` is true, so retry it a
bounded number of times, on the next holder or after a backoff, rather than
failing on the first one. See `tasra-handle-errors`.

**tECDSA DKG is slower than the others.** It runs an extra AuxInfo phase, so the
slot's group key stays empty for roughly 30–40 s after creation where a `bls` or
`frost` slot is ready in a few. Poll for it (`resolveSlotGroupKey`, or the node's
`keys get`) instead of reading once and concluding the mode is unsupported.

## Threshold ECDSA under the production posture

When the keepers refuse the JWT route, the authorization has to be a compound token
from the verifier agent — exactly as for `sign` and `ibe-extract`
(`tasra-oid4vp-wallet-and-verifier-agent`). The keeper exposes
**`POST /v1/committee/sign/eoa-digest`** for it, and **neither the SDK nor
tasra-cli wraps that route**, so call it with `fetch`:

```ts
import {keccak256, serializeTransaction, hexToBytes} from 'viem'
import {privateKeyToAccount} from 'viem/accounts'
import {openVerifierAgentSession, awaitVerifierAgentResult, presentToRequestUri, ed25519HolderKey} from 'tasra-sdk/oid4vp'

const digest = keccak256(serializeTransaction(tx))     // the ONLY thing the network sees

// 'sign' binds sha256(message), and the handler recomputes sha256(digest) — so the
// message IS the 32-byte digest. Do not pass the transaction.
const session = await openVerifierAgentSession({
  verifierAgentUrl, chainId, keyRegistry, slotId,
  action: 'sign',
  message: hexToBytes(digest),
  description: 'Spend 0.5 AVAX from the treasury account',
  signer: privateKeyToAccount(slotCreatorKey),          // the SLOT CREATOR signs the operation
})
const resultP = awaitVerifierAgentResult(session, {timeoutMs: 120_000})
await presentToRequestUri(session.qrPayload, [{sdJwt: credential}], ed25519HolderKey(holderSeed))
const {token, verifierProofs} = await resultP

const res = await fetch(`${nodeUrl}/v1/committee/sign/eoa-digest`, {
  method: 'POST', headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    committee_token: token,                             // the CompoundTokenWire object as-is
    digest,                                             // 0x-hex, 32 bytes
    verifier_proofs: (verifierProofs ?? []).map(p => ({  // snake_case on the wire
      verifier_index: p.verifierIndex, operator: p.operator, pubkey: p.pubkey, proof: p.proof,
    })),
  }),
})
// → {group_public_key, mode, signature_r, signature_s, recovery_id}
const {signature_r: r, signature_s: sHex, recovery_id} = await res.json()
const signed = serializeTransaction(tx, {r, s: sHex, yParity: recovery_id})
```

Try the slot's keepers in turn: one outside the chosen signing set refuses while
another serves.

**Who may spend is the slot's DCQL rule, and it can admit several people.** Give the
rule a `values` list and each holder presents their own credential, independently —
no coordination, no shared key material:

```json
{"credentials":[{"id":"signer","format":"dc+sd-jwt","meta":{"vct_values":["TreasurySigner"]},
  "claims":[{"path":["iss"],"values":["did:web:hr.acme.example"]},
            {"path":["sub"],"values":["did:demo:alice","did:demo:bob"]}]}]}
```

A holder outside that list is refused **by their own wallet**, before anything is
sent: `no held credential answers: signer`.

⚠ **Dual control and tECDSA do not compose.** `KeyRegistry`'s dual-control policy
(the CLI's `slot dual-control` / `dual-approve`; the SDK write client exposes
neither) makes the committee EOA handler refuse the slot before it does anything
else — `slot requires dual-control approval` — and the approval route
`/v1/dual-sign` takes `{key_slot_id, message_hex, signing_set}`, the FROST shape,
not an EOA digest. A tECDSA slot with a dual-control policy pinned cannot sign at
all, and the policy is set-once, so recovering from it means a new slot. To let
several people share one EVM account today, use the multi-holder rule above.

Primitives, when you drive it yourself:

- `signCustody(opts)` — one-shot, node-coordinated FROST.
- `signWithShardDelivery(opts)` — you coordinate; nodes return partial
  signatures; `aggregateFrostSignature` and `verifyFrostSignature` finish locally.
- `signUserRequest(secretKey, slotId, message, requestId)` — a user-side
  authorization signature the node can verify (`userSignaturePayload` is the bytes).
- `signEoaDigest({nodeUrl, jwt, slotId, digest: Uint8Array /* 32-byte prehash */})` →
  `{groupPublicKey: Uint8Array /* 33-byte compressed secp256k1 */, r: Uint8Array /* 32 BE */,
  s: Uint8Array /* 32 BE, low-s */, yParity: 0 | 1}`. r and s are byte arrays;
  convert them with viem's `bytesToHex` (ethers: `hexlify`) where those libraries want hex.
- `addressFromEoaPubkey(pubkey: Uint8Array)` → EIP-55 address (33-byte
  compressed or 65-byte `0x04…` uncompressed; a bare 64-byte X‖Y is not accepted).
- `ethSignatureV(yParity: number, chainId?: number)` → `number`: omit `chainId` for `personal_sign`
  and EIP-712 (27/28) and for typed transactions (use `yParity` directly); pass
  it only for legacy EIP-155 transactions.
- `redeemRenewalToken(verifierUrl, renewalToken)` → `Promise<{token, exp, holder}>`,
  the usual `getJwt` source for an adapter.
- `fetchMpk(nodeUrl, slotId)` → `{mpkBytes: Uint8Array, epoch}`, unauthenticated:
  the 33-byte compressed key of a threshold-ECDSA slot, hence the adapter's address.
- Inputs: the **tECDSA** slot id (`KK_TECDSA_SLOT_ID`, a different slot from the
  frost/BLS one this ecosystem calls `KK_SLOT_ID`); the keepers that hold it, found by
  asking each known keeper (`KK_ALL_NODE_URLS`, else `KK_NODE_URLS`) with `fetchMpk`,
  which answers 404 where the slot is not held (`tasra-chain` reads the committee
  on chain); a JWT the keepers accept **for that slot**: `KK_JWT` as is, or
  `KK_RENEWAL_TOKEN` redeemed at `KK_VERIFIER_URL` and reused until its `exp` (Unix
  seconds) — one token is not automatically good for both slots, and `signEoaDigest`
  answers 401/403 when it is not; and `KK_CHAIN_ID`.

### An Ethereum account whose key is split across the fleet

```ts
import {signEoaDigest, ethSignatureV, addressFromEoaPubkey, redeemRenewalToken} from 'tasra-sdk'

const {groupPublicKey, r, s, yParity} = await signEoaDigest({nodeUrl, jwt, slotId, digest})
const from = addressFromEoaPubkey(groupPublicKey)
const v = ethSignatureV(yParity, chainId)          // chainId ONLY for legacy txs; omit it for
                                                   // messages, EIP-712 and typed transactions
```

A viem `Account` adapter is included in `node_modules/tasra-sdk/examples/viem-account.ts`.
The shape below hashes locally and lets the fleet sign the digest:

```ts
import {toAccount} from 'viem/accounts'
import {hashMessage, hashTypedData, keccak256, serializeTransaction, getTransactionType, numberToHex, bytesToHex, concatHex, hexToBytes} from 'viem'
import {signEoaDigest, ethSignatureV, addressFromEoaPubkey, redeemRenewalToken, fetchMpk, TasraHttpError} from 'tasra-sdk'

// jwt: KK_JWT if set; otherwise redeem the renewal token once and reuse it until shortly before exp (Unix seconds)
let issued: {token: string; exp: number} | undefined
const getJwt = async () => {
  if (jwt) return jwt
  if (!issued || issued.exp - 30 < Date.now() / 1000) issued = await redeemRenewalToken(verifierUrl, renewalToken)
  return issued.token
}
// The keepers holding the slot, and its 33-byte compressed secp256k1 key: no ceremony needed.
const holders: string[] = []
let mpkBytes: Uint8Array | undefined
for (const url of nodeUrls) {
  let got: Uint8Array
  // 404 means this keeper does not hold the slot; an unreachable keeper, a 5xx or a cold DKG
  // (fetchMpk throws a retryable TasraError for a slot served with no key) is that one
  // keeper's problem — skip it and keep asking the rest rather than abandoning discovery.
  try { got = (await fetchMpk(url, slotId)).mpkBytes } catch (e) { console.warn(`${url}: ${e}`); continue }
  // Every holder must serve the same group key; a disagreement means a stale or wrong deployment.
  if (mpkBytes && bytesToHex(got) !== bytesToHex(mpkBytes)) throw new Error(`${url} serves a different key for this slot`)
  mpkBytes = got
  holders.push(url)
}
if (!mpkBytes) throw new Error('no keeper holds this tECDSA slot')
const address = addressFromEoaPubkey(mpkBytes)
async function signDigest(digest: Uint8Array, chainId?: number) {
  let timedOut = 0
  for (const nodeUrl of holders) {
    try {
      const {r, s, yParity} = await signEoaDigest({nodeUrl, jwt: await getJwt(), slotId, digest})
      return {r: bytesToHex(r), s: bytesToHex(s), yParity, v: ethSignatureV(yParity, chainId)}   // r, s are already 32 bytes
    } catch (e) {
      if (!(e instanceof TasraHttpError)) throw e
      if (e.status === 400) continue                   // outside the signing set: next holder
      if (e.status === 504 && ++timedOut < 3) continue  // ceremony timed out: bounded retry on the next holder
      throw e                                           // 404 route off, 401/403 auth, everything else
    }
  }
  throw new Error('no holder produced a signature')
}
const account = toAccount({
  address,
  signMessage:   async ({message}) => { const {r, s, v} = await signDigest(hexToBytes(hashMessage(message))); return concatHex([r, s, numberToHex(v, {size: 1})]) },
  signTypedData: async (td)        => { const {r, s, v} = await signDigest(hexToBytes(hashTypedData(td)));    return concatHex([r, s, numberToHex(v, {size: 1})]) },
  signTransaction: async (tx, opts) => {
    const serialize = opts?.serializer ?? serializeTransaction               // honour a chain's custom serializer
    const legacyChainId = getTransactionType(tx) === 'legacy' ? tx.chainId : undefined
    const {r, s, yParity, v} = await signDigest(hexToBytes(keccak256(await serialize(tx))), legacyChainId)
    return serialize(tx, {r, s, yParity, v: BigInt(v)})                    // typed txs use yParity; legacy uses the EIP-155 v
  },
})
```

`account.signTransaction` is typed as a plain `Hex`; cast to
`TransactionSerialized` before `parseTransaction` / `recoverTransactionAddress`
(the parameterised `TransactionSerialized<'eip1559'>` or `<'legacy'>` narrows the
parsed result when you already know the type). Declare typed-data literals `as const` so
`signTypedData` infers the primary type. An ethers v6 `AbstractSigner` is the
same three methods. The node route for
`signEoaDigest` (`/v1/sign/eoa-digest`) can be feature-gated per deployment; a
404 there means the operator has not enabled it.

## Decryption, from managed to raw

| Call | Assembles the key? | Use when |
|---|---|---|
| `session.decrypt(env)` | yes, lazily, in your process | a managed session on an `exportable: true` slot; other slots answer 403 |
| `createCommitteeSlotClient(...).decrypt(slotId, ...)` | no | committee path (`tasra-committee-path`) |
| `decryptCustody(opts)` | no | a node coordinates the ceremony |
| `decryptWithShardDelivery(opts)` | no | you coordinate; nodes return partial shares |
| `combineDecryptShares(shares, ct, identity, {verify})` | no | you already hold the shares; `verifyDecryptShare` checks each |
| `decryptWithMasterKey(msk, ct, identity)` | you already did | pure local crypto |

The paths that send the ciphertext to keepers (the committee client, `decryptCustody`,
`decryptWithShardDelivery`) are bounded by the node's request limits: a 64 KiB request body by
default, with the ciphertext base64-encoded in it, which leaves roughly 45 KiB of plaintext per
envelope. For larger data, put a random data key in the envelope and encrypt the data locally
with it.

Assembling the key (`fetchAndAssembleKey({urls, jwt}, slotId)`) is the one
operation that reconstructs whole key material client-side; the keepers allow
it only for slots created with `exportable: true`. Keep it only as long as
needed and wipe it (`msk.fill(0)`; `Session.close()` does this).

`decryptCustody({nodeUrl, jwt, slotId, ciphertext, identity, decryptingSet, blsPeers, ciphertextEpoch})`
takes the envelope's parts from `fromBytes(env)`; `decryptingSet` are the BLS
identifiers of the keepers you ask to run the ceremony and `blsPeers` their
`{id, peerId}` pairs, both readable from each keeper's `/v1/info`
(`node_identifier`, `peer_id`). The identity travels to the node as UTF-8
**text**, so encrypt under a text identity for this path —
`session.encrypt(msg, {identity: new TextEncoder().encode('did:example:alice')})` —
the session's default identity is the binary slot id and fails the AEAD check
on the node (HTTP 500 "AEAD failed").

Verifying a FROST result: `verifyFrostSignature(sig.groupPublicKey, message, sig.signature)`
takes the original message bytes, not `sig.messageSha256`.

## Common mistakes

- ❌ Using a `bls` slot for signing, a `frost` slot for encryption, or either
  for `signEoaDigest`. The slot's mode decides which ceremonies it supports.
- ❌ Assembling the key just to decrypt once. Prefer `decryptCustody` or the
  session's lazy assembly with `close()`.
- ❌ Forgetting `chainId` in `ethSignatureV` for **legacy** transactions (typed
  transactions and messages want 27/28 or the bare `yParity`).
- ❌ Treating `r`/`s` as bigints or hex strings. The SDK returns 32-byte arrays; convert
  with `bytesToHex` only where a library wants hex.
- ❌ Passing `chainId` to `ethSignatureV` for a message or typed-data signature.
  Those want 27/28; only legacy transactions want the EIP-155 form. Typed
  transactions are serialised from `yParity`; a `v` you also pass is ignored.

## Where to read more

- `node_modules/tasra-sdk/dist/signing/*.d.ts`,
  `node_modules/tasra-sdk/dist/decryption/*.d.ts`.
