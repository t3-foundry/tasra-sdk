# Under the hood — the primitives the session orchestrates

> What the managed session is doing underneath, and where this package sits.

What `openSession` does internally, if you want to drive it yourself:

```ts
import {
  redeemCredential, fetchMpk, fetchAndAssembleKey,
  encryptEnvelope, toBytes, buildTasraText, hexToBytes,
} from 'tasra-sdk'

// 1. obtain a DCQL-gated JWT from the verifier
const {token: jwt} = await redeemCredential(verifierUrl, redemptionToken, 'did:example:alice')

// 2. assemble the slot's master key from k-of-n nodes (no node ever sees it whole)
const {mpkBytes, epoch} = await fetchMpk(nodeUrls[0], slotHex)
const msk = await fetchAndAssembleKey({urls: nodeUrls, jwt}, slotHex)

// 3. encrypt — publish buildTasraText(toBytes(env)) via any transport;
//    decrypt with `msk` on the way back
const env = encryptEnvelope(hexToBytes(slotHex), mpkBytes, aad, plaintextBytes, BigInt(epoch))
```

The master key only ever exists ephemerally, in your process — `Session.close()`
wipes it when you're done (if you hold a raw `msk` from `fetchAndAssembleKey`,
`msk.fill(0)` is the equivalent).

---

## Layering

```
the network ──────────────── keepers + verifiers + accountants + contracts, the source of truth
        ▲ HTTP / JSON-RPC
tasra-sdk (this repo) ───── a managed Client/Session over product-agnostic primitives
        ▲ composed by
your product ─────────────── a messaging app, a vault, a signer, an explorer — anything
```

License: Apache-2.0.

---

[← Back to the README](../README.md) · [Documentation index](README.md)
