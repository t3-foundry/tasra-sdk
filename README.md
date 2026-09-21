# tasra-sdk

**Credential-gated encryption and threshold signing for TypeScript applications.**

Use Tasra to protect application data, authorize access with verifiable credentials,
and sign through a distributed keeper network. Tasra is the platform; Keykeeper is
its threshold key-management implementation.

> **Version 0.1.0 — initial release.** Minor releases may change APIs; patches do not.

## Install

```sh
npm install tasra-sdk
```

ESM-only; Node ≥22.12 and modern browsers with WebCrypto in a secure context.
Install the optional `viem` peer only for chain integration:

```sh
npm install tasra-sdk viem
```

The package includes declarations, runnable examples, docs, and agent skills.
[Installation and compatibility](docs/installation.md).

## First result — no network required

Copy this into `demo.ts`, install `tsx` with `npm install --save-dev tsx`, and run
`npx tsx demo.ts`. It prints `Hello Tasra`. These are **public demo keys** and must
never protect real data. This demonstrates local crypto, not network authorization.

<!-- offline-example -->
```ts
import {encryptEnvelope, decryptWithMasterKey, hexToBytes} from 'tasra-sdk'

/** Public, fixed DEMO keys. Never encrypt a real secret with these. */
function offlineRoundTrip(): string {
  const msk = new Uint8Array(32)
  msk[0] = 1
  const mpk = hexToBytes('93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8')
  const identity = new TextEncoder().encode('demo')
  try {
    const envelope = encryptEnvelope(new Uint8Array(32), mpk, identity,
      new TextEncoder().encode('Hello Tasra'), 0n)
    return new TextDecoder().decode(decryptWithMasterKey(msk, envelope.ciphertext, identity))
  } finally {
    msk.fill(0)
  }
}

console.log(offlineRoundTrip()) // Hello Tasra
```

Or run the shipped example from your application directory:

```sh
npx tsx node_modules/tasra-sdk/examples/minimal.ts
```

## Choose the custody model

| Model | How decryption works | Revocation boundary |
|---|---|---|
| **Threshold custody — start here for credential-gated applications** | Keepers cooperate for each authorized operation; the master key stays split. | Refuses future authorized operations after the deployment's revocation and token-expiry window. Plaintext already received cannot be revoked. |
| Exportable personal vault | A managed session reconstructs and caches the master key from keeper shards. Requires a slot created with `exportable: true`. | A holder can retain the exported key and decrypt locally afterwards. Revocation cannot take that key back. |

FROST signing and BLS encryption use separate slots. Threshold ECDSA uses a third
slot mode. Do not call all operations on one slot regardless of its mode.
The package has [not had an independent cryptographic audit](SECURITY.md#cryptographic-posture).

## First live application

Start with a provisioned, non-exportable BLS slot and a credential issued to your
holder DID. The application example verifies a pinned deployment manifest, discovers
keepers from chain, obtains fresh holder proofs for the drawn verifiers, and performs
an encrypt/decrypt round trip without exporting the master key:

```sh
npm install tasra-sdk viem
npm install --save-dev tsx
# Configure the inputs listed in docs/prerequisites.md first.
npx tsx node_modules/tasra-sdk/examples/getting-started.ts
```

Use your deployment's onboarding records for the manifest/checksum, enrollment,
funding, rule-provisioning instructions, compatible versions, and support contact.
[Full prerequisites and configuration](docs/prerequisites.md).

Slot creation is an **operator setup** example (`examples/provision-slot.ts`),
separate from the application. It selects direct creation or commit/reveal based on
the registry, persists the recovery record before submitting, and provisions the rule.
Metering funding and credential enrollment follow the deployment's instructions.

For threshold signing, use `examples/committee-slot.ts` with a separate FROST slot.
For exportable personal vaults, use `examples/personal-vault.ts`.

## Managed sessions for exportable vaults

This integration fragment assumes an exportable BLS slot and a renewal token issued
by your deployment. Use the complete personal-vault example for configuration.

```ts
import {createTasraClient} from 'tasra-sdk'

const client = createTasraClient({nodes, verifier, identity: holderDid})
const session = await client.openSession(slotId, {renewalToken})
try {
  const encrypted = session.encrypt(new TextEncoder().encode('vault data'))
  const decrypted = await session.decrypt(encrypted)
} finally {
  await client.closeAll()
}
```

`encrypt()` is synchronous and local: it uses the session's available public key
and epoch, and does not refresh credentials or query the network. `decrypt()` and
signing operations check authentication freshness. Only `{renewalToken}` silently
renews; other authentication modes require reopening the session after expiry.
The first decrypt assembles the master key, with reassembly on detected rotation.
Closing clears the session's owned key buffer; it cannot erase copies retained elsewhere.

## Which client do I want?

| Factory | Entry | Purpose |
|---|---|---|
| `createCommitteeSlotClient` | `/chain` | Credential-gated threshold operations; no master-key export. |
| `createTasraSlotClient` | `/chain` | Chain-discovered managed sessions; local decrypt requires an exportable slot. |
| `createTasraClient` | main | Managed sessions with explicitly configured service endpoints. |
| `createTasraChainClient` | `/chain` | Read client used by the chain-discovered clients. |
| `createTasraWriteClient` | `/chain` | On-chain slot creation, funding, registration, and lifecycle operations. |

Lower-level APIs remain available for envelope crypto, policy evaluation, credentials,
partial decryption, committee tokens, and signing. [Capability catalogue](docs/capabilities.md).

---

## Documentation

| | |
|---|---|
| [What you can do](docs/capabilities.md) | The capability catalogue — every major thing the SDK does, and the call that does it |
| [Prerequisites](docs/prerequisites.md) | What must exist before a session opens |
| [API surface](docs/api.md) | Every export, grouped by purpose |
| [Chain](docs/chain.md) | Reads, writes, slot creation, on-chain discovery |
| [Signing](docs/signing.md) | Threshold ECDSA with ethers, viem, Hardhat |
| [Errors](docs/errors.md) | The taxonomy, and what is worth retrying |
| [Architecture](docs/architecture.md) | What the session does underneath |
| [Glossary](docs/glossary.md) | Slot, k-of-n, MSK, epoch, DKG, DCQL, committee |

[**Full documentation index →**](docs/README.md)

---

## Using a coding agent?

The package ships [agent skills](skills/README.md) — one folder per task: getting
started, creating a slot, credentials, DCQL rules, errors, signing, IBE, chain reads,
the committee path, OpenID4VP, and obtaining real credentials from a Hovi issuer.

Installing the package does not register them with your agent — see the
[installation instructions](skills/README.md), and refresh copied skills after every
SDK upgrade. They are prose, maintained by hand: nothing checks them against the built
declarations, so treat a skill as documentation of the version it shipped with and
verify a symbol against `dist/**/*.d.ts` if it does not resolve.

---

## Project

- **Contributing** — [CONTRIBUTING.md](CONTRIBUTING.md): setup, the gate, tests, conformance vectors.
- **Security** — [SECURITY.md](SECURITY.md). Report vulnerabilities privately; never in a public issue.
- **Changes** — [CHANGELOG.md](CHANGELOG.md). Pre-1.0: a minor may change API, a patch never does.
- **Licence** — [Apache-2.0](LICENSE).

```
the network ──────────────── keepers + verifiers + accountants + contracts, the source of truth
        ▲ HTTP / JSON-RPC
tasra-sdk (this repo) ───── a managed Client/Session over product-agnostic primitives
        ▲ composed by
your product ─────────────── a messaging app, a vault, a signer, an explorer — anything
```
