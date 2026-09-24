# Prerequisites

## Public testnet status

Canonical deployment records are published in
[t3-foundry/tasra-releases](https://github.com/t3-foundry/tasra-releases).
Avalanche Fuji uses chain ID **43113**. Start with
[`networks/testnet/current.json`](https://github.com/t3-foundry/tasra-releases/blob/main/networks/testnet/current.json),
which names `deployments/tasra-fuji-v1.json` and carries its `sha256`. Resolve the
manifest path relative to `networks/testnet/` and read both files from the same
reviewed repository commit. Preserve the exact JSON bytes and record the revision
and checksum with the application. Network records are updated by commit, separately
from the CLI binary release assets.

Use `parsePinnedNetworkManifest` and `addressBookFromManifest`; the complete
bootstrap is in [tasra-chain](../skills/tasra-chain/SKILL.md#public-deployment-manifest).
Use `NETWORKS.testnet.rpcUrl` for the public RPC or supply your own Fuji RPC.
The manifest publishes verifier-agent, relayer and explorer URLs in `services[]`;
keeper and verifier URLs are discovered from chain. Do not invent missing endpoints.

An active manifest establishes deployment configuration, not completed live
acceptance. Credential enrollment, a funded account/slot, rule provisioning,
compatible service versions, revocation timing and support instructions are separate
prerequisites. Obtain any missing inputs from the deployment operator; report the
specific blocked operation instead of treating the whole network as unpublished.

## Offline first result

```sh
npm install tasra-sdk
npm install --save-dev tsx
npx tsx node_modules/tasra-sdk/examples/minimal.ts
```

Expected output: `Hello Tasra`. Public demo keys demonstrate local crypto only.
The example requires no network deployment or `viem`. Examples ship in the package.

## Application configuration

Install `viem` for the chain clients. Use a provisioned **non-exportable BLS slot**,
an anchored verifier-set snapshot, sufficient metering funds, and a credential issued
to your holder DID. The application never needs keeper admin or issuer secrets.

| Environment variable | Value supplied by you or the deployment handoff |
|---|---|
| `KK_MANIFEST_FILE` | Local path to the exact downloaded deployment-manifest bytes |
| `KK_MANIFEST_SHA256` | SHA-256 from the trusted release checksum, not a digest invented from an untrusted download |
| `KK_RPC_URL` | RPC for the manifest's chain |
| `KK_SLOT_ID` | Provisioned BLS slot, 0x-prefixed bytes32 |
| `KK_HOLDER_KEY_FILE` | Private file containing a 32-byte Ed25519 holder seed as hex; examples derive its did:key |
| `KK_CREDENTIALS_FILE` | Private JSON file containing an array of issuer-signed compact-JWS credentials for that DID |
| `KK_VERIFIER_AUDIENCE` | Expected holder-proof audience published by the deployment |
| `KK_SIGN_SLOT_ID` | Separate FROST slot, required only for signing and live acceptance |

Keep key/credential files outside source control and readable only by their owner.
These Node examples use a file-backed holder; applications can instead supply the
SDK's `HolderSigner` callback backed by a wallet or key store.

```sh
npx tsx node_modules/tasra-sdk/examples/getting-started.ts
npx tsx node_modules/tasra-sdk/examples/committee-slot.ts
```

These direct committee examples require a slot with a verifier policy and a deployment
that accepts compound tokens without request binding. If keepers enforce
`api.require_request_binding`, use the verifier-agent authorization flow described in
[the wallet skill](../skills/tasra-oid4vp-wallet-and-verifier-agent/SKILL.md).
Do not weaken the deployment's policy to run an example.

The first command verifies a threshold encrypt/decrypt round trip. The second verifies
a threshold FROST signature. Missing inputs fail nonzero. Neither creates a network,
mints credentials, nor substitutes mock authorization.

## Operator setup

`examples/provision-slot.ts` creates a dedicated slot, persists recovery inputs before
submitting transactions, waits for DKG, and provisions the committed rule on keepers.
It selects commit/reveal when the registry requires it.

In addition to manifest/RPC configuration, provide:

| Variable | Meaning |
|---|---|
| `KK_CREATOR_KEY_FILE` | Private file containing a funded EVM key as 0x-prefixed hex |
| `KK_RULE_FILE` | Exact rule to commit and provision |
| `KK_SLOT_OUTPUT` | New recovery-record path; existing files are never overwritten |
| `KK_ADMIN_JWT` | Short-lived keeper admin JWT for rule provisioning |
| `KK_K`, `KK_N` | Threshold and keeper count |
| `KK_SLOT_MODE` | `bls` for encryption or `frost` for signing |
| `KK_CUSTODY` | `threshold`, or explicitly `exportable` for a personal BLS vault |

```sh
npx tsx node_modules/tasra-sdk/examples/provision-slot.ts
```

Preserve the recovery record even if provisioning fails. Follow deployment instructions
to fund metering, configure verifier policy, and enroll the holder before application use.
The example does not replace the deployment operator's lifecycle/recovery tooling.

## Exportable personal vault

An exportable slot is a separate custody choice. The holder can retain its master key;
revocation does not prevent future local decryption with that key. Deployments requiring
commit/reveal cannot create these slots with the current API, and the example refuses
that combination rather than weakening the registry requirement.

For an existing exportable BLS slot, configure the application inputs plus `KK_DCQL_RULE`
and run `examples/personal-vault.ts`. This example uses one-shot VP authentication;
it does not claim silent renewal.

[Developer journey](DEVELOPER-EXPERIENCE.md) · [Glossary](glossary.md) · [Release acceptance](RELEASING.md#live-acceptance)
