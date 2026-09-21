# Developer experience: a live deployment + the released CLI + this SDK

**Public testnet handoff: not yet published.** Its canonical release records will
be published in `tasra-releases`. Do not infer live endpoints from fixtures or network
profiles. Until then, live acceptance remains pending.

The developer journey uses a live deployment, the separately released `tasra-cli`, and
the published SDK. No sandbox broker, synthetic network, test issuer or locally
generated network shares belong in the acceptance path.

## Who owns what

| Artifact | Owns |
|---|---|
| Binary distribution | Versioned `tasra-cli` archives, checksums and signatures, with per-OS instructions |
| Deployment record | Canonical addresses, public RPC / verifier-agent / service endpoints, compatible CLI and SDK versions, funding and issuer instructions |
| `tasra-cli` | Real account and slot operations, commit/reveal, funding and diagnostics |
| `tasra-sdk` | The wallet protocol, encryption / decryption / signing integrations, and the agent skills |

The deployment handoff must link CLI archives for Linux x86_64/aarch64, macOS aarch64 and
Windows x86_64, each with `SHA256SUMS` and a signature bundle.

## First successful run

1. Download the pinned CLI binary and verify it against the release checksum.
2. Install the SDK:

   ```sh
   npm install tasra-sdk viem
   npm audit signatures        # registry signatures and available provenance
   ```

3. Fund a developer account and create a BLS slot, following the deployment's own
   guide. Keep the manifest and the slot outputs — you need the slot id, and the rule
   salt if you will provision a rule.
4. Verify the deployment before trusting anything on top of it: the CLI's cluster
   verification checks chain-derived keeper endpoints, the group key and the epoch
   agree with what the registry says.
5. Receive a credential from the deployed issuer, then do a live decryption —
   `examples/getting-started.ts`, shipped in the npm package, exercises threshold
   decryption using a provisioned non-exportable slot and your credential.
6. Revoke through the issuer, wait for the documented propagation/token-expiry
   window, and re-run the same threshold operation. **Record that refusal as a
   separate result**: a revocation nobody tested is not a revocation that works.

No command silently creates an alternative service or falls back to a local network.
Missing configuration is a prerequisite failure, and it says which prerequisite.

## What a green build does and does not prove

`npm run ci` proves the package is coherent: it compiles, the hermetic suites pass, the
package declarations and packed-package imports pass validation.
`npm run verify:consumers` separately installs the tarball and checks the runnable
offline README example, browser types, Vite, Webpack, Next.js, and browser crypto.

It proves **nothing about a network**. Real acceptance is steps 4–6 above, run against
actual credentials, with each outcome recorded separately. A green build or a plausible
UI is not acceptance of network behaviour.

## What you need from the deployment operator

The SDK and the CLI are self-service; three things are not, and they gate steps 3–6:

- **The deployment manifest** — contract addresses, RPC, verifier and verifier-agent
  endpoints, and the chain id, with the SHA-256 to pin it against. The SDK reads it
  through `parsePinnedNetworkManifest`.
- **The first credential.** Issuing one needs issuer access, so the operator either
  issues it to your holder DID or enrolls you as an issuer. Everything after that —
  presenting, renewing, revoking — is yours.
- **A slot's clear DCQL rule.** Creating a slot is permissionless, but provisioning its
  rule to the keepers is an operator action. Until it lands, operations on that slot are
  refused with "rule not provisioned", which reads like a broken keeper rather than
  incomplete setup.

One CLI gap worth knowing before you plan an evaluation: the released binary has
`slot protect`, `keys provision-rule`, `keys verify-cluster`, the `tasra` operations and
support diagnostics, but **no** `init`, `doctor`, `network use` or single end-to-end
slot-setup command.

## Where to go next

After the first proof: identity scopes and wildcards, sealed file storage, wallet
presentation from the Tasra extension or a mobile wallet, then a separate FROST
signing slot. Each recipe should carry an independently verified success, an expected
refusal, readable code, and a short redacted evidence report.

---

[← Back to the README](../README.md) · [Documentation index](README.md)

See [release acceptance](RELEASING.md#live-acceptance) for separate baseline and revocation reports.
