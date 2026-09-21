# Documentation

Start with the [README](../README.md) — install, the quick starts, and which client
to reach for. These pages are the depth behind it.

## Building on the SDK

| Page | What's in it |
|---|---|
| [What you can do](capabilities.md) | The capability catalogue — every major thing the SDK does, and the call that does it |
| [Prerequisites](prerequisites.md) | What has to be running before a session can open — and the parts that need nothing at all |
| [Installation](installation.md) | The optional `viem` peer, module format, browser and Node support |
| [API surface](api.md) | Every export grouped by purpose: envelopes, assembly, credentials, IBE, OpenID4VP, the committee path |
| [Chain](chain.md) | `tasra-sdk/chain` — reads, writes, slot creation, on-chain discovery |
| [Signing](signing.md) | Threshold ECDSA for EVM accounts, wired into ethers, viem and Hardhat |
| [Errors](errors.md) | The error taxonomy, what retries, how to tell a denial from an outage |
| [Architecture](architecture.md) | What the managed session does underneath, and where this package sits |
| [Glossary](glossary.md) | Slot, k-of-n, MSK, epoch, DKG, DCQL, holder proof, committee |

## Running against a real deployment

| Page | What's in it |
|---|---|
| [Developer experience](DEVELOPER-EXPERIENCE.md) | Live deployment handoff, pending public testnet publication, and each component’s responsibilities |

## Working on the SDK

| Page | What's in it |
|---|---|
| [Contributing](../CONTRIBUTING.md) | Setup, the gate, tests, conformance vectors, PR expectations |
| [Security policy](../SECURITY.md) | How to report a vulnerability, scope, cryptographic posture |
| [Releasing](RELEASING.md) | Cutting a version and publishing |
| [Changelog](../CHANGELOG.md) | What changed, by version |

## For coding agents

The package ships [agent skills](../skills/README.md) — task-oriented guides, one
folder per job. They are hand-maintained prose with no automated check against the
built declarations, so a skill describes the version it shipped with; `dist/**/*.d.ts`
is the authority on what actually exists.
