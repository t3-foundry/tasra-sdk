# Agent skills for tasra-sdk

Each folder is one [agent skill](https://agentskills.io): a `SKILL.md` that a coding
agent loads when the task matches its description. One format serves every agent; the
installers differ only in where they copy the folder.

## Install into your project

Installing the SDK does **not** install skills into your agent. The package includes
them under `node_modules/tasra-sdk/skills/`. Copy the whole skill folders — not just
the `SKILL.md` — into the directory your agent discovers:

```sh
mkdir -p .agents/skills
cp -R node_modules/tasra-sdk/skills/tasra-* .agents/skills/
```

The directory name varies by agent; check yours for where it looks for project
skills. Review existing folders before copying so you keep local customisations, and
start a new session if the installed skills do not appear. Ask the agent to use
`tasra-getting-started`, then the skill for your task.

**After each SDK upgrade, refresh the copied skills from that exact installed
package.** npm updates the package, not these copies. Keep local modifications in
separate skills, or review their diff before replacing one. Record
`node -p "require('tasra-sdk/package.json').version"` alongside the copied set.

Installing these instructions needs no private checkout, global installer or platform
credentials. Skills do not configure a network or grant access to anything.

## The set

| Skill | Use it when |
|---|---|
| `tasra-getting-started` | first install, choosing a client, first encrypt/decrypt/sign |
| `tasra-create-slot` | creating a key slot on-chain and getting it ready to use |
| `tasra-credentials-and-sessions` | the four auth modes, renewals, holder proofs, JWT expiry |
| `tasra-dcql-rules` | writing, validating and evaluating a slot's access rule |
| `tasra-handle-errors` | catching, classifying and retrying SDK errors |
| `tasra-sign-and-decrypt` | FROST / threshold-ECDSA signing, ethers and viem adapters, threshold decryption |
| `tasra-ibe-identity-scoped` | encrypting to an identity, extraction, large sealed objects |
| `tasra-chain` | address books, the read client, on-chain discovery, events |
| `tasra-committee-path` | the never-reconstruct-the-key path from a bare slot id |
| `tasra-oid4vp-wallet-and-verifier-agent` | OpenID4VP wallets, the Verifier Agent, credential issuance |
| `tasra-hovi-issuer` | getting real credentials: the Hovi Studio trial, organizations, templates and issuance through Hovi's API, receiving with the SDK |

Skills cite documentation included in the package, so an agent can read the full
text under `node_modules/tasra-sdk/` and the exact types
from `node_modules/tasra-sdk/dist/**/*.d.ts`.

## First verified application

`tasra-getting-started` is the entry point, and
[developer handoff](../docs/DEVELOPER-EXPERIENCE.md) is the whole journey against
deployed services. Report diagnostics, live decryption and issuer revocation
separately; never count a missing prerequisite as success.

Deployment records live in [tasra-releases](https://github.com/t3-foundry/tasra-releases),
not the npm package. Fuji's `networks/testnet/current.json` points to
`deployments/tasra-fuji-v1.json` and supplies its checksum. Use `tasra-chain` to
bootstrap from one reviewed repository revision, then discover the slot's keepers.
