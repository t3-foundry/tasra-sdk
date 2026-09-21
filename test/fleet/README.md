# Live suites

These suites exercise the SDK against a **running deployment** — real keepers, real
verifiers, real shards, real chain. They are not part of `npm test`, which is hermetic.

They are deliberately **deployment-agnostic**: every endpoint, address and key comes from
the environment, and nothing here reads a file from, or runs a binary out of, another
repository. Point them at whatever deployment you have.

```sh
TASRA_NODE_URLS=http://localhost:8091,http://localhost:8092,http://localhost:8093 \
TASRA_VERIFIER_URLS=http://localhost:8181,http://localhost:8182,http://localhost:8183 \
TASRA_RPC_URL=http://localhost:8545 TASRA_CHAIN_ID=1337 \
TASRA_SLOT_ID=0x… TASRA_RULE_SALT=0x… \
KEY_REGISTRY=0x… NODE_REGISTRY=0x… SETTLEMENT=0x… \
  npm run test:e2e
```

When the deployment is unreachable a suite **skips** and exits 0. Set
`TASRA_FLEET_REQUIRED=1` to make that a failure instead, which is what you want in CI.
Missing *configuration*, as opposed to an unreachable endpoint, always fails and names
the variable.

## The layers

| Directory | What it answers |
|---|---|
| `test/e2e/` | Does the full platform capability work on real shards — encrypt/decrypt round trips, signing, credentials, renewals, metering, slot lifecycle |
| `test/reconcile/` | Does the explorer reflect on-chain reality — node sets, slots, beacon epochs, token supply |
| `test/slashing/` | Do the slashing paths work end to end. **Mutating and irreversible**; each is separately env-gated |
| `test/economics/` | Bonding-curve funding against a live deployment |
| `test/live/` | Wallet and Verifier Agent compatibility. Run by hand with `npx tsx`; no npm script |
| `test/stress/` | Throughput — client-side crypto, and signing/decryption against live committees |

`_fleet.ts` holds the configuration loader and the reachability gate, `_assert.ts` the
suite/report helpers, `_crypto.ts` and `_wallet.ts` the shared credential machinery.

## Configuration

Endpoints default to a loopback deployment. **Anything identifying a specific deployment
has no default**, because a wrong default surfaces later as an unrelated-looking
authorization failure.

| Var | Default | Meaning |
|---|---|---|
| `TASRA_NODE_URLS` | `:8091…8100` | Comma-separated keeper base URLs. Probed and trimmed to the live ones unless set explicitly |
| `TASRA_VERIFIER_URLS` | `:8181…8183` | Comma-separated verifier base URLs |
| `TASRA_EXPLORER_API` | `http://localhost:8090/api` | Explorer API base, for `test/reconcile/` |
| `TASRA_RPC_URL` | `http://localhost:8545` | JSON-RPC endpoint |
| `TASRA_CHAIN_ID` | `1337` | Chain id — must match the deployment, or writes are rejected |
| `TASRA_SLOT_ID` | — | The slot under test |
| `TASRA_RULE_SALT` | — | Its rule salt. Required to provision a rule: the chain holds only the salted commitment |
| `TASRA_GOVERNANCE_SLOT_ID`, `TASRA_GOVERNANCE_RULE`, `TASRA_GOVERNANCE_RULE_SALT` | — | The governance slot, for the governance suites |
| `TASRA_DEPLOY_PK`, `TASRA_DEPLOY_ADDR` | — | A funded key with the rights the suite needs |
| `TASRA_ISSUER_KEY`, `TASRA_ISSUER_DID` | — | The credential issuer. Must be one the target verifier's anchor trusts |
| `TASRA_JWT_SIGNING_KEY`, `TASRA_JWT_ISS`, `TASRA_JWT_AUD` | — | The deployment's Ed25519 JWT issuer seed and its `iss`/`aud` |
| `TASRA_ADMIN_SECRET` | — | Verifier admin secret, where a suite needs an admin route |
| `TASRA_FAUCET` | `http://localhost:8552` | Faucet base URL |
| `TASRA_FLEET_REQUIRED` | _(unset)_ | `1` ⇒ fail rather than skip when unreachable |
| `TASRA_CHECKS_REQUIRED` | _(unset)_ | `1` ⇒ a skipped check is a failure |
| `TASRA_ACCOUNTANT_EVIDENCE_URLS` | — | Accountant fault-evidence base URLs, for the mis-issuance slashing suite |
| `TASRA_STATS_FILTER` | _(unset)_ | Container-name substring to sample resource usage from, in the stress suites |
| `KK_SLASH_TEST`, `KK_DESTRUCTIVE` | _(unset)_ | `1` ⇒ run a mutating, irreversible suite |

Contract addresses are read from the environment by `addressBookFromEnv`, so
`KEY_REGISTRY`, `NODE_REGISTRY`, `SETTLEMENT`, `VERIFIER_SET_REGISTRY` and the rest work
as plain variables, in either their raw or aliased form.

## Stress

| Harness | What it stresses | Run |
|---|---|---|
| `crypto-throughput.ts` | Client-side encrypt / decrypt / shard-assemble. Needs no deployment | `npm run stress:crypto` |
| `keyops.ts` | FROST signing + BLS threshold decrypt against a provisioned slot | `npm run stress:keyops` |
| `keyops-committees.ts` | The same, swept across committee sizes | `npm run stress:keyops:committees` |

Tunables: `KK_STRESS_DURATION`, `KK_STRESS_CONC`, `KK_STRESS_SLOTS`, `KK_STRESS_MODE`,
`KK_K`, `KK_N`, `KK_CRYPTO_ITERS`, `KK_STRESS_SPREAD`.

HTTP hot-path load testing (stateless routes, spike and soak profiles) is not in this
package — it belongs with whatever operates the deployment.
