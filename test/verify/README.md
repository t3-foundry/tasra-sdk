# `verify` — one-command, no-mocks, production-mode verification

Proves the **whole** Keykeeper stack works — correctness **and** performance —
against a **real** production-mode deployment. No mocks, no shortcuts: a brand-new
account is created, funded by a faucet, buys TSRA on the bonding curve, funds a
slot, runs a DKG, and operates it with a signed credential — then every component
(nodes, accountants, verifiers, SDK, explorer) is swept for correctness,
performance, and real on-chain slashing.

## TL;DR

```bash
cd tasra-sdk
npm run verify:all
```

That single command:

1. **Brings up** the real stack — `KK_THRESHOLD_SET=1 make fleet-up` in
   keykeeper-network (Besu/Prague + 5 nodes + 3 prod-profile verifiers + 3
   **threshold** accountants) + the **explorer** attached to the fleet network.
2. **Real economic onboarding** — fresh account → faucet (gas) → **buy TSRA on
   the bonding curve** → **commit-reveal create a TSRA-funded slot** → committee
   DKG → provision rule → prepay on Settlement → **operate** via a signed JWT-VC
   (encrypt → k-of-n shard fetch → decrypt).
3. **Correctness** — Rust protocol tests (DKG-over-libp2p, rotation, k-of-n
   threshold capstone, operator CLI) + the SDK live-fleet suites
   (`test`/`test:prod` (the **signed** JWT-VC path) /`test:reconcile` (= explorer
   vs chain vs nodes) /`test:slashing`), run with `KK_FLEET_REQUIRED=1` so a down
   service fails red. The dev-only `test:e2e` (unsigned `/v1/verify`) is **not**
   run against the prod-profile fleet — that endpoint is disabled there by design
   (it 404s). Set `KK_VERIFY_DEV_E2E=1` to include it against a dev fleet.
4. **Performance** — crypto `perf_smoke` ceilings + SDK stress (slot-creation,
   sign/decrypt throughput, crypto ops/s).
5. **Destructive** — real node slashing, nuke-and-recover, verifier mis-issuance,
   accountant false-slash and wrong-bundle.
6. **One report** → `test/verify/out/verify-report.md` (+ `.json`). Exits non-zero
   if any required step fails.

> Full run is ~30–40 min. For a fast signal use `verify:correctness` (below).

## Granular commands

| command | what it does |
| --- | --- |
| `npm run verify:up` | bring up fleet + explorer only |
| `npm run verify:bootstrap` | the real account→faucet→TSRA→slot→operate path (needs the fleet up) |
| `npm run verify:correctness` | correctness only, against an already-running fleet |
| `npm run verify:perf` | performance only |
| `npm run verify:destructive` | destructive only (slashing / nuke-recover) |
| `npm run verify:down` | tear the explorer + fleet down |

## Knobs (env)

All default ON for `verify:all`:

- `KK_VERIFY_BRINGUP=0` — reuse an already-running fleet (skip `make fleet-up`)
- `KK_VERIFY_BOOTSTRAP=0` / `KK_VERIFY_CORRECTNESS=0` / `KK_VERIFY_PERF=0` /
  `KK_VERIFY_DESTRUCTIVE=0` — skip a phase
- `KK_VERIFY_BENCH=1` — also run criterion crypto micro-benchmarks (slow)
- `KK_VERIFY_RUST=0` — skip the (slow) in-process Rust anvil protocol tests
- `KK_VERIFY_DEV_E2E=1` — also run the dev `test:e2e` (unsigned-verify path)
- `KK_VERIFY_DEMO_FAULTS=1` — run the demo-faults artifacts that need the
  byzantine fleet (the accountant false-slash / wrong-bundle + verifier
  mis-issuance via the unsigned `/v1/verify`, which the prod profile disables):
  the `verifier-misissue-slash` suite and scenarios `12`/`13`/`14`/`15`.
  When `KK_VERIFY_BRINGUP` is on, this **also brings the fleet up with
  `KK_DEMO_FAULTS=1`** so those byzantine behaviours are actually active (the fleet
  is honest by default). Otherwise these artifacts are **skipped** (not failed)
  with a note — the mis-issuance *mechanism* is still covered by the Rust
  `anvil_threshold_capstone` (V1).
- `KK_KEEP=1` — leave the stack up at the end (no teardown)

Targeting a **remote** deployment instead of the local fleet? Set the standard
fleet overrides — `KK_NODE_URLS`, `KK_VERIFIER_URLS`, `KK_RPC_URL`,
`KK_EXPLORER_API`, `KK_CHAIN_ENV` (see `test/fleet/_fleet.ts`) — and run with
`KK_VERIFY_BRINGUP=0`.

## Prerequisites

`docker`, `make`, `node`/`npm`, and (for the Rust protocol tests + perf ceilings)
`cargo` + `forge`. Missing optional toolchains (`forge`, `cargo`) are
**skipped with a loud warning** in the report — never silently dropped.

## Why this is "real"

- The chain is Besu on **Prague** (`pragueTime: 0`) so the **threshold accountant
  set** (k-of-n beacon + `settleBls` + slashing, all EIP-2537) runs for real — no
  single-signer shortcut.
- The verifier runs its **prod profile** (signed-VC only; unsigned `/v1/verify`
  off), so the credential path under test is the production one.
- TSRA is **bought on the bonding curve**, not handed out by the deployer.
- Slashing tests actually **slash and recover** real nodes/verifiers/accountants.
