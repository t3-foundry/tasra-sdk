# Contributing to tasra-sdk

Thanks for taking the time. This document is about working *on* the SDK. If you are
trying to build something *with* it, start at the [README](README.md) and
[docs/](docs/).

## Ground rules

- **Security bugs do not go in issues.** See [SECURITY.md](SECURITY.md).
- `develop` is the trunk and the default branch. Branch from it, PR back into it.
- Conventional-ish commit subjects, lowercase, imperative, scoped by area:
  `chain: reject a write whose chainId disagrees with the wallet`.
- Every change that alters behaviour gets a line in `CHANGELOG.md` under
  `## [Unreleased]`, grouped by Keep a Changelog type.

## Getting set up

```sh
git clone https://github.com/t3-foundry/tasra-sdk.git
cd tasra-sdk
npm install          # `prepare` builds dist/ as part of this
npm run ci           # the full gate — see below
```

Node **≥22.12** (the `engines` floor, and the first release that can `require()` an
ES module). No other system dependency for the hermetic suites.

## The gate

`npm run ci` is what `prepublishOnly` runs, and CI runs the same steps plus
`npm audit signatures` and a coverage-report upload. If it is green locally it should be
green on the runner:

| Step | What it proves |
|---|---|
| `npm run lint` | **type-aware** eslint (`recommendedTypeChecked`) over `src/`, `test/` and `examples/` |
| `npm run typecheck` | `tsc --noEmit` over the library **and** the harness tree |
| `npm run build` | `dist/` compiles from a clean slate |
| `npm run test:coverage` | the hermetic vitest suites, no network, no deployment — **and the coverage floor** |
| `npm run verify:pkg` | publint + attw + a pack smoke test that extracts the real tarball and resolves every subpath |

`verify:pkg` exercises the **published** artifact rather than
`src/`: it packs the tarball, lays it out as a consumer's `node_modules` would see it,
and resolves every subpath through the `exports` map — ESM, `require()`,
`tasra-sdk/package.json`, and the optional-peer boundary.

The separate hosted consumer job installs the tarball in a fresh npm project and runs
its offline example, browser typechecking, Vite/Webpack builds, Next.js server/client
imports, and crypto in Chromium, Firefox, and WebKit. Run it on Node 24:

```sh
npx playwright install chromium firefox webkit
npm run verify:consumers
```

This check requires registry access and local browser processes. It does not contact a
Tasra deployment. Live acceptance is separate; see [RELEASING](docs/RELEASING.md#live-acceptance).

**Lint is type-aware**, which is what buys `no-floating-promises`,
`no-misused-promises` and `await-thenable` — an unawaited promise in a session or crypto
path is a real bug class here. It needs a project for every linted file, so
`eslint.config.js` lists both tsconfigs; a file in neither is a parse error rather than a
silent skip. Findings that are not defects in this codebase are downgraded to warnings
with the reason inline, so **errors stay at zero** and a new error means something real.

⚠ **Do not run `eslint --fix` blind.** `no-unnecessary-type-assertion` has an unsound
autofix against viem's generic ABI types: a fix pass produced code eslint called clean
and `tsc` rejected. It is a warning for that reason. Fix by hand, then `npm run typecheck`.

**The coverage floor** lives in `vitest.config.ts` and is a floor, not a target: set just
under the current numbers so churn passes and a regression fails. `vitest.config.ts` also
records which directories are low for a structural reason (HTTP orchestration that needs a
live deployment) versus a real gap reachable with a stubbed `fetch` — **that second list is now
empty**, so a new entry on it means code landed without a test. It also lists the branches that
are genuinely UNREACHABLE
(rejection sampling, zero-scalar arms, `??` fallbacks over a table built from the array being
indexed) and which stay uncovered rather than being deleted to move a number. Read it before
you conclude the headline number means what it looks like.

An unreachable branch is worth a second look before it goes on that list: one of them turned
out to be a duplicated policy — the same JWT-renewal condition written in two places, only one
of them reachable — and deduplicating it was the fix, not an exemption.

CI runs this gate on Node 22.12, 24 and 26. Locally it only ever proves the one Node
version you ran it on, which matters because `require(esm)` behaves differently below
the 22.12 floor. To run it automatically before every push:

```sh
printf '#!/bin/sh\nnpm run ci\n' > .git/hooks/pre-push && chmod +x .git/hooks/pre-push
```

Run a single suite while iterating:

```sh
npx vitest run test/specs/crypto.roundtrip.test.ts
npm run test:watch
```

## Tests

**Hermetic suites** (`test/specs/*.test.ts`) run in CI. They mock the deployment. Anything
you can test this way, test this way.

The suites themselves live in `test/*.ts` as self-contained scripts, each with its own
check tally, so you can run one directly while debugging (`npx tsx test/errors.ts`).
`test/specs/*.test.ts` are thin Vitest wrappers around them — see `test/_runSuite.ts`
for why — which is what buys parallelism, coverage, and a failing suite no longer
hiding the ones after it.

**Live harnesses** need infrastructure and stay out of CI. They are real engineering
tools, not leftovers:

| Path | Needs | Run with |
|---|---|---|
| `test/e2e/` | a reachable deployment | `npm run test:e2e` |
| `test/reconcile/` | a deployment + its explorer | `npm run test:reconcile` |
| `test/economics/` | a deployment | `npm run test:e2e` (included) |
| `test/stress/` | a deployment (except `stress:crypto`, which needs nothing) | `npm run stress` |
| `test/slashing/` | a **disposable** deployment — mutates and slashes real operators | `npm run test:destructive` |
| `test/live/` | a deployment + a wallet | `npx tsx <file>` |

Every one of these is configured purely from the environment — see
[`test/fleet/README.md`](test/fleet/README.md) for the full contract. They skip when the
deployment is unreachable, and fail (naming the variable) when configuration is missing.

The destructive ones are separately env-gated and self-skip unless you opt in. Read the
header comment before you run one; several are irreversible against the target.

### Conformance vectors

`test/oid4vp-vectors.json`, `test/ibe-vectors.json` and
`test/committee-token-vectors.json` are **vendored copies** of vectors computed by the
reference implementation. They are the reference the conformance suites run against.

Nothing in this repository detects a change made on the producing side, so refreshing
them is a deliberate manual step: copy the new file in, re-apply the editorial changes
(the `_comment` blocks here carry no internal references), and read the diff. A change
in the vector **values** is a protocol change, not a stale fixture — do not regenerate
vectors to make a test pass, work out which side is wrong first.

`test/fixtures/broadcast/*.json` are trimmed copies of real deploy runs; `test/fixtures/README.md`
records exactly what was trimmed and which fields the parser needs.

### Vendored ABIs

`src/chain/abis/*.ts` are vendored `as const` ABI modules, one per contract, so the
published SDK has no build-time dependency on the contracts. Each file names the
artifact it came from in its header.

Refreshing one is manual: take the `abi` field from that contract's build artifact and
replace the whole array. Nothing detects drift, so an ABI that has moved on stays wrong
until someone notices a decode failing — if you change a contract interface, refresh the
ABI in the same change.

## Public API changes

The API is the product. Before changing an export:

1. Add it to `CHANGELOG.md` under the right heading.
2. Update any skill in `skills/` that names it. **Nothing checks this** — there is no
   automated guard against a skill naming a symbol that no longer exists, so grep
   `skills/` for the old name and fix every hit in the same change.
3. Update `docs/` and the README quickstarts if they demonstrate it.
4. Pre-1.0, a **minor** may change or remove API; a **patch** never does. Announce a
   removal under `### Deprecated` at least one minor earlier when practical.

`engines.node` and the ESM-only decision are part of the API surface too.

## Agent skills

`skills/` ships inside the tarball so that an agent gets task-oriented guidance instead
of guessing. If you add a capability an agent would plausibly be asked to use, add or
extend a skill. Keep them short, runnable, and honest about what needs infrastructure.

## Pull requests

- Keep them focused; a refactor and a behaviour change in one PR is two reviews
  wearing a trenchcoat.
- `npm run ci` green before you ask for review.
- Explain the *why* in the description. The diff already shows the what.
- New public API needs docs and a changelog line in the same PR.

## Licence

By contributing you agree your contributions are licensed under the
[Apache License 2.0](LICENSE), matching the project.
