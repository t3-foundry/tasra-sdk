# Releasing `tasra-sdk`

How a version gets from `develop` to npm. Short, because the package scripts do most
of it.

## What must be true before any release

- You are on a clean checkout of `develop` (the trunk and default branch).
- `npm run ci` is green **on this machine**: lint, both typechecks, build, the hermetic
1  vitest suites, `verify:pkg` (publint, attw, and the pack smoke test that extracts the
  real tarball and resolves every subpath).
- The conformance suites pass against the vendored vectors. They do not detect a change
  made on the producing side, so if the protocol moved, refresh the vectors first — see
  [CONTRIBUTING.md](../CONTRIBUTING.md#conformance-vectors).
- `npm run verify:consumers` passes after `npx playwright install chromium firefox webkit`.
- A live acceptance report for this SDK revision and deployment is recorded (below).
  Fuji records are in [tasra-releases](https://github.com/t3-foundry/tasra-releases);
  their publication does not substitute for this SDK revision's live report.
- `skills/*/SKILL.md` still match the API. This is a MANUAL check — nothing enforces
  it — so grep the skills for anything you renamed or removed this cycle.
- `CHANGELOG.md` has everything for this version under `## [Unreleased]`, grouped by
  Keep a Changelog type, one short line per change.

## Cutting a release

1. Set the release version and move the changelog entry. For the first publication,
   keep the prepared `0.1.0`; for subsequent releases, bump it:

   ```sh
   npm version <patch|minor|major> --no-git-tag-version
   # edit CHANGELOG.md:
   #   - rename "## [Unreleased]" to "## [X.Y.Z] — YYYY-MM-DD"
   #   - add a fresh empty "## [Unreleased]" above it
   ```

2. Pre-flight the tarball. This is the last look before it is public and immutable:

   ```sh
   npm run ci
   npm pack --dry-run      # dist/, skills/, docs/ and the root docs
   ```

3. Commit and tag. The tag is what triggers publishing:

   ```sh
   git commit -am "release: vX.Y.Z"
   git tag vX.Y.Z
   git push origin develop --tags
   ```

4. `.github/workflows/release.yml` re-runs the full gate and publishes with
   **provenance** — a signed attestation tying the tarball to this commit and workflow
   run. It refuses to run if the tag does not match `package.json`.

Provenance needs the repository to be public (npm cannot attest from a private one) and
a **trusted publisher** binding on npmjs.com: package `tasra-sdk` → repository
`t3-foundry/tasra-sdk` → workflow `release.yml`. That binding supplies the credential
via OIDC, so no `NPM_TOKEN` is stored anywhere. Until it exists, publish by hand.

## Manual publish (fallback)

```sh
npm whoami || npm login          # an account with publish rights on tasra-sdk
npm run ci
npm publish --provenance=false   # local publishing cannot generate CI provenance
```

A manual publish carries **no provenance** — that is the only difference on the npm
page, and it is a reason to prefer the workflow. Explicitly record this exception in release notes.

## Versioning

The SDK version tracks the platform version: `tasra-sdk` X.Y.Z is the client for
platform X.Y.Z. Pre-1.0, a **minor** bump may change or remove API (announced under
`### Deprecated` at least one minor earlier when practical); a **patch** never does.
`engines.node` and the ESM-only decision are part of the API.

## After publishing

- Check the package page: README renders, the version is right, the file list matches
  `npm pack --dry-run`, and the provenance badge is present.
- Confirm a fresh install from the registry, not a `file:` link:

  ```sh
  cd "$(mktemp -d)" && npm init -y >/dev/null && npm i tasra-sdk
  npm audit signatures
  node -e "import('tasra-sdk').then(m => console.log(typeof m.createTasraClient))"
  ```

A published version is immutable and unpublishing is heavily restricted. A bad release
is fixed by publishing the next patch, not by removing it.


## Live acceptance

**Require evidence for public testnet:** obtain the pinned Fuji deployment record
from [tasra-releases](https://github.com/t3-foundry/tasra-releases).
Do not mark a release live-verified until real reports exist. Local unit tests,
conformance vectors, and browser checks are not substitutes.

Run from a clean, committed checkout against dedicated, provisioned non-exportable
BLS and FROST test slots. Use application configuration from [prerequisites](prerequisites.md).
Also supply `KK_DENIED_HOLDER_KEY_FILE` and `KK_DENIED_CREDENTIALS_FILE` for a valid
holder whose credentials do not satisfy the slot policy. Keep reports outside the repo
(or under ignored `.tasra/`). Operations consume deployment metering funds.

```sh
KK_ACCEPTANCE_REPORT=/path/to/new-baseline.json npm run test:acceptance -- baseline
```

This records successful decryption, a verified FROST signature, and explicit HTTP
authorization denial. Transport failures and mixed/error responses cannot count as denial.

Revoke the allowed holder's credential through the deployment's documented issuer flow.
Retain the same credential file and holder key. Record the actual revocation time in
`KK_REVOKED_AT` (ISO-8601), and the deployment's propagation/token-expiry window in
`KK_REVOCATION_WAIT_SECONDS`. After that window, run:

```sh
KK_BASELINE_REPORT=/path/to/new-baseline.json KK_ACCEPTANCE_REPORT=/path/to/new-revoked.json npm run test:acceptance -- revoked
```

The second phase requires the same SDK revision, deployment manifest, slots, holder,
and credential set; credentials must still be unexpired. It requests fresh authorization
and records refusal for decrypt and sign separately. Correlate the refusals with issuer
revocation evidence; an HTTP refusal alone does not identify its cause. Revocation does
not erase plaintext already received or keys previously exported from other slots.

Reports omit credentials, private keys, tokens, endpoint URLs, and upstream response
bodies. They include public deployment/slot identifiers and credential commitments;
review before sharing. Archive both reports with the release evidence. Any failure or
missing report leaves live acceptance incomplete.
