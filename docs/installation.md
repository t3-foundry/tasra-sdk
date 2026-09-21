# Install

> Installing, the optional viem peer, module format, and runtime support.

```sh
npm install tasra-sdk
```

The package ships JavaScript, type declarations, runnable examples and all eleven agent
skills; library implementation TypeScript and source maps are excluded (example TypeScript is included), so the shipped
JavaScript stays inspectable.

Releases published by the GitHub workflow carry [npm provenance](https://docs.npmjs.com/generating-provenance-statements)
— a signed attestation linking the tarball to the commit and workflow run that built
it, which npm shows on the package page. Manual bootstrap releases can omit provenance;
check the release notes and package page. Verify registry signatures and available
attestations with:

```sh
npm audit signatures
```

Crypto deps are just `@noble/{curves,ciphers,hashes}`. **`viem` is an optional peer
dependency** — needed only for the `tasra-sdk/chain` subpath, so a core-only consumer
neither installs nor bundles it:

```sh
npm install tasra-sdk viem   # only if you import tasra-sdk/chain
```

(`npm run verify:pkg` asserts this both ways: the main entry loads with viem absent
from the tree, and `/chain` fails without it.)

For network configuration use `parsePinnedNetworkManifest`, `addressBookFromManifest`
and `observeNetworkManifest` from `tasra-sdk/chain`, and pin the manifest SHA-256 from
the deployment's published checksum. Planned or retired deployments cannot configure a
live client. Matching the code is not the same as an audit or a verified round trip.

**Using a coding agent?** The package ships [agent skills](../skills/README.md) — one
folder per task (getting started, creating a slot, credentials, DCQL rules, errors,
signing, IBE, chain reads, the committee path, OID4VP, and getting real credentials
from a Hovi issuer). Installing the package does not register them; see the
[installation instructions](../skills/README.md) and refresh copied skills after every
SDK upgrade.

Runs in the browser (Vite, Webpack, Next.js) and Node **≥22.12**. The SDK
persists nothing — no localStorage, no sessionStorage, no directory of slots —
so your product holds slot ids and credentials wherever it holds its own state.

## Module format

**This package is ESM-only** (`"type": "module"`, built with `tsc` under
`NodeNext`). There is no CommonJS build, and there deliberately won't be: the SDK
holds key material and session caches, and a dual ESM+CJS build would let two
copies of that state exist in one process.

You do not need a bundler or a transpile step. Modern Node and every current
bundler consume it directly:

```ts
import {createTasraClient} from 'tasra-sdk'   // ESM — the normal path
```

From CommonJS, both of these work on Node ≥22.12:

```js
const sdk = require('tasra-sdk')        // Node ≥22.12 can require() an ES module
const sdk = await import('tasra-sdk')   // works on any Node that supports ESM
```

`npm run verify:pkg` checks all of the above against the real packed tarball
(`publint` + `attw` + a resolution smoke test).

## Compatibility

- **Node ≥ 22.12**, or any evergreen browser. WebCrypto (`crypto.subtle`,
  `getRandomValues`) must be present — it is everywhere the above holds, but not
  on an insecure-context browser page (`http://` off loopback).
- **ESM only** (above). `require()` works on Node ≥ 22.12 and nowhere older.
- **Wire compatibility with the network is fixed per SDK version, not negotiated at runtime.**
  Every node, verifier and verifier-agent endpoint the SDK calls is under `/v1/`. The SDK
  does not check a node's version or feature set; a mismatch surfaces as an
  HTTP 404/403 at call time (`TasraHttpError`). Some routes are
  per-deployment feature gates — threshold ECDSA (`/v1/sign/eoa-digest`) and
  the admin scope among them — and `nodeApi.info()` in `tasra-sdk/chain`
  reports which are on.
- **Pre-1.0 versioning**: a minor bump may change the API, a patch never does.

---

[← Back to the README](../README.md) · [Documentation index](README.md)
