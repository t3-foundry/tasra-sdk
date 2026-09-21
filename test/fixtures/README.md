# Test fixtures

Static inputs for the service-identity and registered-service suites. Nothing here is
a real credential, and nothing here is used outside tests.

## `service-test-ca.pem`, `service-test-cert.pem`, `service-test-key.pem`

A throwaway self-signed TLS chain, generated once for this repository:

- **Subject** `CN=localhost`, **issuer** `CN=Tasra isolated service test CA`.
- Used to stand up in-process HTTPS servers so the service-identity and transport
  code can be exercised against real TLS rather than a mock.

**`service-test-key.pem` is a private key, and it is committed deliberately.** It
protects nothing: it is a localhost certificate for an isolated test server, it has
never been used by any deployment, and it grants no access to anything. It is in the
tree so the hermetic suite runs with no setup step and no certificate-generation
dependency — `node:crypto` cannot mint X.509 certificates, so generating this at test
time would mean adding a library for it.

Consumed by `test/specs/chain.service-transport.test.ts` — hermetic, and in CI. That
suite stands up real HTTPS servers to exercise the transport, TLS pinning and the
`isPublicServiceAddress` SSRF guard against an actual socket rather than a mock, which
is why a fixture and not a stub.

**These files do not ship.** `test/` is excluded from the published package, so the key
reaches nobody who installs `tasra-sdk` — it exists only in this repository.

If you need a fresh pair, regenerate both cert and key together and leave the CA
subject string unchanged — the suite asserts against it.

## `service-identity-v1.json`

A captured service-identity document in its v1 shape, used to test parsing and
validation without a running service. Consumed by
`test/specs/chain.service-identity.test.ts`.

## `broadcast/43112-run.json`, `broadcast/43113-run.json`

Two real Foundry `Deploy.s.sol` broadcast runs with different contract sets, driving
the address-book parser in `test/chain.deployments.ts`.

They are trimmed copies. Dropped: the top-level `receipts`, `libraries`, `pending` and
`returns`; per transaction `transaction`, `hash`, `isFixedGasLimit` and `function`; and
`initCode` on every created contract **except** `ERC1967Proxy`.

Everything retained is read by the parser, and three of those are easy to mistake for
noise:

- `additionalContracts[].transactionType` — the parser skips any entry that is not
  `CREATE`/`CREATE2`, so dropping it silently empties most of the book.
- `arguments` — how a directly-created proxy names its implementation.
- `initCode` on `ERC1967Proxy` — how a factory-created proxy names its implementation:
  the parser looks for the padded implementation address followed by the ABI offset
  word, so a truncated or synthesised value would not exercise that match.

To refresh, copy a run that resolves a full book and apply the same trim. A run from
later in a deployment's life may be an incremental deploy that resolves almost nothing.
