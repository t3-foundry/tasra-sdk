# Security policy

`tasra-sdk` is the client half of a threshold key-management protocol. It handles
private key material, assembles master secret keys in process memory, and decides
whether a credential satisfies an access rule. Bugs here can expose keys or grant
access that policy should have refused. We take reports seriously and we will not
argue about severity before fixing something real.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately through
[GitHub Security Advisories](https://github.com/t3-foundry/tasra-sdk/security/advisories/new),
which lets us collaborate on a fix in a private fork before anything is disclosed.
This requires no special access — any GitHub user can file one, and only the
maintainers can read it.

Private disclosure is also enabled on the repository, so the **Report a
vulnerability** button on the Security tab reaches the same place.

If you cannot or would rather not use GitHub, email **waldemar@managination.com**
with `tasra-sdk` in the subject. Encrypted mail is welcome; say so in the
first message and we will arrange keys.

Please include, as far as you have it:

- the version (`npm ls tasra-sdk`) and Node or browser runtime;
- what an attacker gains — key material, unauthorized decryption, policy bypass,
  signature forgery, denial of service;
- the smallest reproduction you can manage, ideally a failing script against a
  local fleet;
- whether you have told anyone else.

### What to expect

| | |
|---|---|
| First response | within 3 business days |
| Triage and initial assessment | within 10 business days |
| Fix or mitigation plan communicated | within 30 days of triage |
| Coordinated disclosure | by agreement, default 90 days from report |

We will credit you in the advisory and the changelog unless you ask us not to.
We do not currently run a paid bounty.

## Scope

**In scope** — anything shipped from this repository:

- the envelope format and its crypto (`encryptEnvelope`, `decryptWithMasterKey`);
- shard fetch and master-key assembly, including zeroization on `close`;
- DCQL validation and evaluation — in particular a subject being granted access it
  should not have, or a rule that validates here but is refused by the network's own
  evaluator (a conformance divergence is a security bug, not a nit);
- credential, JWT and holder-proof handling, including replay and binding;
- committee token assembly and verification, and verifier-set inclusion proofs;
- threshold signing and decryption paths;
- the chain write client — anything that could sign a transaction for the wrong
  chain, the wrong contract, or with the wrong arguments;
- dependency vulnerabilities that are actually reachable from this package's code.

**Out of scope here** — report these to the network, not the SDK:

- keeper node, verifier, verifier-agent or issuer implementations;
- contract vulnerabilities;
- the operational security of any particular deployment.

If you are not sure which side a bug is on, report it here and we will route it.

## Known non-issues

Things that look alarming, are already known, and do not need reporting:

- **`test/fixtures/service-test-key.pem` is a committed private key.** It is a
  self-signed `CN=localhost` key, generated once for this repository, never used by any
  deployment, and it grants access to nothing. It exists so the hermetic suite can
  stand up real HTTPS servers — `test/specs/chain.service-transport.test.ts` exercises
  TLS pinning and the `isPublicServiceAddress` SSRF guard against an actual socket,
  which a mock cannot do honestly. `test/` is excluded from the published package, so it
  reaches nobody who installs `tasra-sdk`. Secret scanners flag it; that is expected.

## Supported versions

Pre-1.0, only the latest published minor receives security fixes. After 1.0 this
table will state a support window per major.

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Cryptographic posture

Worth knowing before you file:

- Primitives come from [`@noble`](https://github.com/paulmillr/noble-curves)
  (`curves`, `ciphers`, `hashes`). We do not implement primitives ourselves; we
  implement protocol on top of them. A flaw in a primitive belongs upstream, though
  we still want to hear about it.
- The SDK persists nothing — no localStorage, no key files. Key material lives in
  process memory and is zeroized on `Session.close()`. **If your application writes
  an assembled key to disk, that is your boundary, not ours.**
- `decryptWithMasterKey` requires an assembled master key, which means the local
  decrypt model: `k`-of-`n` nodes revealed their shards to you. If your threat model
  cannot tolerate reconstruction, use the threshold path — `decryptCustody`,
  `decryptWithShardDelivery`, `combineDecryptShares` — which never assembles it.
- Conformance with the network's own implementation is checked against **vendored**
  known-answer vectors, computed by that implementation. Nothing here detects a change
  made on its side, so a divergence can exist without a test going red until the
  vectors are refreshed. A divergence in DCQL evaluation, IBE, or committee-token
  hashing is a protocol disagreement and we treat it as a security issue — report one
  even if the suites are green.

This package has **not** had an independent third-party cryptographic audit. Weigh
that before putting it in front of real user secrets.
