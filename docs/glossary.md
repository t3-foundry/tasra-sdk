# Glossary

> Slot, k-of-n, MSK, epoch, DKG, DCQL, holder proof, committee — defined.

Every domain term this README uses, defined once.

- **Slot** — the unit of key management: one threshold keypair plus the policy
  governing access to it. Created on-chain, identified by a 32-byte `slotId`.
  Everything in this SDK is scoped to a slot.
- **k-of-n** — the threshold. A slot's key is split into `n` shards across `n`
  nodes; any `k` of them can cooperate to decrypt or sign. Fewer than `k` can do
  nothing, and no single node ever holds the whole key.
- **Shard** — one node's share of a slot's secret key.
- **MSK / master secret key** — the whole secret, reconstructed *in your process*
  by Lagrange-interpolating `k` shards. Only the local-decrypt path does this;
  threshold sign/decrypt never reconstructs it. `Session.close()` zeroizes it.
- **MPK / group public key** — the slot's public key. Public and served by any
  node, so encryption needs no credentials.
- **Epoch** — the slot's key generation. Rotation (e.g. after revoking a holder)
  bumps it; envelopes carry the epoch they were encrypted under so a rotated slot
  can still read old ciphertext.
- **DKG** — distributed key generation. The committee generating a slot's key
  among themselves after creation, with no dealer. Takes a moment after
  `createSlot`, which is why `getting-started.ts` polls for a non-empty group key.
- **DCQL** — the query language a slot's access **rule** is written in, evaluated
  against a holder's verifiable credentials. The chain stores only a salted hash
  of the rule; the clear rule is provisioned to the nodes.
- **Credential / VC** — a signed claim about a holder (a verifiable credential),
  presented to the verifier and evaluated against the DCQL rule.
- **Holder proof** — a proof-of-possession signed with the holder DID's
  authentication key, binding a presentation to a fresh verifier nonce. Stops a
  leaked credential from being replayed by someone else.
- **Verifier** — the service that checks credentials against a slot's rule and
  mints the short-lived JWT the keeper nodes accept.
- **Committee** — two distinct things, unfortunately: (1) the *keeper* committee,
  the `n` nodes drawn on-chain to hold a slot's shards; (2) the *verifier*
  committee of the committee path, a per-request quorum drawn from the on-chain
  verifier set. Where it matters below, which one is meant is stated.
- **TASRA** — the network's token, used for staking, metering, and settlement.
  (Spelled `Tasra` in contract and type names.)

---

[← Back to the README](../README.md) · [Documentation index](README.md)
