# What you can do

> The capability catalogue: every major thing this SDK does, with the functions that
> do it. Skim it once to learn the shape of the surface, then use
> [the API reference](api.md) for detail.

- **Open a managed session** — `createTasraClient({nodes, verifier, identity})`
  then `client.openSession(slot, auth)` returns a `Session` that holds the JWT +
  assembled key, **auto-renews the JWT**, **re-assembles on rotation**, and exposes
  `encrypt` / `decrypt` / `sign` / `signDigest` / `close`.
- **…or open one from just a slot id, endpoints resolved from chain** — the chain-driven
  surface in `tasra-sdk/chain`: `createTasraSlotClient` (JWT path) and
  `createCommitteeSlotClient` (committee path) discover the keeper nodes from the
  slot's on-chain committee and **choose the verifier from the on-chain verifier set** — no
  hardcoded node/verifier URLs.
- **Assemble a key from the fleet** — fetch BLS shards from `k`-of-`n`
  keykeeper-nodes and **Lagrange-assemble the master secret key in-process** (the
  local-decrypt model — the nodes reveal their shards and you reconstruct the key), or leave
  the key on the fleet and **decrypt over the threshold** so it's never reconstructed.
  `fetchMpk`, `fetchAndAssembleKey`
- **Encrypt / decrypt envelopes** — ChaCha20-Poly1305 over a BLS12-381 G2 ElGamal
  KEM, in a versioned `[KK]<base64>` wire envelope. `encryptEnvelope`,
  `decryptWithMasterKey`, `toBytes`/`fromBytes`, `buildTasraText`/`parseTasraPost`
- **Sign** — FROST-Ed25519 (custody one-shot + client-coordinated shard-delivery,
  with local aggregation) and threshold ECDSA for EVM EOAs. `signCustody`,
  `signWithShardDelivery`, `signEoaDigest`, `aggregateFrostSignature`
- **Decrypt over the threshold** — node-coordinated custody or client-side
  share-combine that never assembles the key. `decryptCustody`,
  `decryptWithShardDelivery`, `combineDecryptShares`
- **Obtain & refresh DCQL-gated JWTs** — the full verifier credential lifecycle:
  redeem a credential or renewal for a JWT, present signed VCs, mint admin
  credentials, create/revoke renewals, and revoke a holder's slot access (re-keying
  the slot). `redeemCredential`, `redeemRenewalToken`, `createRenewal`/`revokeRenewal`,
  `issueAdminCredential`, `verifyVpJwt`/`verifyPresentation`, `revokeSlotUser`
- **Authorize with your own identity provider** — no wallet, no credentials: a
  user's DPoP-bound OAuth access token from your Keycloak / Auth0 tenant authorizes the
  operation through a Verifier Agent `oauth` session. `createOauthSession`,
  `submitOauthResponse`, `waitForSession`, `auth0DpopSigner`, `createDpopKey` — see
  [the OAuth + DPoP section](api.md).
- **Evaluate DCQL policy** — validate a rule before paying for a slot, or test a
  subject against a rule client-side; a generic, opaque-scope evaluator mirroring
 the reference implementation crate. `validateDcql`, `evaluateDcql`, `selectDcql`
- **Assemble compound committee authorization tokens** — per-request
  verifier-committee selection, canonical hashing, ed25519 quorum verification,
  verifier-set Merkle proofs. `selectVerifierCommittee`, `compoundTokenHash`,
  `assembleCompoundToken`, `verifyCompoundToken`, …
- **Create on-chain Key Slots** — sovereign, self-signed (see [`tasra-sdk/chain`](chain.md):
  `createTasraWriteClient().createSlot`; permissionless + fee-less). Fund a fresh
  client account with gas + TASRA via the faucet — `httpFaucet`.
- **Read & write on-chain + live-fleet state** — the [`tasra-sdk/chain`](chain.md) subpath.

---

Next: [which client do I want?](../README.md#which-client-do-i-want) ·
[the full API surface](api.md) · [prerequisites](prerequisites.md)

---

[← Back to the README](../README.md) · [Documentation index](README.md)
