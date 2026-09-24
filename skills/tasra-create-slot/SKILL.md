---
name: tasra-create-slot
description: Create a Tasra key slot on-chain with tasra-sdk/chain and get it ready for use — write client setup, chainId rules, the DCQL rule commitment, k-of-n and mode, getting gas and test EURC from a testnet faucet, buying TASRA on the bonding curve, funding the slot's metering balance, waiting for DKG, persisting the rule salt durably (lose it and the slot is unusable), and rule provisioning. Use for "create a slot", "createSlot", "createTasraWriteClient", "fund a slot", "faucet", "EURC", "buy TASRA", "bonding curve", "wait for DKG", "chainId is required" errors, and gas sponsorship via relay.
metadata:
  package: tasra-sdk
  sources:
    - docs/prerequisites.md
    - docs/chain.md
    - dist/chain/write.d.ts
---

# Create a key slot on-chain

A slot is one threshold keypair plus the access policy governing it. Creating
one is a permissionless, fee-less transaction signed by the creator's own EVM
account; gas is the only cost. Everything below lives in `tasra-sdk/chain`
and needs `viem` installed.

## Inputs you need

- `rpcUrl` and the chain id of the deployment.
- An address book of the deployed contracts. For Fuji, obtain the pointer and
  `tasra-fuji-v1.json` from [tasra-releases](https://github.com/t3-foundry/tasra-releases)
  and use `parsePinnedNetworkManifest` → `addressBookFromManifest` from
  `tasra-chain`; pass `manifest.chainId` (43113). For operator-provided configuration,
  use `addressBookFromEnv(process.env)` — env keys `KEY_REGISTRY`, `NODE_REGISTRY`,
  `SETTLEMENT`, `TASRA_TOKEN`, `THRESHOLD_BEACON`, plus `BONDING_CURVE` and
  `EURC` for the funding steps below and `VERIFIER_SET_REGISTRY` for the
  committee path — or `addressBookFromObject({KeyRegistry: '0x…',
  NodeRegistry: '0x…', Settlement: '0x…', TasraToken: '0x…',
  ThresholdRandomBeacon: '0x…'})`, whose keys are the **PascalCase contract
  names** exactly as `requireAddress(book, 'KeyRegistry')` looks them up (the
  object form does not translate keys), or `addressBookFromBroadcast(foundryJson)`.
  Which entries a call needs depends on the call; a missing one throws from
  `requireAddress` naming the key.
- A funded creator key, or a chain-bound viem `WalletClient` (browser wallet).
- A DCQL rule string (see `tasra-dcql-rules`). **Decide its shape now**: the rule
  is committed at creation and cannot be amended without a `rulePolicy`, so a slot
  that will serve identity-scoped operations (IBE extraction — `tasra-ibe-identity-scoped`)
  needs `kk_identity_scope_claim` / `kk_scope_namespace` in the rule from the start.
  Adding them later means a new slot, and anything already sealed to the old slot's
  key is stranded.

## Steps

The whole order for a brand-new account, once: **(1)** gas + test EURC and
**(2)** buy TASRA — both in "Funding" below — then **(3)** `createSlot`,
**(4)** resolve the keepers, **(5)** wait for DKG, **(6)** provision the rule
(see "Provision the rule"), **(7)** `fundSlot`, and **(8)** `setVerifierPolicy`
when the slot will be used over the committee path. The block below is steps 3 to 8.

```ts
import {
  createTasraChainClient, createTasraWriteClient, addressBookFromEnv,
  resolveSlotKeeperUrls, resolveVerifierDirectory,
} from 'tasra-sdk/chain'
import {fetchMpk} from 'tasra-sdk'
import {keccak256, toHex} from 'viem'

const addresses = addressBookFromEnv(process.env)
const chain  = createTasraChainClient({rpcUrl, addresses, chainId})
const writer = createTasraWriteClient({rpcUrl, addresses, chainId, privateKey})
// browser: createTasraWriteClient({rpcUrl, addresses, wallet})  // wallet bound to account + chain

// 3. create — mode: 'bls' encryption, 'frost' Ed25519 signing, 'tecdsa' an EVM account,
//    plus 'bls-bn254' and 'tecdsa-p256'. The fleet must run keepers for the mode you pick.

//    SIZE n AGAINST THE ELIGIBLE POOL, NOT THE FLEET. The committee is drawn only from operators
//    carrying the tag in `tags`, and `tags` DEFAULTS TO ['keykeeper'] when you pass none — so the
//    pool is always narrower than activeOperators(), and n above it reverts
//    `InsufficientFilteredPool(have, need)`. Two reads answer it:
const tag = keccak256(toHex('keykeeper'))                     // the default tag; keccak of your own otherwise
const operators = (await chain.readers.nodeRegistry.activeOperators()) as readonly `0x${string}`[]
const eligible: `0x${string}`[] = []
for (const op of operators) if (await chain.readers.nodeRegistry.hasTag(op, tag)) eligible.push(op)
const k = 2, n = 3                                            // k <= n <= eligible.length
if (eligible.length < n) throw new Error(`${eligible.length} eligible keepers; n=${n} cannot be drawn`)

//    ASK THE REGISTRY WHICH CALL IT ACCEPTS. A deployment that sets requireCommitReveal — every
//    production genesis does — refuses createSlot with CommitRevealRequired() and takes only the
//    two-phase call. One read tells you which, and costs nothing:
const oneShot = !(await chain.readers.keyRegistry.requiresCommitReveal())
const created = oneShot
  ? await writer.createSlot({dcqlRule, k, n, mode: 'bls'})
  // Commits the parameters, then asks the accountants for a seed to reveal immediately.
  // Falls back to the beacon-epoch wait when no usable seed is available; onEpoch reports
  // that wait with NUMBERS, not bigints. Returns commitTx, revealTx, and seeded instead of txHash.
  : await writer.createSlotCommitReveal({dcqlRule, k, n, mode: 'bls', onEpoch: (cur, target) => console.log(`epoch ${cur}/${target}`)})
const {slotId, ruleSalt} = created
const txHash = 'txHash' in created ? created.txHash : created.revealTx
// slotId and ruleSalt are 0x-hex strings.

// ⚠⚠ 3b. PERSIST {slotId, ruleSalt} DURABLY, NOW — before the DKG poll, before anything.
// This is the only time you are handed the salt. The chain holds only the salted
// commitment, the salt is random and cannot be re-derived, and the SDK stores nothing.
// Lose it and the slot is permanently unusable: see "Persist the salt" below.
await yourStore.putSlot({slotId, ruleSalt, dcqlRule})   // your storage, not the SDK's

// 4. the keeper committee was drawn on-chain; read its URLs, do not configure them.
//    On-chain URLs are often in-cluster names (http://tasra-node-7:8080); map them to
//    addresses reachable from where you run — otherwise the DKG poll below just times out.
const basePort = Number(process.env.KEEPER_LOCAL_BASE_PORT ?? 8090)   // .env.example carries this
const rewriteUrl = (u: string) => u.replace(/^http:\/\/tasra-node-(\d+):8080$/, (_, i) => `http://localhost:${basePort + Number(i)}`)  // YOUR mapping; not an SDK export
const nodes = (await resolveSlotKeeperUrls(chain, slotId)).map(rewriteUrl)

// 5. wait for distributed key generation: poll for a NON-EMPTY group key.
//    HOW LONG depends on the mode: 'bls' and 'frost' key in a few seconds, 'tecdsa' runs an
//    extra AuxInfo phase and takes ~30-40s. A single read right after createSlot returns an
//    empty key for a tecdsa slot that is keying perfectly well — poll, do not conclude.
//    Ask EVERY keeper, not nodes[0]: one keeper can be down or lagging while the rest key the slot,
//    and k keyed keepers are enough to serve it.
const deadline = Date.now() + 120_000
let keyed: string[] = []
while (keyed.length < k && Date.now() < deadline) {
  keyed = []
  for (const node of nodes) {
    try {
      const {mpkBytes} = await fetchMpk(node, slotId)  // GET {node}/v1/keys/{slotId}/public
      if (mpkBytes.length > 0) keyed.push(node)        // 200 with empty bytes = known, not yet keyed
    } catch { /* not served yet, or this keeper is down */ }
  }
  if (keyed.length < k) await new Promise(r => setTimeout(r, 2000))
}
if (keyed.length < k) throw new Error(`DKG timed out: ${keyed.length} of ${nodes.length} keepers keyed, need ${k}`)

// 6. provision the rule to every keeper — see "Provision the rule" below. Until it is done the
//    keepers cannot evaluate access, so no session opens. A keeper that never gets it cannot answer.

// 7. fund metered usage. tsraAmount comes from the buy in "Funding" below, which runs first.
await writer.fundSlot(slotId, tsraAmount)

// 8. the per-request verifier policy — REQUIRED before any committee-path operation.
//    Until it is set, ibeExtractRequest / ibeDecryptRequest / createCommitteeSlotClient all fail
//    with `slot 0x… has no verifierPolicy (committee path not wired); use the JWT path`, and
//    nothing in the steps above reveals that. The managed JWT path (Session.decrypt) does not
//    need it, so set it only for slots that will serve the committee or IBE paths.
//    `committee` verifiers are drawn per request and `quorum` of them must co-sign (both uint16);
//    committee cannot exceed the on-chain verifier set.
const verifierCount = (await resolveVerifierDirectory(chain)).length
await writer.setVerifierPolicy(slotId, Math.min(3, verifierCount), 2)
```

Every write method returns only after its transaction is mined and its receipt says `success`
(a reverted transaction throws), so calls can be written one after another as they are here.

## Funding: gas → EURC → TASRA → the slot

Creating a slot is fee-less (only gas), but every metered operation on it is
paid from the slot's TASRA balance in the Settlement contract. On a test
deployment the whole chain of funding is self-serve:

```ts
import {parseUnits, formatEther} from 'viem'
import {httpFaucet} from 'tasra-sdk'   // only for route (b)

// How much TASRA the slot should start with; everything here is about having that much in hand.
const tsraNeeded = parseUnits('10', 18)

// 1. gas + test EURC. FIRST ASK WHETHER YOU NEED ANY OF THIS: an account an operator provisioned
//    already holds both, and then the whole funding section is skipped. Read, do not assume — a
//    deployment that hands out funded accounts has no faucet to fall back on.
const hasGas = (await writer.ethBalance(writer.address)) > parseUnits('0.05', 18)
const hasTsra = (await writer.tsraBalance(writer.address)) >= tsraNeeded
//    Otherwise: THREE ALTERNATIVES — exactly one exists on a given deployment, so pick the one whose
//    variable is set and skip the others. None of these names is in .env.example: ask the operator
//    which route the deployment serves and under which URL.
const onrampUrl = process.env.KK_ONRAMP_URL   // (a) application on-ramp
const faucetUrl = process.env.KK_FAUCET_URL   // (b) standalone faucet service
const funderKey = process.env.KK_FUNDER_KEY   // (c) dev chain: a funded key that drips gas
let tsraFromFaucet: bigint | undefined
if (hasGas && hasTsra) {
  // nothing to do: the account is already funded
} else if (onrampUrl) {
  // POST {onramp}/v1/onramp with {address, eurCents}: mints mock EURC and drips native gas; replies
  // {eurcBalance}. The NETWORK's relayer (KK_RELAYER_URL) does NOT serve this route — an application
  // relayer such as the Tasra Vault's does. Testnets and local fleets only: real EURC has no open mint.
  await fetch(`${onrampUrl}/v1/onramp`, {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({address: writer.address, eurCents: 2000})})
} else if (faucetUrl) {
  // httpFaucet(faucetUrl).fund(address) from 'tasra-sdk' posts to {faucetUrl}/faucet →
  // {address, ethWei?, tsra?, txHashes?} — DECIMAL STRINGS, both optional. When `tsra` comes back the
  // faucet has funded TASRA directly: skip step 2 and use BigInt(tsra) as tsraAmount.
  const drip = await httpFaucet(faucetUrl).fund(writer.address)
  if (drip.tsra) tsraFromFaucet = BigInt(drip.tsra)
} else {
  // A dev chain with the mock token: gas from a second write client on a funded key. The EURC is
  // minted in step 2, once the amount the slot actually needs is known.
  // `process.env.X` is `string`, `privateKey` is viem's `Hex` — every key, address and slot id
  // read from the environment needs the cast, here and everywhere below.
  if (funderKey) await createTasraWriteClient({rpcUrl, addresses, chainId, privateKey: funderKey as `0x${string}`})
    .sendEth(writer.address, parseUnits('0.2', 18))
}

// 2. quote and buy TASRA on the bonding curve. EURC has 6 decimals, TASRA 18.
//    Skip it when the account already holds enough, or the faucet handed you TASRA.
//    BUY FROM THE AMOUNT YOU NEED, never from a guessed EUR figure: the curve price decides how
//    much a given EUR amount buys, so "spend 20 EUR, then fund 10 TASRA" reverts the moment the
//    price makes 20 EUR worth less than 10. `eurCentsForTsra` is the inverse of `tsraForEurCents`.
if (!hasTsra && !tsraFromFaucet) {
  const short = tsraNeeded - (await writer.tsraBalance(writer.address))
  const cents = ((await chain.read('BondingCurve', 'eurCentsForTsra', [short])) as bigint) * 115n / 100n  // headroom: the price rises as you buy
  const eurcUnits = cents * 10_000n                                                                  // cents -> EURC's 6 decimals
  const quote = (await chain.read('BondingCurve', 'tsraForEurCents', [cents])) as bigint             // read() returns unknown; TASRA, 18 decimals
  if (!onrampUrl && !faucetUrl) await writer.mintMockEurc(writer.address, eurcUnits)                 // dev chain's mock token only
  await writer.approveEurcForCurve(eurcUnits)                                                        // ERC-20 approve to the curve
  await writer.buyTsra(eurcUnits, (quote * 97n) / 100n)                                              // minTsraOut: 3 % slippage floor
}
console.log('TASRA balance', formatEther(await writer.tsraBalance(writer.address)))

// tsraAmount is what step 7 of the main block funds the slot with — the funding block stops here.
const tsraAmount = tsraFromFaucet ?? tsraNeeded
```

`writer.eurcBalance(address)`, `writer.tsraBalance(address)`, `writer.ethBalance(address)`
and `writer.settlementBalance(slotId)` read the four balances involved;
`writer.spotPrice()` and `writer.priceAt(sold)` read the curve; `redeemTsra(amount, minEurcOut)`
sells back. In production EURC is the real Circle token bought off-chain.

## Gas: who pays

By default the creator key pays gas for every write. A deployment can sponsor
the **sender-bound** calls through its platform relayer (ERC-2771): the client
signs an EIP-712 forward request, the relayer applies its policy, pays the gas
and submits it through the pinned forwarder, and the contract still sees the
signer as the sender — the relayer authorises nothing.

`RelayConfig` is `RegisteredRelayConfig` — **there is no `url` field**. A
relayer is chosen by the application's own on-chain service approvals, not by an address
you type: "Registry membership alone never selects a service." A `{url, forwarder}` object
is the old shape and no longer compiles.

```ts
import {SERVICE_TYPES, readApprovedServiceRecord} from 'tasra-sdk/chain'
import type {RegisteredRelayConfig, ServiceApproval} from 'tasra-sdk/chain'
import {createNodeRelayTransport} from 'tasra-sdk/chain/node'   // NOTE the /chain/node subpath

// 1. Find the registered relayer. SERVICE_TYPES.gasRelayer = 0; status 0 = active.
const ids = await chain.readers.serviceRegistry.serviceIds(0n, 20n)
let approval: ServiceApproval | undefined
for (const serviceId of ids) {
  const s = await chain.readers.serviceRegistry.getService(serviceId)
  if (s.serviceType !== SERVICE_TYPES.gasRelayer || s.status !== 0) continue
  // An approval is YOUR application pinning exactly this record — registry membership
  // alone never selects a service. Pin `revision` and `manifestHash`, not just the id.
  approval = {chainId, registry: requireAddress(addresses, 'ServiceRegistry'), serviceId,
    serviceType: SERVICE_TYPES.gasRelayer, owner: s.owner, revision: s.revision,
    manifestHash: s.manifestHash}
}
await readApprovedServiceRecord(chain, approval!)   // re-reads through the approval; throws if the pin no longer matches

// 2. A relayer on a private host behind a deployment CA needs both stated explicitly;
//    hostname and certificate verification stay mandatory either way.
const transport = createNodeRelayTransport({allowedPrivateHosts: ['localhost'], ca: readFileSync(caFile)})

const writer = createTasraWriteClient({
  rpcUrl, addresses, chainId, privateKey,
  relay: {
    approvals: [approval!],   // in preference order
    transport,
    forwarder,                // the deployment's ERC-2771 forwarder, pinned by YOU — never from a relayer manifest
    // persistAttempt / resumeAttempt make a sponsored write durable across a restart
  } satisfies RegisteredRelayConfig,
})
const {slotId, ruleSalt, relay} = await writer.createSlot({dcqlRule, k, n, mode: 'bls'})
await yourStore.putSlot({slotId, ruleSalt, dcqlRule})   // still required on the sponsored path
relay?.txHash
relay?.costWei          // gas the RELAYER paid, a DECIMAL STRING: BigInt(costWei) before formatEther. Also writer.lastRelay()
```

Verified against a demo fleet: an account holding **0 AVAX** created a slot this way, the
relayer paid `0.08286025 AVAX`, the account's balance was still 0 afterwards, and
`getKeySlot(slotId).creator` was that account — the forwarder preserves `_msgSender()`, so
the relayer pays but authorises nothing.

`createRegisteredRelaySubmitter(chain, config, wallet)` drives it directly, and
`reconcileRelayAttempt` resolves an attempt whose outcome you did not see —
`RelayOutcomeUnknownError` is the case to handle, because a submitted request may have
landed even when the response did not.

**What a deployment sponsors is its relayer's allowlist, not a fixed SDK list.** Read it
rather than assuming — `tasra-cli relay policy` prints `(target, selector, class,
max_gas)`, where class `public` means any account and `operator` means a registered one. A
demo fleet sponsors, as `public`: `createKeySlot` and every filtered/exportable/with-policy
variant, `commitKeySlot` + `revealKeySlot`, `setVerifierPolicy`, `setRulePolicy`,
`setDualControlPolicy`, `Settlement.fund`, bonding-curve `buy`/`redeem`, `cancelSlot`,
`renew`, and the whole rule-amendment path (`proposeRuleUpdate`, `endorseRuleUpdate`,
`activateRuleUpdate`, `vetoRuleUpdate`).

One invariant holds everywhere: **ERC-20 `approve` is never sponsorable** — it is not
2771-aware, so it always comes from your key. `fundSlot` and `buyTsra` each need one. So
even a fully sponsored developer needs a little native gas; that is what the faucet's gas
drip is for. If the relayer refuses a call (its policy, or relay mode off) the error names
the relay; without `relay` in the config nothing is sponsored and every call needs gas.

## Persist the salt

**The SDK persists nothing** — no storage, no filesystem, no directory of slots. Both
creation calls hand you `ruleSalt` exactly once and it is then your responsibility.

At minimum, store durably and atomically with the creation:

| Keep | Why |
|---|---|
| `slotId` | everything else is keyed by it |
| `ruleSalt` | random, **not derivable**, and the chain holds only `keccak256(DOMAIN ‖ ruleSalt ‖ rule)` |
| the clear `dcqlRule` | provisioning sends the rule and the salt together; the chain never stores the rule |

⚠ **Losing the salt makes the slot permanently unusable.** A keeper recomputes the
commitment before accepting a clear rule, so provisioning fails with `dcql_rule does not
match the slot's on-chain commitment`. That message reads like a typo in a rule that is
perfectly fine, which is what makes this expensive to diagnose. There is no recovery
path: the salt is not on chain, not in the SDK, and not reconstructible from the
commitment. The slot keeps its identity and its key forever and can never be authorized.

Two practical consequences:

- **Write before you wait.** Persist immediately after the creation call returns, not
  after the DKG poll. The poll can take minutes and any crash in between loses the salt
  while the slot exists on chain.
- **`verifyRuleCommitment(rule, salt, commitment)` is your integrity check**, not a
  recovery tool. Run it against what you stored and the on-chain `ruleCommitment` to
  confirm the pair is still the right one — it tells you a record is wrong, never what
  the right value was.

If your application creates slots on a user's behalf, treat `{slotId, ruleSalt}` with the
same durability guarantees as the rest of that user's account state.

## Provision the rule (required before any session)

After DKG and before anything can open a session, the clear rule goes to the
keepers and the first credential is minted. Both are operator-gated:

- Rule provisioning is `POST {node}/v1/keys/{slotId}/rule` with body
  `{dcql_rule, dcql_salt}` and `Authorization: Bearer <admin JWT>`, sent to
  every keeper. **The admin JWT does not decide the rule.** The keeper recomputes the
  salted commitment over `{dcql_rule, dcql_salt}` and compares it with the `ruleCommitment`
  your `createSlot` wrote on chain; a mismatch is refused with `dcql_rule does not match
  the slot's on-chain commitment`. The only rule any keeper accepts is the exact preimage
  the creator committed, so provisioning is delivery of a rule already fixed at creation,
  not a second chance to choose one — and an operator cannot substitute a policy of their
  own. The clear rule stays off-chain on purpose (the commitment is salted so the
  low-entropy grammar cannot be guessed from it), which is why this step exists at all. The SDK has no helper for it; the nodes cannot evaluate access
  until it is done. The admin JWT is an EdDSA JWT the operator's signing key
  produces — the deployment's JWT signing seed (32 bytes; env `KK_JWT_SIGNING_KEY`),
  header `{"alg":"EdDSA","typ":"JWT"}`, claims `{sub, iss, aud, iat, exp, scope: ["admin"]}`
  with the `iss`/`aud` the nodes are configured for (demo fleet:
  `your-verifier-iss` / `your-node-aud`), signature
  `ed25519.sign(utf8(base64url(header) + "." + base64url(claims)), seed)` from
  `@noble/curves/ed25519`. `sub` is free-form (`admin` does); keep `exp` short,
  minutes rather than hours. If `KK_ADMIN_JWT` is already set and unexpired, use
  it and mint nothing. A 2xx from
  every keeper means the rule is live; 401/403 means the JWT lacks the admin
  scope or has the wrong issuer/audience. Send it to every keeper and count the
  2xxs: `k` keepers that are both keyed and provisioned can serve the slot, but a
  keeper that never got the rule cannot answer a request routed to it. `{slotId}` in that path is the 0x-hex
  string `createSlot` returned, exactly as `fetchMpk` uses it. The signing seed
  in `KK_JWT_SIGNING_KEY` is 32 bytes as hex, with or without the `0x` prefix.
- The first credential comes from `issueAdminCredential(verifier, adminSecret, {scopes, slotIds})`
  or from a credential issuer (see `tasra-credentials-and-sessions`).

## Amending a slot's rule

**Decide this at creation or never.** A slot whose `rulePolicy.admin` is unset has an
**immutable** rule — `proposeRuleUpdate` reverts `RuleImmutable()` forever. And the
recovery window is tiny: `setRulePolicy` demands `_msgSender() == creator`, no policy
already set, and a **fresh** slot (`epoch == 0 && publicKey.length == 0 && ruleVersion == 0`)
— so once DKG submits the group key, seconds after creation, it reverts
`RulePolicySlotNotFresh()`. Pin it in `createSlot({..., rulePolicy})`, which is trivially
fresh because it happens in the same transaction.

```ts
await writer.createSlot({dcqlRule, k, n, mode: 'bls', rulePolicy: {
  admin: appOwner,        // the only address that may propose an amendment
  guardian: securityTeam, // may veto, or endorse to skip the delay. MUST differ from admin
  timelockSecs: 86_400,   // with NO guardian, at least MIN_RULE_TIMELOCK (1 hour)
}})
```

**A guardian is optional and is a second key, not a second party.** `guardian` need only
*differ from* `admin`, so a sole owner's normal posture is a hot admin key and a cold
guardian key they also hold: propose from hot, `endorseRuleUpdate` from cold, activate at
once — and if the hot key leaks, the cold one vetoes.

**The guardian is also what buys a short timelock.** `MIN_RULE_TIMELOCK` (1 hour) binds
only when `guardian == address(0)`, so a guarded policy may set `timelockSecs: 0` and skip
`endorseRuleUpdate` entirely — amendment then takes only as long as the keepers need to
attest. Omitting the guardian is legal and works, but every amendment waits the full hour,
because the rule *is* the access control: whoever can change it can grant themselves the
key, so an instant unilateral change would turn a stolen admin key into an instant
compromise. frames the delay precisely: it "exists solely to give the guardian time to notice
and object", which is why it may be zero when a guardian exists and must be ≥ 1 hour when
one does not. The timelock is a **notice** property; the `n − k + 1` adoption threshold is
the **safety** property and nothing may waive it. But note what adoption does *not* cover:
keepers attest that they hold the new rule, not that they approve it, so a compromised
`admin` on a zero-timelock slot can propose a rule granting itself the key and have it
adopted within seconds. lists `ruleTimelock: 0–1h` as the *dev / low-value*
posture and `1h` as the production one — keep a real delay on any slot whose admin key is
hot, and monitor `RuleUpdateProposed`, without which the timelock buys nothing.

Then the amendment is a four-party dance, and each party is different:

| step | who | what |
|---|---|---|
| `proposeRuleUpdate(slotId, newRuleCommitment)` | **admin only** | pins `ruleVersion + 1` and `notBefore = now + timelock`. One pending amendment at a time; the new hash cannot equal the current one |
| deliver the new clear rule + its salt | operator (the admin-gated POST) | the keeper matches it against the **pending** commitment and stores it as pending — the live rule keeps serving |
| `attestRuleAdoption(slotId, ruleVer, ruleCommitment)` | **each assigned keeper** | "I hold and have verified this rule". Needs `n - k + 1` of them. Keepers should attest *during* the timelock |
| `endorseRuleUpdate(slotId)` | **guardian only**, optional | collapses `notBefore` to now — the fast path |
| `vetoRuleUpdate(slotId)` | **guardian only**, optional | discards the proposal. A tripwire, not a wall: the admin may propose again |
| `activateRuleUpdate(slotId)` | **anyone** | swaps `ruleCommitment` and bumps `ruleVersion`, but only once the timelock has elapsed **and** adoptions ≥ `n - k + 1` |

The adoption threshold is the point of the whole design: the rule cannot become active
until enough keepers already hold its preimage, so a slot never points at a commitment
nobody can resolve. `ruleAdoptionThreshold(slotId)` and `ruleAdoptionVotes(slotId)` read
the progress.

The SDK's write client exposes `setRulePolicy` only; send the four update calls with viem
against `CONTRACT_ABIS.KeyRegistry`. All four are typically relayer-`public`, so an owner
amends their own policy without gas.

## `chainId` rule

`createTasraWriteClient` throws unless `chainId` is given or the wallet is
chain-bound, except when `rpcUrl` is a loopback address (then the local
default, `DEFAULT_CHAIN_ID` = 1337, applies). The throw is a `TasraError`
(from `tasra-sdk`) at construction time, before any network call; failures
of the writes themselves surface as viem `ContractFunctionExecutionError`s. The chain id goes into every
EIP-155 signature; a wrong one means the RPC node (not the keeper) rejects every
write, with no useful message. Always pass it.

## Other write-client methods

`createSlotCommitReveal` accepts `slotSeed: false` to use the beacon-epoch path,
`accountantUrls` to override accountant discovery, `slotSeedTimeoutMs` for each
accountant request, and `onSeed` to observe the seed response (or `null` for fallback).
Its `seeded` result indicates whether the seeded reveal succeeded. A failed seeded
reveal through a relay propagates the error, leaving retries to the relay submitter.

`createSlotCommitReveal` (two-phase creation — the only one a registry with
`requireCommitReveal` accepts; see step 3), `fundSlot`, `rotateKey`,
`reshareKey`, `cancelSlot`, `renewSlot`, `setVerifierPolicy(slotId, committee, quorum)`
(step 8 above — the committee path does not run without it),
`setRulePolicy`, token helpers (`buyTsra`, `redeemTsra`, `tsraBalance`,
`ethBalance`, `settlementBalance`), and `sendEth(to, wei)`. `writer.address` is the
creator identity; `generateClientKey()` mints a fresh 0x-hex private key for a
new sovereign account. Gas sponsorship is described under "Gas: who pays".

`createSlot` options worth knowing: `rulePolicy` pins an amendment authority in
the same transaction — do this here, not with `setRulePolicy` afterwards, which loses a
race against DKG and leaves the rule immutable for good (see "Amending a slot's rule"); `exportable: true` allows raw shard export, which is
what the managed `Session.decrypt` needs — without it the keepers refuse shard
release (403) and the slot is decrypted over the threshold instead; use it only
for personal-vault or recovery slots; `tags` filters the committee draw and
**defaults to `['keykeeper']`** — there is no unfiltered draw, so size `n` against the
tagged pool as step 3 does.

Rule grammar on the bearer-JWT path: the keepers evaluate a DCQL query with
`format: "jwt"` against a virtual credential built from the token (`sub`, `iss`,
`scope`). `{"credentials":[{"id":"e","format":"jwt","claims":[{"path":["sub"],"values":["did:example:alice"]}]}]}`
admits one holder. This form is **not** accepted by the SDK's `validateDcql`
(which knows only the OID4VP formats) — pass it to `createSlot` unvalidated;
the commitment is then over the raw bytes, and the keepers accept it. OID4VP
rules (`jwt_vc_json`, `dc+sd-jwt`, with the `["iss"]` entry) are for the
credential paths (`tasra-committee-path`, `vpJwt` sessions).

## Common mistakes

- ❌ Omitting `chainId` against a remote RPC. The client refuses; pass the
  deployment's chain id.
- ❌ Polling `/public` for HTTP 200. It answers 200 as soon as the slot is known
  from chain, before the key exists. Poll for a non-empty `mpkBytes`.
- ❌ Hardcoding keeper URLs after creation. They are a chain read
  (`resolveSlotKeeperUrls`).
- ❌ Losing `ruleSalt`. Not a verification inconvenience — the slot becomes
  **permanently unusable**. See "Persist the salt" below.
- ❌ Destructuring only `{slotId}` from a creation call and dropping the rest. That is
  how the salt gets lost.
- ❌ Calling `setRulePolicy` after creation from a human-approved wallet. Use
  `rulePolicy` in `createSlot`.
- ❌ Taking `k: 3, n: 5` as a default. `n` must fit the tagged pool;
  `InsufficientFilteredPool(have, need)` names both numbers when it does not.
- ❌ Reaching `chain.keyRegistry` / `chain.nodeRegistry` directly. The typed readers
  are under `chain.readers.*`; the bare form does not exist and fails at `tsc`.
- ❌ Creating a slot for IBE with a rule that is not identity-scoped, or leaving the
  verifier policy unset. Both fail only later, at the first extraction. A rule is immutable unless
  its amendment policy was configured at creation.
- ❌ Reading a `fundSlot` revert as a slot problem. Short TASRA surfaces as the token's
  own error bubbling out of `Settlement.fund`, which viem cannot name against the
  Settlement ABI — it arrives as the bare selector `0xe450d38c`
  (`ERC20InsufficientBalance`). Check `writer.tsraBalance(writer.address)` first.

## Where to read more

- `node_modules/tasra-sdk/docs/chain.md` and `docs/prerequisites.md`.
- `node_modules/tasra-sdk/dist/chain/write.d.ts` (`CreateSlotArgs`,
  `WriteClientConfig`, `RelayConfig`).
