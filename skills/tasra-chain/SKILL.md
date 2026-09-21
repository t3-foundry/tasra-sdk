---
name: tasra-chain
description: Read a Tasra deployment from chain with tasra-sdk/chain — address books (addressBookFromEnv/Object/Broadcast), the viem read client (createTasraChainClient) and its typed readers, windowed event decoding, on-chain discovery of a slot's keepers and the verifier directory, live node/verifier info, and the slot-driven client createTasraSlotClient. Use for "read the registry", "which nodes hold my slot", "decode events", "explorer", "addressBook", "rewriteUrl", "NETWORKS".
metadata:
  package: tasra-sdk
  sources:
    - docs/chain.md
    - dist/chain/client.d.ts
    - dist/chain/discovery.d.ts
    - dist/chain/deployments.d.ts
---

# `tasra-sdk/chain`

Everything on-chain, behind its own subpath so the crypto core stays free of
`viem`. Install `viem` alongside the SDK to use it.

## Public deployment manifest

A manifest is the record of a deployment — every contract, its address, its runtime
code hash and its proxy implementation. Configuring from one means no address is ever
copied by hand, and nothing loads that does not match its pin.

```ts
import {parsePinnedNetworkManifest, addressBookFromManifest, observeNetworkManifest} from 'tasra-sdk/chain'

const manifest  = parsePinnedNetworkManifest(readFileSync(path, 'utf8'), expectedSha256)
const addresses = addressBookFromManifest(manifest)
const chain     = createTasraChainClient({rpcUrl, addresses, chainId: manifest.chainId})
const obs       = await observeNetworkManifest(manifest, rpcUrl)   // {matches, contracts[], blockNumber}
```

Obtain the JSON and its SHA-256 from a verified release, never from a moving explorer
response, and never invent addresses from a network name. The digest is the whole
point: a file that does not hash to it throws
`Network manifest SHA-256 mismatch` before any network call.

- **Only `status: "active"` configures a live client.** Planned and retired records are
  for display; `addressBookFromManifest` will not give you a usable book from one.
- `observeNetworkManifest` compares finalized runtime code and proxy implementations
  with the record. It certifies **code identity only** — not service readiness,
  governance wiring or audit quality.
- **A manifest records contracts, not endpoints or secrets.** `services[]` is often
  empty (a manifest generated from a deployment broadcast has no service data), so
  keeper, verifier-agent and RPC URLs still come from the operator — as do every key
  and token. A dev deployment's mock EURC is usually absent too, so `mintMockEurc`
  needs its address from elsewhere while `BondingCurve` reads fine from the book.
- Regenerate it whenever the deployment changes: the addresses move and the old digest
  stops verifying, which is the behaviour you want.

The public package ships `dist/chain/manifest.d.ts` and the other declarations;
no private source checkout is needed.

## Address book and read client

```ts
import {createTasraChainClient, addressBookFromEnv, addressBookFromObject, requireAddress, NETWORKS} from 'tasra-sdk/chain'

// env keys: KEY_REGISTRY, NODE_REGISTRY, SETTLEMENT, TASRA_TOKEN, BONDING_CURVE, TREASURY,
// TASRA_VESTING_VAULT, THRESHOLD_BEACON, VERIFIER_SET_REGISTRY, … — the book keeps BOTH the env
// alias and the PascalCase contract name, so `requireAddress` "Known:" lists show each twice
const addresses = addressBookFromEnv(process.env)
// or addressBookFromObject({KeyRegistry: '0x…', NodeRegistry: '0x…'})  — keys are the PascalCase
// contract names as-is (no translation); or addressBookFromBroadcast(foundryRunJson)
const chain = createTasraChainClient({rpcUrl, addresses, chainId, logWindow: 1_000})   // at or under the RPC's getLogs cap
```

Slot ids everywhere in this subpath are the bytes32 id as a `0x…` hex string
(viem `Hex`), never a number or bigint.

`requireAddress(book, 'KeyRegistry')` throws with the known keys when one is
missing. `NETWORKS` holds named presets (`chainId` + `rpcUrl`); `local`, `testnet` and `mainnet`
provide chain policy; deployed contract addresses come from a pinned manifest. `chainId` defaults
to the local dev chain (1337) and the RPC is never consulted for it; pass it explicitly for any
other deployment. `logWindow` must
stay under your RPC's `getLogs` range cap (public RPCs: about 2k blocks).
Construction is offline — it only configures viem; the first read is the first
RPC call, and a missing address throws there rather than at construction.

## Reading

```ts
const slot  = await chain.readers.keyRegistry.getKeySlot(slotId)
const nodes = await chain.readers.keyRegistry.assignedNodes(slotId)
const ops   = await chain.readers.nodeRegistry.activeOperators()
const bal   = await chain.readers.settlement.balanceOf(slotId)
const keeps = await chain.readers.nodeRegistry.hasTag(ops[0], keccak256(toHex('keykeeper')))  // role tag
const policy = await chain.readers.keyRegistry.verifierPolicy(slotId)   // [committee, quorum]; 0 = unset
const cr    = await chain.readers.keyRegistry.requiresCommitReveal()    // which createSlot call the registry takes
```

Reader namespaces: `nodeRegistry`, `keyRegistry`, `settlement`, `token`,
`bondingCurve`, `treasury`, `vault`, `beacon`, `verifierSet`. They live under
`chain.readers.*` — `chain.keyRegistry` does not exist.

`activeOperators()` is the whole fleet; a slot's committee is drawn only from the
operators carrying its tag, so the pool a new slot can use is
`activeOperators().filter(hasTag)` — count it before choosing `n`
(`tasra-create-slot`):

```ts
const tag = keccak256(toHex('keykeeper'))                    // createSlot's default tag
const eligible = []
for (const op of await chain.readers.nodeRegistry.activeOperators())
  if (await chain.readers.nodeRegistry.hasTag(op, tag)) eligible.push(op)
```
`chain.read(contract, fn, args)` and `chain.readMany(...)` cover the rest;
concurrent reads are batched through Multicall3. `chain.client` is the
underlying viem `PublicClient` and `chain.addresses` the resolved book.

Events: `chain.getLogsWindowed({fromBlock, toBlock, contracts?, onWindow?})`
walks a range in windows and returns `DecodedEvent[]` — `{category, contract,
address, eventName, args, blockNumber, blockHash, txHash, txIndex, logIndex}`;
`contracts` takes PascalCase book names; block numbers are viem `bigint`s, and
`onWindow(toBlock, events)` fires per window. The range is inclusive at both
ends, so for the last N blocks take `const head = await chain.getBlockNumber()`,
then `fromBlock = head >= N - 1n ? head - (N - 1n) : 0n` and `toBlock = head` —
a young chain has fewer blocks than you asked for. `decodeContractLogs`,
`categoryFor`, `eventNamesOf` and `jsonSafe` support explorer-style tooling:
`jsonSafe(value)` is not a stringifier, it returns a copy with every `bigint`
turned into a string, so hand its result to `JSON.stringify`.
`chain.getBlockTimestamps(blockNumbers)` batches timestamps.

## Discovery

```ts
import {resolveSlotKeeperUrls, resolveVerifierDirectory, resolveSlotGroupKey, VERIFIER_TAG} from 'tasra-sdk/chain'

const keeperUrls = await resolveSlotKeeperUrls(chain, slotId)   // assignedNodes → NodeRegistry.nodeOf(op).url
const verifiers  = await resolveVerifierDirectory(chain)         // CommitteeVerifier[] {index, url, operator?, pubkey?}, by ascending address
const {publicKey, epoch, mode} = await resolveSlotGroupKey(chain, slotId)   // mode: number, 0 = frost, 1 = bls; epoch: number
```

`VERIFIER_TAG` is `keccak256("verifier")`, the `NodeRegistry` role tag
`resolveVerifierDirectory` selects on. Address-book entries these need:
`resolveSlotKeeperUrls` reads `KeyRegistry` + `NodeRegistry`,
`resolveVerifierDirectory` only `NodeRegistry`, `resolveSlotGroupKey` only
`KeyRegistry`; `createTasraSlotClient` uses the first two. The committee path
also reads `ThresholdRandomBeacon` and `VerifierSetRegistry` (`tasra-committee-path`).

Live-fleet HTTP readers (`import {nodeApi, verifierApi, parsePrometheus} from 'tasra-sdk/chain'`)
are plain objects of functions taking the base URL:
`nodeApi.info(nodeUrl)` (`version`, `peer_id`, `node_identifier` — the node's BLS
identifier — and feature gates such as `admin_scope_enabled`; fields are
snake_case as the node returns them, and every one of them is optional in
`NodeInfo`, so narrow before using a value), `nodeApi.keys(nodeUrl)`, `nodeApi.metering(nodeUrl, id)`,
`verifierApi.info(verifierUrl)`, and `parsePrometheus(text)` for metrics.
These take the URL you pass; `rewriteUrl` belongs to the slot client and does not
reach them, so apply the same mapping yourself to a discovered URL first.

## The slot-driven client

```ts
import {createTasraSlotClient} from 'tasra-sdk/chain'

const kk = createTasraSlotClient({
  chain,
  identity: 'did:example:alice',   // this holder's DID (KK_IDENTITY in the other skills)
  rewriteUrl: u => u.replace('tasra-node-', 'nodes.example.com/node-'),  // in-cluster → reachable,
                                   // applied to both the keeper URLs and the chosen verifier
  onResolve: r => console.log(r.verifier, r.nodes),
})
const s = await kk.openSession(slotId, {renewalToken})   // same Session API as createTasraClient
await s.close()                                           // kk.closeAll() closes every session
```

It reads the slot's keepers from chain and chooses the verifier from the
on-chain verifier set; that verifier mints the JWT. The `Session` and the auth
modes are the ones described in `tasra-getting-started` and
`tasra-credentials-and-sessions`. `identity` is optional for `{jwt}` and
`{renewalToken}` — the token already names the holder — and required for
`{redemptionToken}` and `{vpJwt}`, which throw without it.

## Common mistakes

- ❌ Importing `tasra-sdk/chain` without `viem` installed. It is an
  optional peer; install it.
- ❌ Assuming on-chain node URLs are reachable from your network. They are
  often in-cluster names; use `rewriteUrl` for the slot client, and the same
  mapping by hand for `nodeApi`/`verifierApi` calls.
- ❌ Huge `getLogs` ranges on a public RPC. Set `logWindow` under the cap.
- ❌ Serialising reader results with `JSON.stringify`. Values are `bigint`;
  use `JSON.stringify(jsonSafe(value))`.
- ❌ Passing `number` block ranges to `getLogsWindowed`. Use `bigint`.

## Where to read more

- `node_modules/tasra-sdk/dist/chain/index.d.ts` and the files it re-exports.
