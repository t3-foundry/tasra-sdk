// viem-based read client for a Tasra Network deployment. Provides:
//   - a configured PublicClient
//   - windowed log fetching + decoding (for the indexer backfill/tail)
//   - block-timestamp lookups
//   - typed view-function readers for the entities the explorer cares about
//
// Read-only: no wallet, no signing. The explorer never writes to the chain.

import {
  createPublicClient,
  http,
  defineChain,
  type PublicClient,
  type Abi,
  type Log,
  type ReadContractReturnType,
} from 'viem'
import {CONTRACT_ABIS, type ContractName} from './abis/index.js'
import {createServiceRegistryReaders, type ServiceRegistryReaders} from './services.js'
import {nodeRegistryAbi} from './abis/nodeRegistry.js'
import {keyRegistryAbi} from './abis/keyRegistry.js'
import {settlementAbi} from './abis/settlement.js'
import {tasraTokenAbi} from './abis/tasraToken.js'
import {bondingCurveAbi} from './abis/bondingCurve.js'
import {treasuryAbi} from './abis/treasury.js'
import {tasraVestingVaultAbi} from './abis/tasraVestingVault.js'
import {thresholdRandomBeaconAbi} from './abis/thresholdRandomBeacon.js'
import {verifierSetRegistryAbi} from './abis/verifierSetRegistry.js'
import {
  type AddressBook,
  type Address,
  type VaultTranche,
  DEFAULT_CHAIN_ID,
  VAULT_TRANCHES,
  requireAddress,
  requireVaultAddress,
  vaultKey,
} from './deployments.js'
import {decodeContractLogs, type DecodedEvent} from './events.js'

/**
 * Calldata BYTES per Multicall3 aggregate — viem's unit here is bytes, not items, and
 * it chunks the list for us at this size.
 *
 * A cap, not a target. The point is to stop a 10k-operator registry becoming 10k round
 * trips, but one unbounded aggregate is a payload an RPC rejects and an `eth_call` gas
 * budget a node refuses. At ~68 bytes for a one-address view call this is ~480 items per
 * request, so 10k reads become ~21 requests — the win is already three orders of
 * magnitude, and raising it further buys little for real risk.
 *
 * viem's own default is 1024 bytes (~15 items), which is too small to matter here.
 */
const MULTICALL_BATCH_BYTES = 32_768

/** Multicall3's canonical, deterministic-deployment address. */
export const MULTICALL3_ADDRESS: Address = '0xcA11bde05977b3631167028862bE2a173976CA11'

export interface ChainClientConfig {
  /** JSON-RPC HTTP endpoint of the chain. */
  rpcUrl: string
  /** Resolved deployment addresses. */
  addresses: AddressBook
  /** Chain id; defaults to DEFAULT_CHAIN_ID (the RPC is never consulted). */
  chainId?: number
  /** getLogs block-window size; keep ≤ the RPC's range cap (anvil/besu: large; public: ~2k). */
  logWindow?: number
  /**
   * Where Multicall3 lives, for batching the per-item reads in {@link
   * TasraChainClient.readMany} (and therefore the registry enumerations built on it).
   *
   * - omitted — **auto**: probe {@link MULTICALL3_ADDRESS} once with `eth_getCode` and
   *   batch if something is deployed there. A chain without it costs one extra call,
   *   once, and then reads individually forever.
   * - an address — use that deployment instead of the canonical one. Still probed, so a
   *   wrong address degrades to individual reads rather than failing every read.
   * - `false` — never batch. For an RPC that rejects large `eth_call` payloads, or to
   *   keep one read per item for debugging.
   */
  multicall3?: Address | false
}

export interface ReadManyOpts {
  /**
   * What a failing item does.
   *
   * - `true` (default) — the item is `null` in place. One unreadable operator must not
   *   blank the whole set.
   * - `false` — ANY failing item rejects the call. Required whenever position carries
   *   meaning: dropping one operator from an ordered set shifts every index after it,
   *   which silently changes what the caller is looking at.
   */
  allowFailure?: boolean
}

export interface GetLogsWindowedOpts {
  fromBlock: bigint
  toBlock: bigint
  /** Restrict to these contracts (default: all present in the AddressBook). */
  contracts?: ContractName[]
  windowSize?: number
  /** Called after each window with the last block scanned (progress). */
  onWindow?: (toBlock: bigint, events: DecodedEvent[]) => void
}

// ── Explicit public types ────────────────────────────────────────────────────
//
// These are written out rather than inferred (`ReturnType<typeof factory>`).
// Inference forces TypeScript to expand viem's `PublicClient` inline when it emits
// declarations — every action, including ones whose types live at internal module
// paths viem does not export. A consumer's compiler cannot name those, so declaration
// emit fails with TS2742 the moment viem adds an action (2.54 added token/ and siwe/).
// Naming `PublicClient` here, and each result through viem's public
// `ReadContractReturnType`, keeps the emitted types portable AND gives this package a
// stable public API surface that no longer moves when viem adds actions.

export interface NodeRegistryReaders {
  nodeOf(op: Address): Promise<ReadContractReturnType<typeof nodeRegistryAbi, 'nodeOf'>>
  isActive(op: Address): Promise<ReadContractReturnType<typeof nodeRegistryAbi, 'isActive'>>
  operatorCount(): Promise<ReadContractReturnType<typeof nodeRegistryAbi, 'operatorCount'>>
  operatorAt(i: bigint): Promise<ReadContractReturnType<typeof nodeRegistryAbi, 'operatorAt'>>
  activeCount(): Promise<ReadContractReturnType<typeof nodeRegistryAbi, 'activeCount'>>
  attributesOf(op: Address): Promise<ReadContractReturnType<typeof nodeRegistryAbi, 'attributesOf'>>
  rewardBalanceOf(op: Address): Promise<ReadContractReturnType<typeof nodeRegistryAbi, 'rewardBalanceOf'>>
  requiredStake(): Promise<ReadContractReturnType<typeof nodeRegistryAbi, 'requiredStake'>>
  operatorIdOf(op: Address): Promise<ReadContractReturnType<typeof nodeRegistryAbi, 'operatorIdOf'>>
  hasTag(op: Address, tag: `0x${string}`): Promise<ReadContractReturnType<typeof nodeRegistryAbi, 'hasTag'>>
  activeOperators(): Promise<ReadContractReturnType<typeof nodeRegistryAbi, 'activeOperators'>>
}

export interface KeyRegistryReaders {
  getKeySlot(id: `0x${string}`): Promise<ReadContractReturnType<typeof keyRegistryAbi, 'getKeySlot'>>
  assignedNodes(id: `0x${string}`): Promise<ReadContractReturnType<typeof keyRegistryAbi, 'assignedNodes'>>
  requiresCommitReveal(): Promise<ReadContractReturnType<typeof keyRegistryAbi, 'requireCommitReveal'>>
  verifierPolicy(id: `0x${string}`): Promise<ReadContractReturnType<typeof keyRegistryAbi, 'verifierPolicy'>>
}

export interface SettlementReaders {
  balanceOf(slot: `0x${string}`): Promise<ReadContractReturnType<typeof settlementAbi, 'balanceOf'>>
  lastNonce(slot: `0x${string}`): Promise<ReadContractReturnType<typeof settlementAbi, 'lastNonce'>>
  revenueSplit(): Promise<ReadContractReturnType<typeof settlementAbi, 'revenueSplit'>>
  totalHeld(): Promise<ReadContractReturnType<typeof settlementAbi, 'totalHeld'>>
}

export interface TokenReaders {
  totalSupply(): Promise<ReadContractReturnType<typeof tasraTokenAbi, 'totalSupply'>>
  balanceOf(a: Address): Promise<ReadContractReturnType<typeof tasraTokenAbi, 'balanceOf'>>
  symbol(): Promise<ReadContractReturnType<typeof tasraTokenAbi, 'symbol'>>
  decimals(): Promise<ReadContractReturnType<typeof tasraTokenAbi, 'decimals'>>
}

export interface BondingCurveReaders {
  spotPrice(): Promise<ReadContractReturnType<typeof bondingCurveAbi, 'spotPrice'>>
  weightedAvgPrice365d(): Promise<ReadContractReturnType<typeof bondingCurveAbi, 'weightedAvgPrice365d'>>
  soldTokens(): Promise<ReadContractReturnType<typeof bondingCurveAbi, 'soldTokens'>>
  reserve(): Promise<ReadContractReturnType<typeof bondingCurveAbi, 'reserve'>>
}

export interface TreasuryReaders {
  balance(): Promise<ReadContractReturnType<typeof treasuryAbi, 'balance'>>
}

export interface BeaconReaders {
  seed(): Promise<ReadContractReturnType<typeof thresholdRandomBeaconAbi, 'seed'>>
  epoch(): Promise<ReadContractReturnType<typeof thresholdRandomBeaconAbi, 'epoch'>>
  seedAt(epoch: bigint): Promise<ReadContractReturnType<typeof thresholdRandomBeaconAbi, 'seedAt'>>
  lastUpdate(): Promise<ReadContractReturnType<typeof thresholdRandomBeaconAbi, 'lastUpdate'>>
  mpk(): Promise<ReadContractReturnType<typeof thresholdRandomBeaconAbi, 'mpk'>>
}

export interface VerifierSetReaders {
  snapshotAt(epoch: bigint): Promise<ReadContractReturnType<typeof verifierSetRegistryAbi, 'snapshotAt'>>
}

/** Readers for one vesting tranche. `address` is the de-duplication key. */
export interface VaultReaders {
  address(): Address
  released(): Promise<ReadContractReturnType<typeof tasraVestingVaultAbi, 'released'>>
  remaining(): Promise<ReadContractReturnType<typeof tasraVestingVaultAbi, 'remaining'>>
  totalLocked(): Promise<ReadContractReturnType<typeof tasraVestingVaultAbi, 'totalLocked'>>
  startTime(): Promise<ReadContractReturnType<typeof tasraVestingVaultAbi, 'startTime'>>
  cliffDuration(): Promise<ReadContractReturnType<typeof tasraVestingVaultAbi, 'cliffDuration'>>
  linearDuration(): Promise<ReadContractReturnType<typeof tasraVestingVaultAbi, 'linearDuration'>>
  unlockedAt(ts: bigint): Promise<ReadContractReturnType<typeof tasraVestingVaultAbi, 'unlockedAt'>>
  beneficiary(): Promise<ReadContractReturnType<typeof tasraVestingVaultAbi, 'beneficiary'>>
}

/** Typed view-function readers, grouped by contract. */
export interface TasraChainReaders {
  serviceRegistry: ServiceRegistryReaders
  nodeRegistry: NodeRegistryReaders
  keyRegistry: KeyRegistryReaders
  settlement: SettlementReaders
  token: TokenReaders
  bondingCurve: BondingCurveReaders
  treasury: TreasuryReaders
  vault(tranche: VaultTranche): VaultReaders
  beacon: BeaconReaders
  verifierSet: VerifierSetReaders
}

/** A read client for a deployment: a configured viem client, log helpers and typed readers. */
export interface TasraChainClient {
  /**
   * The configured viem public client. No wallet, no signing.
   *
   * ⚠ NOT multicall-batched: batching is applied explicitly in {@link readMany}, so a
   * chain without Multicall3 keeps working. Firing many reads concurrently through this
   * client costs one request each — go through `readMany` for a per-item fan-out.
   */
  client: PublicClient
  /** The deployment's resolved contract addresses. */
  addresses: AddressBook
  deployedContracts(): ContractName[]
  logSources(contracts?: ContractName[]): Array<{address: Address; contract: ContractName}>
  /** Read one view function across many argument lists. Batched via Multicall3 when
   *  available; a failing item is `null` unless `allowFailure: false`. */
  readMany<T>(
    contract: ContractName,
    functionName: string,
    argsList: readonly unknown[][],
    opts?: ReadManyOpts & {allowFailure?: true},
  ): Promise<Array<T | null>>
  readMany<T>(
    contract: ContractName,
    functionName: string,
    argsList: readonly unknown[][],
    opts: ReadManyOpts & {allowFailure: false},
  ): Promise<T[]>
  /**
   * The Multicall3 address `readMany` will batch through, or `null` when it will read
   * items individually. Resolved once per client and cached; exposed so a caller can
   * SEE which mode it is in rather than inferring it from request counts.
   */
  multicallAddress(): Promise<Address | null>
  getBlockNumber(): Promise<bigint>
  getLogsWindowed(opts: GetLogsWindowedOpts): Promise<DecodedEvent[]>
  getBlockTimestamps(blockNumbers: Iterable<bigint>): Promise<Map<string, number>>
  read<C extends ContractName>(contract: C, functionName: string, args?: readonly unknown[]): Promise<unknown>
  readers: TasraChainReaders
}

/**
 * viem-based **read** client for a Tasra Network deployment: a configured
 * `PublicClient`, windowed log fetching + decoding, block-timestamp lookups, and
 * typed view-function readers for the registry entities.
 *
 * Read-only by construction — no wallet, no signing. For on-chain writes (slot
 * creation, registration) use `createTasraWriteClient`.
 *
 * This is a **dependency of** the slot-driven clients rather than an alternative to
 * them: both {@link createTasraSlotClient} and {@link createCommitteeSlotClient}
 * take one of these as their `chain` field. Build it first.
 *
 * @param cfg `rpcUrl` + a resolved {@link AddressBook}. `chainId` defaults to
 *   `DEFAULT_CHAIN_ID` and the RPC is never consulted for it, so set it explicitly
 *   for any deployment that is not the local dev chain.
 * @returns a read client exposing `publicClient`, `readers`, log helpers, and the
 *   deployment's address book
 *
 * @example
 * ```ts
 * const chain = createTasraChainClient({
 *   rpcUrl: 'http://127.0.0.1:8545',
 *   addresses: addressBookFromEnv(process.env),
 * })
 * const kk = createTasraSlotClient({chain, identity: 'did:example:alice'})
 * ```
 */
export function createTasraChainClient(cfg: ChainClientConfig): TasraChainClient {
  const chain = defineChain({
    id: cfg.chainId ?? DEFAULT_CHAIN_ID,
    name: 'keykeeper',
    nativeCurrency: {name: 'Ether', symbol: 'ETH', decimals: 18},
    rpcUrls: {default: {http: [cfg.rpcUrl]}},
  })
  // ⚠ No `batch: {multicall}` here, deliberately. viem's client-level batching is
  // driven by the CHAIN definition naming a multicall3 address, and it does not
  // degrade: where Multicall3 is absent the aggregate call returns empty data and
  // EVERY read in the batch fails to decode, which a bare local chain would hit on
  // its first read. Worse, once it is on there is no way back — an individual-read
  // fallback goes through the same broken batch.
  //
  // So batching is applied explicitly in `readMany`, gated on a one-off `eth_getCode`
  // probe and with a fallback that can actually run. See `multicallAddress`.
  const client: PublicClient = createPublicClient({
    chain,
    transport: http(cfg.rpcUrl),
  })
  const addresses = cfg.addresses
  const defaultWindow = cfg.logWindow ?? 2000

  /**
   * Resolved ONCE per client: the Multicall3 address to batch through, or null.
   *
   * Cached as the promise, not the value, so concurrent first calls share one probe
   * instead of racing several. Latched to null if a batch ever fails at the aggregate
   * level (a wrong address, or something at that address that is not Multicall3), so one
   * bad batch does not cost a failed attempt on every later call.
   */
  /**
   * Set once a batch has returned at least one SUCCESSFUL item, i.e. the thing at the
   * batch address has demonstrably behaved like Multicall3.
   *
   * ⚠ Needed because `eth_getCode` cannot tell Multicall3 from any other contract at that
   * address, and viem does NOT throw when the aggregate is answered by something else —
   * it reports every item as failed. All-failed is therefore ambiguous: either the batch
   * mechanism is broken, or the items genuinely are unreadable. Until one success has been
   * seen, that case is resolved by reading the items individually and comparing, rather
   * than by guessing (guessing wrong means silently returning nulls for readable state).
   */
  let batchProven = false
  let multicallProbe: Promise<Address | null> | undefined
  function multicallAddress(): Promise<Address | null> {
    return (multicallProbe ??= (async () => {
      if (cfg.multicall3 === false) return null
      const at = cfg.multicall3 ?? MULTICALL3_ADDRESS
      try {
        const code = await client.getCode({address: at})
        // An address with no contract answers '0x' (or undefined), which is the bare-chain
        // case. Probing beats assuming: assuming is what breaks every read.
        return code && code !== '0x' ? at : null
      } catch {
        // A probe that cannot complete must not decide the reads are impossible.
        return null
      }
    })())
  }
  const disableMulticall = (): void => {
    multicallProbe = Promise.resolve(null)
  }

  /** Which of the known contracts have an address in this deployment. */
  function deployedContracts(): ContractName[] {
    return (Object.keys(CONTRACT_ABIS) as ContractName[]).filter(
      c => !!addresses[c],
    )
  }

  /**
   * Every address whose logs this deployment can decode, paired with the ABI to
   * decode them against.
   *
   * NOT the same as {@link deployedContracts}: that maps one canonical contract
   * NAME to one address, but the vesting vaults are one ABI over up to three
   * TRANCHE addresses (`TasraVestingVault_investor`, `_team`, `_community`),
   * which are deliberately not contract names. Scanning by name alone therefore
   * misses every vault log — the tranche keys are invisible to it — so an
   * indexer must enumerate log sources through here instead.
   *
   * Addresses are de-duplicated: a single-vault deployment that only sets the
   * bare `TasraVestingVault` key must be scanned once, not once per tranche.
   */
  function logSources(
    contracts?: ContractName[],
  ): Array<{address: Address; contract: ContractName}> {
    const want = contracts ?? deployedContracts()
    const out: Array<{address: Address; contract: ContractName}> = []
    const seen = new Set<string>()
    const push = (address: Address, contract: ContractName): void => {
      const k = address.toLowerCase()
      if (seen.has(k)) return
      seen.add(k)
      out.push({address, contract})
    }
    for (const c of want) {
      const a = addresses[c]
      if (a) push(a, c)
    }
    if (!contracts || contracts.includes('TasraVestingVault')) {
      for (const t of VAULT_TRANCHES) {
        const a = addresses[vaultKey(t)]
        if (a) push(a, 'TasraVestingVault')
      }
    }
    return out
  }

  async function getBlockNumber(): Promise<bigint> {
    return client.getBlockNumber()
  }

  /**
   * Fetch + decode logs for the given contracts over [fromBlock, toBlock] in
   * windows. Logs are grouped by emitting address and decoded with the right
   * contract ABI (so shared signatures like OwnerChanged are attributed
   * correctly).
   */
  async function getLogsWindowed(
    opts: GetLogsWindowedOpts,
  ): Promise<DecodedEvent[]> {
    const sources = logSources(opts.contracts)
    const addrToContract = new Map<string, ContractName>()
    const addressList: Address[] = []
    for (const {address, contract} of sources) {
      addrToContract.set(address.toLowerCase(), contract)
      addressList.push(address)
    }
    if (addressList.length === 0) return []

    const windowSize = BigInt(opts.windowSize ?? defaultWindow)
    const all: DecodedEvent[] = []
    for (let from = opts.fromBlock; from <= opts.toBlock; from += windowSize) {
      const to =
        from + windowSize - 1n > opts.toBlock
          ? opts.toBlock
          : from + windowSize - 1n
      const logs = (await client.getLogs({
        address: addressList,
        fromBlock: from,
        toBlock: to,
      })) as Log[]
      const byAddr = new Map<string, Log[]>()
      for (const log of logs) {
        const k = (log.address ?? '').toLowerCase()
        const arr = byAddr.get(k)
        if (arr) arr.push(log)
        else byAddr.set(k, [log])
      }
      const windowEvents: DecodedEvent[] = []
      for (const [addr, ls] of byAddr) {
        const c = addrToContract.get(addr)
        if (!c) continue
        // Appended one by one: spreading a large window into push() overflows the stack.
        for (const event of decodeContractLogs(c, addr as Address, ls)) windowEvents.push(event)
      }
      for (const event of windowEvents) all.push(event)
      opts.onWindow?.(to, windowEvents)
    }
    return all
  }

  /** Resolve block timestamps (seconds) for a set of block numbers. */
  async function getBlockTimestamps(
    blockNumbers: Iterable<bigint>,
  ): Promise<Map<string, number>> {
    const unique = [...new Set([...blockNumbers].map(b => b.toString()))]
    const out = new Map<string, number>()
    await Promise.all(
      unique.map(async n => {
        const block = await client.getBlock({blockNumber: BigInt(n)})
        out.set(n, Number(block.timestamp))
      }),
    )
    return out
  }

  /** Generic typed-ish read against a known contract. */
  async function read<C extends ContractName>(
    contract: C,
    functionName: string,
    args: readonly unknown[] = [],
  ): Promise<unknown> {
    return client.readContract({
      address: requireAddress(addresses, contract),
      abi: CONTRACT_ABIS[contract] as readonly unknown[],
      functionName,
      args: args as unknown[],
    })
  }

  // ── Typed domain readers (precise return types via specific ABIs) ────────
  const nodeRegistry = {
    nodeOf: (op: Address) =>
      client.readContract({
        address: requireAddress(addresses, 'NodeRegistry'),
        abi: nodeRegistryAbi,
        functionName: 'nodeOf',
        args: [op],
      }),
    isActive: (op: Address) =>
      client.readContract({
        address: requireAddress(addresses, 'NodeRegistry'),
        abi: nodeRegistryAbi,
        functionName: 'isActive',
        args: [op],
      }),
    operatorCount: () =>
      client.readContract({
        address: requireAddress(addresses, 'NodeRegistry'),
        abi: nodeRegistryAbi,
        functionName: 'operatorCount',
      }),
    operatorAt: (i: bigint) =>
      client.readContract({
        address: requireAddress(addresses, 'NodeRegistry'),
        abi: nodeRegistryAbi,
        functionName: 'operatorAt',
        args: [i],
      }),
    activeCount: () =>
      client.readContract({
        address: requireAddress(addresses, 'NodeRegistry'),
        abi: nodeRegistryAbi,
        functionName: 'activeCount',
      }),
    attributesOf: (op: Address) =>
      client.readContract({
        address: requireAddress(addresses, 'NodeRegistry'),
        abi: nodeRegistryAbi,
        functionName: 'attributesOf',
        args: [op],
      }),
    rewardBalanceOf: (op: Address) =>
      client.readContract({
        address: requireAddress(addresses, 'NodeRegistry'),
        abi: nodeRegistryAbi,
        functionName: 'rewardBalanceOf',
        args: [op],
      }),
    requiredStake: () =>
      client.readContract({
        address: requireAddress(addresses, 'NodeRegistry'),
        abi: nodeRegistryAbi,
        functionName: 'requiredStake',
      }),
    // Phase-2 Option B: the operator's stable, immutable global FROST identifier.
    operatorIdOf: (op: Address) =>
      client.readContract({
        address: requireAddress(addresses, 'NodeRegistry'),
        abi: nodeRegistryAbi,
        functionName: 'operatorIdOf',
        args: [op],
      }),
    // Whether an operator carries a given attribute tag (e.g. the keeper tag the
    // committee draw selects by).
    hasTag: (op: Address, tag: `0x${string}`) =>
      client.readContract({
        address: requireAddress(addresses, 'NodeRegistry'),
        abi: nodeRegistryAbi,
        functionName: 'hasTag',
        args: [op, tag],
      }),
    // The full active operator set in one call (avoids operatorCount+operatorAt fan-out).
    activeOperators: () =>
      client.readContract({
        address: requireAddress(addresses, 'NodeRegistry'),
        abi: nodeRegistryAbi,
        functionName: 'activeOperators',
      }),
  }

  const keyRegistry = {
    getKeySlot: (id: `0x${string}`) =>
      client.readContract({
        address: requireAddress(addresses, 'KeyRegistry'),
        abi: keyRegistryAbi,
        functionName: 'getKeySlot',
        args: [id],
      }),
    assignedNodes: (id: `0x${string}`) =>
      client.readContract({
        address: requireAddress(addresses, 'KeyRegistry'),
        abi: keyRegistryAbi,
        functionName: 'assignedNodes',
        args: [id],
      }),
    /**
     * Does this deployment refuse one-shot slot creation? A registry with `requireCommitReveal` set
     * — every production genesis has it — reverts `createKeySlotFiltered*` with
     * `CommitRevealRequired()` and accepts only the commit-then-reveal pair. Ask before creating: the
     * answer decides between `createSlot` and `createSlotCommitReveal`, and costs one read.
     */
    requiresCommitReveal: () =>
      client.readContract({
        address: requireAddress(addresses, 'KeyRegistry'),
        abi: keyRegistryAbi,
        functionName: 'requireCommitReveal',
      }) as Promise<boolean>,
    // The slot's per-request verifier-committee policy → `[committee, quorum]`
    // (both `uint16`). `committee == 0` ⇒ the slot has no policy (committee path not wired);
    // fall back to the legacy JWT path. Needed by the committee-authorization flow.
    verifierPolicy: (id: `0x${string}`) =>
      client.readContract({
        address: requireAddress(addresses, 'KeyRegistry'),
        abi: keyRegistryAbi,
        functionName: 'verifierPolicy',
        args: [id],
      }) as Promise<readonly [number, number]>,
  }

  const settlement = {
    balanceOf: (slot: `0x${string}`) =>
      client.readContract({
        address: requireAddress(addresses, 'Settlement'),
        abi: settlementAbi,
        functionName: 'balanceOf',
        args: [slot],
      }),
    lastNonce: (slot: `0x${string}`) =>
      client.readContract({
        address: requireAddress(addresses, 'Settlement'),
        abi: settlementAbi,
        functionName: 'lastNonce',
        args: [slot],
      }),
    revenueSplit: () =>
      client.readContract({
        address: requireAddress(addresses, 'Settlement'),
        abi: settlementAbi,
        functionName: 'revenueSplit',
      }),
    totalHeld: () =>
      client.readContract({
        address: requireAddress(addresses, 'Settlement'),
        abi: settlementAbi,
        functionName: 'totalHeld',
      }),
  }

  const token = {
    totalSupply: () =>
      client.readContract({
        address: requireAddress(addresses, 'TasraToken'),
        abi: tasraTokenAbi,
        functionName: 'totalSupply',
      }),
    balanceOf: (a: Address) =>
      client.readContract({
        address: requireAddress(addresses, 'TasraToken'),
        abi: tasraTokenAbi,
        functionName: 'balanceOf',
        args: [a],
      }),
    symbol: () =>
      client.readContract({
        address: requireAddress(addresses, 'TasraToken'),
        abi: tasraTokenAbi,
        functionName: 'symbol',
      }),
    decimals: () =>
      client.readContract({
        address: requireAddress(addresses, 'TasraToken'),
        abi: tasraTokenAbi,
        functionName: 'decimals',
      }),
  }

  const bondingCurve = {
    spotPrice: () =>
      client.readContract({
        address: requireAddress(addresses, 'BondingCurve'),
        abi: bondingCurveAbi,
        functionName: 'spotPrice',
      }),
    weightedAvgPrice365d: () =>
      client.readContract({
        address: requireAddress(addresses, 'BondingCurve'),
        abi: bondingCurveAbi,
        functionName: 'weightedAvgPrice365d',
      }),
    soldTokens: () =>
      client.readContract({
        address: requireAddress(addresses, 'BondingCurve'),
        abi: bondingCurveAbi,
        functionName: 'soldTokens',
      }),
    reserve: () =>
      client.readContract({
        address: requireAddress(addresses, 'BondingCurve'),
        abi: bondingCurveAbi,
        functionName: 'reserve',
      }),
  }

  const treasury = {
    balance: () =>
      client.readContract({
        address: requireAddress(addresses, 'Treasury'),
        abi: treasuryAbi,
        functionName: 'balance',
      }),
  }

  // The deploy creates one vesting vault per tranche, so the tranche is
  // explicit: there is no "the vault" to default to.
  //
  // ⚠ Two tranches can resolve to the SAME address when the book only carries
  // the bare `TasraVestingVault` key (see `requireVaultAddress`). Anything that
  // AGGREGATES across tranches must therefore de-duplicate on `address()` first,
  // or it reports a multiple of the real locked supply.
  /**
   * Read one view function across many argument lists — the registry fan-out, and the
   * only place in this client where the number of round trips is worth engineering.
   *
   * Where Multicall3 is deployed the whole list is one `eth_call` per chunk; where it is
   * not, the reads are issued CONCURRENTLY rather than in a loop, so they overlap
   * instead of queueing. Which mode is in use comes from a single cached
   * {@link multicallAddress} probe, never from an assumption about the chain.
   *
   * Why it matters: a 10k-operator registry is ~40,000 view calls, which as sequential
   * round trips is tens of minutes on any real RPC.
   *
   * A failing item is `null` in place — one unreadable operator must not blank the whole
   * set. Pass `allowFailure: false` where POSITION carries meaning (an ordered operator
   * set, whose indexes shift if one item is dropped); that rejects instead.
   */
  async function readMany<T>(
    contract: ContractName,
    functionName: string,
    argsList: readonly unknown[][],
    opts?: ReadManyOpts,
  ): Promise<Array<T | null>> {
    if (argsList.length === 0) return []
    const allowFailure = opts?.allowFailure ?? true
    // Resolved up front, and NOT swallowed: a missing address is a deployment mistake,
    // not an unreadable item, and it must not come back as a list of nulls.
    const address = requireAddress(addresses, contract)
    const abi = CONTRACT_ABIS[contract] as Abi

    /** The per-item path: one request each, concurrently. */
    const individually = async (): Promise<Array<T | null>> =>
      Promise.all(
        argsList.map(args =>
          client
            .readContract({address, abi, functionName, args: args as readonly unknown[]})
            .then(v => v as T)
            .catch((error: unknown) => {
              if (!allowFailure) throw error
              return null
            }),
        ),
      )

    // One item is one call either way, so skip the probe rather than pay for it.
    const at = argsList.length > 1 ? await multicallAddress() : null
    if (!at) return individually()

    // `allowFailure` at the viem layer is always true, whatever the caller asked for: a
    // per-item revert must come back as a result we can inspect rather than as a thrown
    // batch. Our own `allowFailure` then decides what that means.
    //
    // ⚠ There is no try/catch here on purpose. Under `allowFailure: true` viem does not
    // throw when the aggregate call itself is rejected — out of gas, payload refused,
    // nothing at the address — it reports every ITEM as failed. So a catch block would be
    // a guard that never fires, and the all-failed branch below is the one real recovery
    // path. That behaviour is pinned by test/chain.read-client.ts, which is what would
    // fail loudly if a viem upgrade ever changed it.
    const results = await client.multicall({
      contracts: argsList.map(args => ({address, abi, functionName, args: args as readonly unknown[]})),
      allowFailure: true,
      multicallAddress: at,
      batchSize: MULTICALL_BATCH_BYTES,
    })

    if (results.some(r => r.status === 'success')) {
      batchProven = true
    } else if (!batchProven) {
      // Everything failed on the first batch this client ever sent, which is ambiguous:
      // either the batch mechanism is broken, or the items genuinely are unreadable.
      // Settle it by reading them individually — once per client, only in this case. If
      // they read fine the batch is at fault and must be abandoned; if they fail too, the
      // batch was telling the truth and batching stays on.
      const direct = await individually()
      if (direct.some(v => v !== null)) {
        disableMulticall()
        return direct
      }
      batchProven = true
      return direct
    }

    if (!allowFailure) {
      const failed = results.findIndex(r => r.status !== 'success')
      if (failed >= 0) {
        throw new Error(
          `readMany(${contract}.${functionName}): item ${failed} of ${argsList.length} failed and ` +
            'allowFailure is false, so the result would misreport every later index',
          {cause: (results[failed] as {error?: unknown}).error},
        )
      }
    }
    return results.map(r => (r.status === 'success' ? (r.result as T) : null))
  }

  const vault = (tranche: VaultTranche) => {
    const at = () => requireVaultAddress(addresses, tranche)
    const get = (functionName: 'released' | 'remaining' | 'totalLocked') => () =>
      client.readContract({address: at(), abi: tasraVestingVaultAbi, functionName})
    const getU64 = (functionName: 'startTime' | 'cliffDuration' | 'linearDuration') => () =>
      client.readContract({address: at(), abi: tasraVestingVaultAbi, functionName})
    return {
      /** Which address this tranche resolves to — the de-duplication key. */
      address: at,
      released: get('released'),
      remaining: get('remaining'),
      totalLocked: get('totalLocked'),
      startTime: getU64('startTime'),
      cliffDuration: getU64('cliffDuration'),
      linearDuration: getU64('linearDuration'),
      /** Cumulative amount unlocked as of `ts`: 0 during the cliff, then linear. */
      unlockedAt: (ts: bigint) =>
        client.readContract({
          address: at(),
          abi: tasraVestingVaultAbi,
          functionName: 'unlockedAt',
          args: [ts],
        }),
      beneficiary: () =>
        client.readContract({
          address: at(),
          abi: tasraVestingVaultAbi,
          functionName: 'beneficiary',
        }),
    }
  }

  const beacon = {
    seed: () =>
      client.readContract({
        address: requireAddress(addresses, 'ThresholdRandomBeacon'),
        abi: thresholdRandomBeaconAbi,
        functionName: 'seed',
      }),
    epoch: () =>
      client.readContract({
        address: requireAddress(addresses, 'ThresholdRandomBeacon'),
        abi: thresholdRandomBeaconAbi,
        functionName: 'epoch',
      }),
    /** The seed of a PAST epoch — what a committee draw pinned to `latest - 1` needs. */
    seedAt: (epoch: bigint) =>
      client.readContract({
        address: requireAddress(addresses, 'ThresholdRandomBeacon'),
        abi: thresholdRandomBeaconAbi,
        functionName: 'seedAt',
        args: [epoch],
      }),
    lastUpdate: () =>
      client.readContract({
        address: requireAddress(addresses, 'ThresholdRandomBeacon'),
        abi: thresholdRandomBeaconAbi,
        functionName: 'lastUpdate',
      }),
    mpk: () =>
      client.readContract({
        address: requireAddress(addresses, 'ThresholdRandomBeacon'),
        abi: thresholdRandomBeaconAbi,
        functionName: 'mpk',
      }),
  }

  // W1 verifier-set snapshot — `size` is the committee draw's
  // registrySize, `root` the Merkle root for trustless verifier proofs.
  const verifierSet = {
    snapshotAt: (epoch: bigint) =>
      client.readContract({
        address: requireAddress(addresses, 'VerifierSetRegistry'),
        abi: verifierSetRegistryAbi,
        functionName: 'snapshotAt',
        args: [epoch],
      }),
  }

  return {
    client,
    addresses,
    deployedContracts,
    logSources,
    readMany: readMany as TasraChainClient['readMany'],
    multicallAddress,
    getBlockNumber,
    getLogsWindowed,
    getBlockTimestamps,
    read,
    readers: {
      serviceRegistry: createServiceRegistryReaders(client, () => requireAddress(addresses, 'ServiceRegistry')),
      nodeRegistry,
      keyRegistry,
      settlement,
      token,
      bondingCurve,
      treasury,
      vault,
      beacon,
      verifierSet,
    },
  }
}
