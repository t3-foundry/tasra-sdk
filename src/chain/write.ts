import {networkNameForChain, resolveNetworkProfile, assertEurcFaucetAllowed} from './networks.js'
import {SlotCommitmentExpiredError} from './commitmentRecovery.js'
import {requestSlotSeed, type SlotSeed} from './slotSeed.js'
// Client-side ON-CHAIN WRITE path: the client is a sovereign actor with its own
// EVM account that signs its own transactions — no relayer/provisioner.
//
// Slot creation is permissionless (KeyRegistry.createKeySlot* has no owner gate;
// the creator is just msg.sender) and fee-less (only gas), so a fresh
// funded account can create and own a slot. This client signs:
//   - createKeySlot(Filtered) — create + own a slot (committee drawn on-chain,
//     nodes auto-DKG),
//   - TSRA approve + Settlement.fund — prepay the slot's metered usage,
// and exposes plain ETH/TSRA transfers (so a funded key can also back a faucet).
//
// Lives in the `tasra-sdk/chain` subpath (viem). Browser + Node (uses
// globalThis.crypto for slot/salt randomness; no Node-only APIs).

import {
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  concat,
  encodeFunctionData,
  keccak256,
  toHex,
  type Account,
  type Address,
  type Chain,
  type Hex,
  type PublicClient,
  type Transport,
  type WalletClient,
} from 'viem'
import {generatePrivateKey, privateKeyToAccount} from 'viem/accounts'
import {createTasraChainClient} from './client.js'
import {createRegisteredRelaySubmitter, type RegisteredRelayConfig, type RelayReceipt, type RelayAttempt} from './registeredRelay.js'
import {describeRevert} from './revertReason.js'
export type {RelayReceipt} from './registeredRelay.js'
import {canonicalize, isOid4vpRule} from '../auth/oid4vp.js'
import {TasraError} from '../errors.js'
import {keyRegistryAbi} from './abis/keyRegistry.js'
import {settlementAbi} from './abis/settlement.js'
import {tasraTokenAbi} from './abis/tasraToken.js'
import {thresholdRandomBeaconAbi} from './abis/thresholdRandomBeacon.js'
import {bondingCurveAbi} from './abis/bondingCurve.js'
import {mockEurcAbi} from './abis/mockEurc.js'
import {treasuryAbi} from './abis/treasury.js'
import {tasraVestingVaultAbi} from './abis/tasraVestingVault.js'
import {
  DEFAULT_CHAIN_ID,
  requireAddress,
  requireVaultAddress,
  type AddressBook,
  type VaultTranche,
} from './deployments.js'

/**
 * The slot's key type, mirroring `KeyRegistry.Mode` on-chain:
 * `frost` Ed25519 threshold signatures, `bls` BLS12-381 encryption/decryption,
 * `tecdsa` secp256k1 threshold ECDSA (an EVM account — what `signEoaDigest` needs),
 * `bls-bn254`, and `tecdsa-p256` (ES256). A deployment need not run keepers for
 * every mode; creating a slot the fleet cannot key leaves it without a group key.
 */
export type SlotMode = 'frost' | 'bls' | 'tecdsa' | 'bls-bn254' | 'tecdsa-p256'

/** `KeyRegistry.Mode` enum order. */
const SLOT_MODES: readonly SlotMode[] = ['frost', 'bls', 'tecdsa', 'bls-bn254', 'tecdsa-p256']
function modeIndex(mode: SlotMode): number {
  const i = SLOT_MODES.indexOf(mode)
  if (i < 0) throw new TasraError(`createSlot: unknown mode ${JSON.stringify(mode)} (expected ${SLOT_MODES.join(' | ')})`)
  return i
}

/**
 * How a holder authorises against this slot's rule, mirroring `KeyRegistry.AuthType`.
 * Pinned at creation and recorded on the slot; `unspecified` (the default) declares
 * nothing, which is what every slot created before the field existed reads as.
 *
 * ⚠ It is deliberately NOT part of `computeCommitment`, so a commit-reveal creation
 * may name an auth type the commit never covered — the commitment binds the
 * parameters that decide the committee, not this label.
 */
export type SlotAuthType = 'unspecified' | 'oid4vp' | 'oauth'

/** `KeyRegistry.AuthType` enum order — APPEND-ONLY on-chain, so never reorder. */
const SLOT_AUTH_TYPES: readonly SlotAuthType[] = ['unspecified', 'oid4vp', 'oauth']
function authTypeIndex(auth: SlotAuthType | undefined): number {
  if (auth === undefined) return 0
  const i = SLOT_AUTH_TYPES.indexOf(auth)
  if (i < 0) {
    throw new TasraError(
      `createSlot: unknown authType ${JSON.stringify(auth)} (expected ${SLOT_AUTH_TYPES.join(' | ')})`,
    )
  }
  return i
}

/**
 * platform-sponsored gas: route SENDER-BOUND calls (slot creation, verifier policy,
 * settlement funding, curve buys) through the pinned ERC-2771 forwarder via the platform
 * relayer. The client signs an EIP-712 forward request; the relayer applies its policy to the
 * inner call, pays the gas and submits `forwarder.execute` from its own key — the target sees
 * the SIGNER as `_msgSender()`, the relayer authorises nothing. ERC-20 `approve` is not
 * 2771-aware and always comes from the local key.
 */
export type RelayConfig = RegisteredRelayConfig

interface WriteClientConfigBase {
  rpcUrl: string
  addresses: AddressBook
  /** When set, sender-bound calls are gas-sponsored through the platform relayer. */
  relay?: RelayConfig
  /**
   * Chain id. It goes into the EIP-155 signature, so a wrong value makes every
   * write rejected by the node. Defaults to DEFAULT_CHAIN_ID (the local demo
   * fleet) ONLY when `rpcUrl` is a loopback address; against any other RPC it
   * is required — or supply a chain-bound `wallet`, whose chain id is used.
   */
  chainId?: number
}

/** Sovereign-key variant: the SDK owns the account and signs with `privateKey`. */
export interface WriteClientKeyConfig extends WriteClientConfigBase {
  /** The CLIENT's own 0x-prefixed 32-byte private key (it signs + pays gas). */
  privateKey: Hex
  wallet?: undefined
}

/**
 * BYO-signer variant: the caller supplies an account-bound viem `WalletClient`,
 * so the SDK never sees a private key. This is the browser-wallet path —
 * MetaMask via wagmi's `getWalletClient()`, a Safe App connector, a hardware
 * wallet, or any `custom()` transport.
 *
 * ⚠ The supplied client MUST be bound to both an account and a chain (wagmi's
 * `getWalletClient()` returns one that is). The SDK calls `writeContract`
 * without passing `chain`/`account`, so an unbound client makes viem throw.
 *
 * ⚠ `rpcUrl` is still required: reads and receipt-waiting go through the SDK's
 * own PublicClient, never through the wallet's transport.
 */
export interface WriteClientWalletConfig extends WriteClientConfigBase {
  wallet: WalletClient<Transport, Chain, Account>
  privateKey?: undefined
}

export type WriteClientConfig = WriteClientKeyConfig | WriteClientWalletConfig

/**
 * Options for {@link TasraWriteClient.createSlotCommitReveal}.
 *
 * The ADR-0075 fields are all opt-OUT or overrides: the default is to try the accountant set for
 * a per-commitment draw seed, and to fall back to the beacon-epoch wait when it cannot be had.
 */
export interface CommitRevealOptions {
  /** Cap on the beacon-epoch wait, when the ADR-0075 fast path is unavailable. */
  maxWaitMs?: number
  /** Progress during that wait. Not called on the seeded path — there is no wait to report. */
  onEpoch?: (cur: number, target: number) => void
  /**
   * `false` skips the ADR-0075 seed request and goes straight to the epoch wait.
   *
   * ⚠ Turn this off only to exercise the ADR-0030 path deliberately (a test, or a deployment
   * whose accountants are known down). It is not a security control: both paths draw from a seed
   * that post-dates the commitment, and neither lets the creator choose.
   */
  slotSeed?: boolean
  /** Accountant base URLs for the seed request. Resolved from `NodeRegistry` when omitted. */
  accountantUrls?: string[]
  /** Per-accountant HTTP timeout for the seed request. */
  slotSeedTimeoutMs?: number
  /** The seed that was obtained, or `null` when the epoch wait is being used instead. */
  onSeed?: (seed: SlotSeed | null) => void
}

export interface CreateSlotArgs {
  dcqlRule: string
  /** rule salt; minted when omitted. NOT `salt` (committee selection). */
  ruleSalt?: Hex
  k: number
  n: number
  mode: SlotMode
  /**
   * `KeyRegistry.AuthType` for this slot — how a holder authorises against the rule.
   * Defaults to `'unspecified'` (ordinal 0), which declares nothing and is what every
   * slot predating the field reads as. Set it when the rule is an OID4VP-DCQL query
   * (`'oid4vp'`) or an OAuth/OIDC token rule (`'oauth'`).
   */
  authType?: SlotAuthType
  /** Committee-draw filter tags; default `["keykeeper"]`. */
  tags?: string[]
  /** Override the (otherwise random) slot id / salt. */
  slotId?: Hex
  salt?: Hex
  /**
   * amendment authority, pinned in the SAME transaction that creates the
   * slot. Omit for an immutable rule, which is the default.
   *
   * ⚠ Prefer this to calling {@link TasraWriteClient.setRulePolicy} afterwards.
   * That is a second transaction, and it CANNOT be won from a wallet that asks a
   * human to approve one — the keepers start their DKG the moment creation lands,
   * and the pin is refused once a key exists. See the note on `setRulePolicy`.
   */
  rulePolicy?: RulePolicyArgs
  /**
   * client-sovereign key custody: allow RAW shard export for this slot
   * (POST /v1/shards/key returns each keeper's secret share; k of them reconstruct the
   * master secret key). DANGEROUS — a holder who exports keeps the key permanently, so
   * revocation no longer locks them out. Off by default. Use ONLY for personal-vault /
   * key-recovery slots, never a group or credential-gated slot. Immutable at birth; cannot
   * be combined with rulePolicy (no single entry point for both).
   */
  exportable?: boolean
}

/** Who may amend a slot's DCQL rule, and how slowly. */
export interface RulePolicyArgs {
  admin: Address
  /** May veto or endorse. Omitted means none — which then requires a real timelock. */
  guardian?: Address
  timelockSecs: number
}

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as Address

/**
 * salted DCQL rule commitment: `keccak256(DOMAIN ‖ salt ‖ rule)`.
 *
 * ⚠ Must byte-for-byte match the reference rule-commitment function — the keeper
 * re-derives this to verify-fill the rule and the verifier re-derives it to
 * authenticate a fetched one, so a mismatch here means every keeper refuses the
 * rule and the slot stays fail-closed. Cross-checked vector: salt 0x11*32 over
 * "EmployeeOf:dept=Engineering" =
 * 0x176e8b17e8e6b587e649754fe682f7ad6eb12f97461a295d2cfa9c92c287dfde.
 *
 * ⚠ NOT the `salt` passed to createKeySlot — that is the committee-selection
 * salt and never touches the rule.
 */

/**
 * Wait for a transaction AND require that it actually succeeded.
 *
 * ⚠ viem's `waitForTransactionReceipt` RESOLVES for a reverted transaction — it returns a
 * receipt whose `status` is `'reverted'` rather than throwing. Every write in this file
 * awaited it and checked nothing, so a revert was indistinguishable from success and the
 * caller carried on with a value the chain had rejected.
 *
 * That is not theoretical. `createSlotCommitReveal` returned a `slotId` for a slot whose
 * `revealKeySlot` had reverted (`InsufficientFilteredPool`, when a keeper was transiently
 * ineligible), and the caller then waited 90 seconds for a slot that had never existed,
 * reporting `committee=0` — a mystery with no error anywhere. The failure was silent for
 * exactly as long as nobody looked at `receipt.status`.
 */
async function confirmed(
  pub: {waitForTransactionReceipt: (a: {hash: Hex}) => Promise<{status: 'success' | 'reverted'}>},
  hash: Hex,
  what: string,
): Promise<void> {
  const receipt = await pub.waitForTransactionReceipt({hash})
  if (receipt.status !== 'success') {
    throw new Error(`${what} REVERTED on chain (tx ${hash}) — the call did not take effect`)
  }
}

/**
 * The salted rule commitment, `keccak256(DOMAIN ‖ salt ‖ body)`, with the SAME
 * dispatch as the reference implementation's the reference rule-commitment function — the one every keeper runs when a
 * rule is provisioned and every verifier runs when it hash-checks a fetched rule:
 *
 *  - an OID4VP-DCQL rule (`isOid4vpRule`) commits to its RFC 8785 (JCS) canonical form. It
 *    gets parsed and re-serialised when embedded in a signed OID4VP request object, and any
 *    JSON library may reorder keys or restyle whitespace, so raw bytes would not survive;
 *  - any other rule — the keeper's bearer-JWT kk-DCQL grammar, the universal grant `"any"` —
 *    commits to its RAW bytes, unchanged. Canonicalising those here silently disagreed with
 *    the keeper, which refused the rule at provisioning as "dcql_rule does not match the
 *    slot's on-chain commitment" — an error that reads like a typo in a rule that is fine.
 */
export function ruleCommitment(ruleSalt: Hex, dcqlRule: string): Hex {
  const body = isOid4vpRule(dcqlRule) ? canonicalize(dcqlRule) : dcqlRule
  return keccak256(concat([toHex('keykeeper/rule-commitment/v1'), ruleSalt, toHex(body)]))
}

/**
 * Verify that a disclosed rule matches its on-chain commitment (defence
 * against a lying verifier inflating the rule). Returns `true` when the commitment
 * matches, `false` otherwise — never throws on a mismatch.
 */
export function verifyRuleCommitment(
  dcqlRule: string,
  ruleSalt: Hex,
  onChainRuleCommitment: Hex,
): boolean {
  try {
    return ruleCommitment(ruleSalt, dcqlRule) === onChainRuleCommitment
  } catch {
    return false
  }
}

/** Fresh 0x-prefixed 32-byte private key for a new sovereign client account. */
export function generateClientKey(): Hex {
  return generatePrivateKey()
}

/**
 * True for an RPC on this machine — the only place the demo fleet's chain id
 * may be assumed. Anything else is some other deployment, and guessing its
 * chain id produces EIP-155 signatures the node rejects, with no signal from
 * this package about why.
 */
function isLoopbackRpc(rpcUrl: string): boolean {
  try {
    const host = new URL(rpcUrl).hostname
    return (
      host === 'localhost' ||
      host.endsWith('.localhost') ||
      host === '127.0.0.1' ||
      host === '0.0.0.0' ||
      host === '[::1]' ||
      host === '::1'
    )
  } catch {
    return false
  }
}

function random32(): Hex {
  const b = new Uint8Array(32)
  ;(globalThis.crypto as Crypto).getRandomValues(b)
  return `0x${Array.from(b, x => x.toString(16).padStart(2, '0')).join('')}`
}

/**
 * A wallet-backed on-chain client. The returned object's `address` is the
 * sovereign identity.
 *
 * Two signer shapes, same surface (see {@link WriteClientConfig}):
 *   - `privateKey` — the SDK owns the account and signs locally (Node, tests,
 *     faucets, CI). Historic behaviour, unchanged.
 *   - `wallet` — the caller supplies an account-bound viem `WalletClient`, so
 *     the SDK never touches a private key. This is the browser-wallet path
 *     (MetaMask/wagmi, Safe App, hardware wallet).
 */
export function createTasraWriteClient(cfg: WriteClientConfig): TasraWriteClient {
  const chainId = cfg.chainId ?? cfg.wallet?.chain?.id
  if (chainId === undefined && !isLoopbackRpc(cfg.rpcUrl)) {
    throw new TasraError(
      `createTasraWriteClient: chainId is required for ${cfg.rpcUrl} — the default ` +
        `(DEFAULT_CHAIN_ID = ${DEFAULT_CHAIN_ID}) is the local demo fleet's chain and goes into ` +
        `the EIP-155 signature, so assuming it against another deployment produces writes the ` +
        `node rejects. Pass the deployment's chain id, or a chain-bound \`wallet\`.`,
    )
  }
  const chain = defineChain({
    id: chainId ?? DEFAULT_CHAIN_ID,
    name: 'keykeeper',
    nativeCurrency: {name: 'Ether', symbol: 'ETH', decimals: 18},
    rpcUrls: {default: {http: [cfg.rpcUrl]}},
  })
  // Reads and receipt-waiting always go through OUR PublicClient, never the
  // supplied wallet's transport — an injected provider is rate-limited, may be on
  // a different node, and can be unavailable while the user's tab is backgrounded.
  const pub = createPublicClient({chain, transport: http(cfg.rpcUrl)}) as PublicClient
  const addr = cfg.addresses
  const relay = cfg.relay
  let lastRelay: RelayReceipt | undefined
  let registeredRelay: ReturnType<typeof createRegisteredRelaySubmitter> | undefined
  async function relayForward(to: Address, data: Hex, label?: string): Promise<RelayReceipt> {
    if (!relay) throw new Error('relayForward: no relay configured')
    registeredRelay ??= createRegisteredRelaySubmitter(
      createTasraChainClient({rpcUrl: cfg.rpcUrl, addresses: cfg.addresses, chainId: chain.id}), relay, wallet,
    )
    lastRelay = await registeredRelay.submit(to, data, label)
    return lastRelay
  }
  /** One door for every sender-bound write: the relayer when configured, else the local key. */
  async function sendCall(address: Address, abi: readonly unknown[], functionName: string, args: readonly unknown[], label: string): Promise<Hex> {
    const call = {abi, functionName, args} as unknown as Parameters<typeof encodeFunctionData>[0]
    if (relay) return (await relayForward(address, encodeFunctionData(call), label)).txHash
    return wallet.writeContract({address, ...call} as unknown as Parameters<typeof wallet.writeContract>[0])
  }

  const supplied = cfg.wallet
  let wallet: WalletClient<Transport, Chain, Account>
  let account: Account
  if (supplied) {
    if (!supplied.account) {
      throw new Error(
        'createTasraWriteClient: the supplied `wallet` has no account bound — ' +
          'pass a client from wagmi getWalletClient() or createWalletClient({account, chain, transport})',
      )
    }
    wallet = supplied
    account = supplied.account
  } else {
    if (!cfg.privateKey) {
      throw new Error('createTasraWriteClient: pass either `privateKey` or `wallet`')
    }
    account = privateKeyToAccount(cfg.privateKey)
    wallet = createWalletClient({account, chain, transport: http(cfg.rpcUrl)})
  }

  // A dev/test RPC (besu/anvil) under load can transiently return a STALE nonce for
  // getTransactionCount — e.g. 0 for an account already at 64 — and viem then builds
  // a tx with that nonce, which the node rejects with "nonce too low". This is safe
  // to retry: the tx was rejected BEFORE entering the mempool (no double-submit
  // risk), and since no nonceManager is attached, each retry re-derives the nonce
  // fresh, so a re-run a moment later clears the glitch. Bounded + backoff; ONLY
  // nonce-too-low retries — every other error throws immediately.
  //
  // ⚠ LOCAL-KEY PATH ONLY. Two reasons a supplied wallet must not get this:
  //   1. A browser wallet manages its own nonce, so a retry would re-enter the
  //      signing flow and surface as a SECOND signature prompt for one action —
  //      which reads to the user as a double-spend attempt.
  //   2. It monkey-patches the client, and that client belongs to the caller.
  if (!supplied) {
    const NONCE_TOO_LOW = /nonce too low|nonce provided for the transaction is lower/i
    const withNonceRetry = async <T>(op: () => Promise<T>): Promise<T> => {
      let lastErr: unknown
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          return await op()
        } catch (e) {
          lastErr = e
          if (!NONCE_TOO_LOW.test(String((e as {message?: string})?.message ?? e))) throw e
          await new Promise(r => setTimeout(r, 250 * (attempt + 1)))
        }
      }
      throw lastErr
    }
    const _writeContract = wallet.writeContract.bind(wallet)
    wallet.writeContract = ((args: Parameters<typeof wallet.writeContract>[0]) =>
      withNonceRetry(() => _writeContract(args))) as typeof wallet.writeContract
    const _sendTransaction = wallet.sendTransaction.bind(wallet)
    wallet.sendTransaction = ((args: Parameters<typeof wallet.sendTransaction>[0]) =>
      withNonceRetry(() => _sendTransaction(args))) as typeof wallet.sendTransaction
  }


  /**
   * The contract's own policy preconditions, checked BEFORE signing.
   *
   * Shared by every path that writes a policy so they reject identically. Failing
   * here costs nothing; discovering it as a revert costs the creation on the
   * atomic paths, and on the legacy path costs the slot its amendability forever.
   */
  async function validateRulePolicy(policy: RulePolicyArgs): Promise<Address> {
    const guardian = policy.guardian ?? ZERO_ADDRESS
    if (guardian.toLowerCase() === policy.admin.toLowerCase()) {
      throw new Error('rule policy: guardian must differ from admin')
    }
    if (guardian === ZERO_ADDRESS) {
      // ⚠ READ the floor from the contract; never hardcode it. `MIN_RULE_TIMELOCK` is a
      // public constant, so duplicating it here would be a second source of truth that
      // drifts silently the day the contract changes — and it would drift in the
      // dangerous direction, accepting a policy the chain then rejects.
      const min = (await pub.readContract({
        address: requireAddress(addr, 'KeyRegistry'),
        abi: keyRegistryAbi,
        functionName: 'MIN_RULE_TIMELOCK',
      })) as number | bigint
      if (BigInt(policy.timelockSecs) < BigInt(min)) {
        throw new Error(
          `rule policy: a slot with no guardian needs a timelock of at least ${String(min)}s ` +
            `(MIN_RULE_TIMELOCK), got ${policy.timelockSecs}s`,
        )
      }
    }
    return guardian
  }

  /** The `RulePolicy` tuple the contract expects; all-zero means "immutable". */
  async function policyTuple(
    policy: RulePolicyArgs | undefined,
  ): Promise<{admin: Address; guardian: Address; timelock: number}> {
    if (!policy) return {admin: ZERO_ADDRESS, guardian: ZERO_ADDRESS, timelock: 0}
    const guardian = await validateRulePolicy(policy)
    return {admin: policy.admin, guardian, timelock: policy.timelockSecs}
  }

  /**
   * A one-shot creation reverts `CommitRevealRequired()` when the registry has `requireCommitReveal`
   * set, which every production genesis does. The remedy is a different call rather than a different
   * argument, so name it here: the raw revert says nothing about `createSlotCommitReveal`.
   */
  function rethrowCommitRevealRequired(e: unknown): never {
    const named = describeRevert(e) ?? ''
    if (`${named} ${String((e as Error | undefined)?.message ?? '')}`.includes('CommitRevealRequired')) {
      throw new Error(
        'createSlot: this deployment requires commit-reveal creation (KeyRegistry.requireCommitReveal is set) — ' +
          'use createSlotCommitReveal(), which commits the parameters and reveals once the beacon has advanced',
        {cause: e},
      )
    }
    throw e
  }

  /** Self-sign createKeySlotFiltered. Returns the slot id once the tx is mined. */
  async function createSlot(args: CreateSlotArgs): Promise<{slotId: Hex; txHash: Hex; ruleSalt: Hex; relay?: RelayReceipt}> {
    const slotId = args.slotId ?? random32()
    const salt = args.salt ?? random32()
    const ruleSalt = args.ruleSalt ?? random32()
    // Named `…Hash` only because `ruleCommitment` is the function that derives it;
    // this is the SALTED value the contract stores as `KeySlot.ruleCommitment`.
    const ruleCommitmentHash = ruleCommitment(ruleSalt, args.dcqlRule)
    const tags = (args.tags ?? ['keykeeper']).map(t => keccak256(toHex(t)))
    const mode = modeIndex(args.mode)
    const auth = authTypeIndex(args.authType)
    // The `…WithPolicy` entry point is used ONLY when there is a policy: a slot with
    // no amendment authority is created through the original function, so the common
    // path keeps its long-standing, widely-verified call shape.
    if (args.exportable && args.rulePolicy) {
      throw new Error(
        'createSlot: `exportable` and `rulePolicy` cannot be combined — there is no single ' +
          'entry point for both. Create an exportable slot without an amendment policy.',
      )
    }
    const keyRegistry = requireAddress(addr, 'KeyRegistry')
    const policy = args.rulePolicy ? await policyTuple(args.rulePolicy) : undefined
    const txHash = await (args.exportable
      ? sendCall(keyRegistry, keyRegistryAbi, 'createKeySlotFilteredExportable', [slotId, ruleCommitmentHash, args.k, args.n, mode, auth, salt, tags], 'createKeySlotFilteredExportable')
      : policy
      ? sendCall(keyRegistry, keyRegistryAbi, 'createKeySlotFilteredWithPolicy', [slotId, ruleCommitmentHash, args.k, args.n, mode, auth, salt, tags, policy], 'createKeySlotFilteredWithPolicy')
      : sendCall(keyRegistry, keyRegistryAbi, 'createKeySlotFiltered', [slotId, ruleCommitmentHash, args.k, args.n, mode, auth, salt, tags], 'createKeySlotFiltered')
    ).catch(rethrowCommitRevealRequired)
    await confirmed(pub, txHash, 'createKeySlotFiltered')
    // ruleSalt is returned because it exists NOWHERE else: without it the rule
    // can never be provisioned to a keeper.
    return {slotId, txHash, ruleSalt, relay: lastRelay?.txHash === txHash ? lastRelay : undefined}
  }

  /**
   * Grinding-resistant slot creation — the production default:
   * commit the params, request an accountant seed, then reveal+create. Falls back
   * to the beacon-epoch wait when a usable seed is unavailable. Needs a beacon
   * (ThresholdRandomBeacon address in the book, or resolved from KeyRegistry.randomBeacon).
   * `onEpoch` reports fallback wait progress; `seeded` identifies the completed path.
   */
  async function createSlotCommitReveal(
    args: CreateSlotArgs & CommitRevealOptions,
  ): Promise<{slotId: Hex; commitTx: Hex; revealTx: Hex; targetEpoch: number; ruleSalt: Hex; seeded: boolean}> {
    const maxWaitMs = args.maxWaitMs ?? 180_000
    if (!Number.isSafeInteger(maxWaitMs) || maxWaitMs < 1 || maxWaitMs > 2_147_483_647) throw new Error('Invalid commit-reveal wait')
    if (args.exportable) throw new Error('Commit-reveal does not support raw-export slots')
    const slotId = args.slotId ?? random32()
    const salt = args.salt ?? random32()
    const ruleSalt = args.ruleSalt ?? random32()
    const ruleCommitmentHash = ruleCommitment(ruleSalt, args.dcqlRule)
    const tags = (args.tags ?? ['keykeeper']).map(t => keccak256(toHex(t)))
    const mode = modeIndex(args.mode)
    // ⚠ `auth` is NOT an input to `computeCommitment` — the commitment deliberately
    // does not cover it, so it is passed at the REVEAL only.
    const auth = authTypeIndex(args.authType)
    // Application descriptors already pin KeyRegistry. Its configured beacon is
    // authoritative when the caller has no separate beacon address in its book.
    const beacon = addr.ThresholdRandomBeacon ?? await pub.readContract({
      address: requireAddress(addr, 'KeyRegistry'), abi: keyRegistryAbi, functionName: 'randomBeacon',
    })
    if (!beacon || beacon === '0x0000000000000000000000000000000000000000') throw new Error('KeyRegistry has no random beacon')
    // Validated UP FRONT, before the commit is signed. A policy the chain would
    // reject must not be discovered at the reveal, minutes and one beacon epoch
    // later, when the commit has already been paid for.
    const policy = args.rulePolicy ? await policyTuple(args.rulePolicy) : null

    const commitment = (await pub.readContract({
      address: requireAddress(addr, 'KeyRegistry'),
      abi: keyRegistryAbi,
      functionName: 'computeCommitment',
      args: [slotId, ruleCommitmentHash, args.k, args.n, mode, salt, tags, account.address],
    })) as Hex
    const keyReg = requireAddress(addr, 'KeyRegistry')
    const beaconEpoch = () => pub.readContract({address: beacon, abi: thresholdRandomBeaconAbi, functionName: 'epoch'}) as Promise<bigint>
    const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

    const commitTx = await sendCall(keyReg, keyRegistryAbi, 'commitKeySlot', [commitment], 'commitKeySlot')
    await confirmed(pub, commitTx, 'commitKeySlot')

    // Read the ACTUAL target epoch the contract pinned (computing it client-side
    // races the ~20s beacon). slotCommits → (targetEpoch, expiryEpoch, creator, used).
    const commit = (await pub.readContract({address: keyReg, abi: keyRegistryAbi, functionName: 'slotCommits', args: [commitment]})) as readonly [bigint, bigint, string, boolean]
    const targetEpoch = Number(commit[0])

    // ADR-0075 FAST PATH: ask the accountant set to threshold-sign this commitment, and reveal
    // immediately instead of waiting for `targetEpoch`.
    //
    // ⚠ Strictly an optimisation, and written so it can only ever cost time. Every way it can go
    //   wrong — no accountant reachable, a KeyRegistry too old to have `commitSeedDigest`, a set
    //   whose group key is not the beacon's — lands in the epoch wait below, which is what this
    //   path did before it existed. The commitment is unchanged either way, so nothing is lost by
    //   trying.
    // ⚠ The seeded reveal draws a DIFFERENT committee than the epoch path would, because the seed
    //   is different. That is the mechanism, not a side effect: both seeds post-date the
    //   commitment, so both are ungrindable, and the creator does not get to pick which it gets.
    let seed: SlotSeed | null = null
    if (args.slotSeed !== false) {
      try {
        seed = await requestSlotSeed(
          createTasraChainClient({rpcUrl: cfg.rpcUrl, addresses: cfg.addresses, chainId: chain.id}),
          keyReg,
          commitment,
          {urls: args.accountantUrls, timeoutMs: args.slotSeedTimeoutMs},
        )
      } catch {
        seed = null
      }
    }
    args.onSeed?.(seed)
    if (seed) {
      try {
        const seededTx = policy
          ? await sendCall(keyReg, keyRegistryAbi, 'revealKeySlotWithSeedAndPolicy', [slotId, ruleCommitmentHash, args.k, args.n, mode, auth, salt, tags, seed.signature, policy], 'revealKeySlotWithSeedAndPolicy')
          : await sendCall(keyReg, keyRegistryAbi, 'revealKeySlotWithSeed', [slotId, ruleCommitmentHash, args.k, args.n, mode, auth, salt, tags, seed.signature], 'revealKeySlotWithSeed')
        await confirmed(pub, seededTx, 'revealKeySlotWithSeed')
        return {slotId, commitTx, revealTx: seededTx, targetEpoch, ruleSalt, seeded: true}
      } catch (e) {
        // ⚠ Under a relay this MUST rethrow. The relay submitter owns the retries of the one
        //   request it signed, and falling through would start a second signed request against the
        //   same forwarder nonce — the defect that wedges every later write by this signer.
        //   Without a relay, a reverted seeded reveal has spent gas and left the commitment
        //   untouched, so the epoch wait below still completes the creation.
        if (relay) throw e
      }
    }

    // Wait for the beacon to reach the target, then reveal — retrying across the
    // epoch boundary (EpochNotReached / BeaconSeedUnavailable can transiently fire
    // until the seed for the target epoch has landed).
    const deadline = Date.now() + maxWaitMs
    let revealTx: Hex | undefined
    let prevEpoch = -1
    while (!revealTx) {
      const cur = Number(await beaconEpoch())
      args.onEpoch?.(cur, targetEpoch)
      if (!commit[3] && BigInt(cur) > commit[1]) throw new SlotCommitmentExpiredError(chain.id, keyReg, slotId, commitment, account.address, salt)
      if (cur < targetEpoch) {
        if (Date.now() > deadline) throw new Error(`beacon did not reach target epoch ${targetEpoch} (at ${cur})`)
        // The beacon is anchored to CHAIN time (tick = block.timestamp / interval).
        // On a mint-on-demand chain (the local dev chain), block.timestamp only
        // advances when a transaction mints a block - so an idle chain freezes the
        // beacon and this wait would always hit its deadline. When the epoch has
        // not moved since the last poll AND the head is stale, nudge chain time
        // with a zero-value self-transfer. On live chains (Fuji, mainnet) blocks
        // flow continuously, the head is never stale, and no nudge is ever sent.
        if (!relay && cur === prevEpoch) {
          try {
            const head = await pub.getBlock()
            const nowSecs = BigInt(Math.floor(Date.now() / 1000))
            if (nowSecs - head.timestamp > 5n && wallet.account) {
              const nudge = await wallet.sendTransaction({to: wallet.account.address, value: 0n})
              await confirmed(pub, nudge, 'chain-time nudge')
            }
          } catch {
            // Best-effort: a failed nudge leaves us exactly where a passive wait would be.
          }
        }
        prevEpoch = cur
        await sleep(3000)
        continue
      }
      try {
        // With a policy, the reveal PINS IT in the same transaction. That is the
        // whole point: as a follow-up call it is unwinnable from a wallet that
        // prompts, because the DKG starts the instant this transaction lands.
        revealTx = policy
          ? await sendCall(keyReg, keyRegistryAbi, 'revealKeySlotWithPolicy', [slotId, ruleCommitmentHash, args.k, args.n, mode, auth, salt, tags, policy], 'revealKeySlotWithPolicy')
          : await sendCall(keyReg, keyRegistryAbi, 'revealKeySlot', [slotId, ruleCommitmentHash, args.k, args.n, mode, auth, salt, tags], 'revealKeySlot')
        await confirmed(pub, revealTx, 'revealKeySlot')
      } catch (e) {
        revealTx = undefined
        // The relay submitter owns bounded retries of one signed request. Never start a
        // replacement attempt or a direct write from this epoch-wait loop.
        if (relay) throw e
        if (Date.now() > deadline) throw e
        await sleep(3000)
      }
    }
    return {slotId, commitTx, revealTx, targetEpoch, ruleSalt, seeded: false}
  }

  /** Prepay a slot's metered usage: approve TSRA then Settlement.fund(slot, amount). */
  async function fundSlot(slotId: Hex, amount: bigint): Promise<{approveTx: Hex; fundTx: Hex; relay?: RelayReceipt}> {
    const token = requireAddress(addr, 'TasraToken')
    const settlement = requireAddress(addr, 'Settlement')
    const approveTx = await wallet.writeContract({address: token, abi: tasraTokenAbi, functionName: 'approve', args: [settlement, amount]})
    await confirmed(pub, approveTx, 'approve')
    const fundTx = await sendCall(settlement, settlementAbi, 'fund', [slotId, amount], 'fund')
    await confirmed(pub, fundTx, 'fund')
    return {approveTx, fundTx, relay: relay ? lastRelay : undefined}
  }

  /** Send native ETH (gas) — e.g. a funded key backing a faucet. */
  async function sendEth(to: Address, wei: bigint): Promise<Hex> {
    const h = await wallet.sendTransaction({to, value: wei})
    await confirmed(pub, h, 'sendEth')
    return h
  }

  /** Transfer TSRA — e.g. a faucet handing tokens to a fresh client. */
  async function transferTsra(to: Address, amount: bigint): Promise<Hex> {
    const h = await wallet.writeContract({address: requireAddress(addr, 'TasraToken'), abi: tasraTokenAbi, functionName: 'transfer', args: [to, amount]})
    await confirmed(pub, h, 'transfer')
    return h
  }

  /** EURC the curve prices in (the real Circle token, or the demo mock on a dev/test chain). */
  async function eurcBalance(a: Address): Promise<bigint> {
    return (await pub.readContract({address: requireAddress(addr, 'MockEurc'), abi: mockEurcAbi, functionName: 'balanceOf', args: [a]})) as bigint
  }
  /** Approve EURC to the bonding curve — an ERC-20 approve, always from the local key. */
  async function approveEurcForCurve(amount: bigint): Promise<Hex> {
    const h = await wallet.writeContract({address: requireAddress(addr, 'MockEurc'), abi: mockEurcAbi, functionName: 'approve', args: [requireAddress(addr, 'BondingCurve'), amount]})
    await confirmed(pub, h, 'approve')
    return h
  }
  /** DEV/TEST ONLY: mint the demo MockEurc (permissionless faucet). Fails against real EURC. */
  async function mintMockEurc(to: Address, amount: bigint): Promise<Hex> {
    const actualChainId = await pub.getChainId()
    const token = requireAddress(addr, 'MockEurc')
    const profile = resolveNetworkProfile(networkNameForChain(actualChainId), {chainId: actualChainId, eurcAddress: token})
    assertEurcFaucetAllowed(profile, actualChainId, token)
    const h = await wallet.writeContract({address: requireAddress(addr, 'MockEurc'), abi: mockEurcAbi, functionName: 'mint', args: [to, amount]})
    await confirmed(pub, h, 'mint')
    return h
  }
  // ─── slot lifecycle (KeyRegistry; gated to the slot's creator/owner) ─────────
  /** Rotate a slot's key — re-DKG under a new epoch. */
  async function rotateKey(slotId: Hex, reason = ''): Promise<Hex> {
    const h = await wallet.writeContract({address: requireAddress(addr, 'KeyRegistry'), abi: keyRegistryAbi, functionName: 'rotateKey', args: [slotId, reason]})
    await confirmed(pub, h, 'rotateKey')
    return h
  }
  /** Reshare a slot to a new operator set / threshold. */
  async function reshareKey(slotId: Hex, newOperators: Address[], k: number, n: number, reason = ''): Promise<Hex> {
    const h = await wallet.writeContract({address: requireAddress(addr, 'KeyRegistry'), abi: keyRegistryAbi, functionName: 'reshareKey', args: [slotId, newOperators, k, n, reason]})
    await confirmed(pub, h, 'reshareKey')
    return h
  }
  /** Cancel a slot. */
  async function cancelSlot(slotId: Hex): Promise<Hex> {
    const h = await wallet.writeContract({address: requireAddress(addr, 'KeyRegistry'), abi: keyRegistryAbi, functionName: 'cancelSlot', args: [slotId]})
    await confirmed(pub, h, 'cancelSlot')
    return h
  }
  /** Renew a slot's lease. `renew` is creator-only, so this must be signed by the slot's creator —
   *  routed through `sendCall` so it relays (ERC-2771 forward) when a relay is configured, exactly
   *  like `createSlot`. A direct `writeContract` here would sign with the LOCAL key, which is not
   *  the creator when the slot was created under a forwarded (`_msgSender()`) identity. */
  async function renewSlot(slotId: Hex): Promise<Hex> {
    const h = await sendCall(requireAddress(addr, 'KeyRegistry'), keyRegistryAbi, 'renew', [slotId], 'renew')
    await confirmed(pub, h, 'renew')
    return h
  }
  /** Set the slot's per-request verifier-committee policy: committee
   *  draw size + signing quorum. */
  async function setVerifierPolicy(slotId: Hex, committee: number, quorum: number): Promise<Hex> {
    const h = await sendCall(requireAddress(addr, 'KeyRegistry'), keyRegistryAbi, 'setVerifierPolicy', [slotId, committee, quorum], 'setVerifierPolicy')
    await confirmed(pub, h, 'setVerifierPolicy')
    return h
  }

  /**
   * Pin a slot's amendment authority. Creator only, ONCE, and only while
   * the slot is still fresh.
   *
   * ⚠ PREFER `rulePolicy` on {@link CreateSlotArgs}. This function is a SECOND
   * transaction, and as such it is a race that cannot be won from any wallet that
   * asks a human to approve one — which is every browser wallet. It reverts
   * `RulePolicySlotNotFresh` once `epoch`, `publicKey` or `ruleVersion` is non-zero,
   * and the keepers begin their DKG the moment creation emits `KeySlotCreated`. On a
   * local fleet the key anchors in a few seconds, after which the slot is immutable
   * FOREVER: there is deliberately no meta-amendment, so a rule can then only be
   * changed by creating a new slot, which for threshold SSH means a new
   * `authorized_keys` line on every host.
   *
   * That failure was observed end to end, not theorised: commit and reveal mined,
   * this call reverted, and a slot created with "amendable" requested came out
   * permanent. Passing `rulePolicy` to `createSlot` / `createSlotCommitReveal`
   * pins the authority inside the creating transaction and removes the race.
   *
   * Kept for slots created by an older client, and for a signer with no human in
   * the loop (a script holding the key) where the follow-up call can still land in
   * time. In that case call it IMMEDIATELY after the reveal — do not await anything
   * else in between, and do not offer the user a decision point here.
   *
   * The contract's own preconditions, enforced here as arguments rather than
   * discovered as reverts: `guardian` must differ from `admin` (one address holding
   * both collapses propose, veto and endorse into a single authority), and a slot
   * with NO guardian must carry at least `MIN_RULE_TIMELOCK` (1 hour) of delay,
   * because the delay is then the only thing standing between a proposal and
   * activation.
   */
  async function setRulePolicy(slotId: Hex, policy: RulePolicyArgs): Promise<Hex> {
    const keyReg = requireAddress(addr, 'KeyRegistry')
    const guardian = await validateRulePolicy(policy)
    const h = await wallet.writeContract({
      address: keyReg,
      abi: keyRegistryAbi,
      functionName: 'setRulePolicy',
      args: [slotId, policy.admin, guardian, policy.timelockSecs],
    })
    await confirmed(pub, h, 'setRulePolicy')
    return h
  }

  // ─── TASRA tokenomics (BondingCurve / TasraToken) ────────────────────────────
  /** Buy TSRA from the bonding curve. Approve `eurcAmount` of EURC to the
   *  BondingCurve first; read balances for the fill. */
  async function buyTsra(eurcAmount: bigint, minTsraOut: bigint): Promise<Hex> {
    const h = await sendCall(requireAddress(addr, 'BondingCurve'), bondingCurveAbi, 'buy', [eurcAmount, minTsraOut], 'buy')
    await confirmed(pub, h, 'buy')
    return h
  }
  /** Redeem TSRA back to the bonding curve (approves TSRA to the curve first).
   *  `minEurcOut` is the slippage floor the pre-audit hardening added to `redeem` (the
   *  VWAP can move between the read and the inclusion); `0n` accepts any fill. */
  async function redeemTsra(tsraAmount: bigint, minEurcOut: bigint = 0n): Promise<{approveTx: Hex; redeemTx: Hex}> {
    const curve = requireAddress(addr, 'BondingCurve')
    const approveTx = await wallet.writeContract({address: requireAddress(addr, 'TasraToken'), abi: tasraTokenAbi, functionName: 'approve', args: [curve, tsraAmount]})
    await confirmed(pub, approveTx, 'approve')
    const redeemTx = await wallet.writeContract({address: curve, abi: bondingCurveAbi, functionName: 'redeem', args: [tsraAmount, minEurcOut]})
    await confirmed(pub, redeemTx, 'redeem')
    return {approveTx, redeemTx}
  }
  /** Burn TSRA from the caller's balance (deflationary). */
  async function burnTsra(amount: bigint): Promise<Hex> {
    const h = await wallet.writeContract({address: requireAddress(addr, 'TasraToken'), abi: tasraTokenAbi, functionName: 'burn', args: [amount]})
    await confirmed(pub, h, 'burn')
    return h
  }
  const spotPrice = () =>
    pub.readContract({address: requireAddress(addr, 'BondingCurve'), abi: bondingCurveAbi, functionName: 'spotPrice'}) as Promise<bigint>
  const priceAt = (sold: bigint) =>
    pub.readContract({address: requireAddress(addr, 'BondingCurve'), abi: bondingCurveAbi, functionName: 'priceAt', args: [sold]}) as Promise<bigint>

  // ─── treasury / vault (owner / refunder gated) ───────────────────────────────
  async function treasuryWithdraw(to: Address, amount: bigint): Promise<Hex> {
    const h = await wallet.writeContract({address: requireAddress(addr, 'Treasury'), abi: treasuryAbi, functionName: 'withdraw', args: [to, amount]})
    await confirmed(pub, h, 'withdraw')
    return h
  }
  async function treasuryRefund(to: Address, amount: bigint): Promise<Hex> {
    const h = await wallet.writeContract({address: requireAddress(addr, 'Treasury'), abi: treasuryAbi, functionName: 'refund', args: [to, amount]})
    await confirmed(pub, h, 'refund')
    return h
  }
  /** Release vested TSRA from one tranche's vault to its beneficiary. */
  async function vaultRelease(tranche: VaultTranche): Promise<Hex> {
    const h = await wallet.writeContract({address: requireVaultAddress(addr, tranche), abi: tasraVestingVaultAbi, functionName: 'release', args: []})
    await confirmed(pub, h, 'release')
    return h
  }

  const tsraBalance = (of?: Address) =>
    pub.readContract({address: requireAddress(addr, 'TasraToken'), abi: tasraTokenAbi, functionName: 'balanceOf', args: [of ?? account.address]}) as Promise<bigint>
  const ethBalance = (of?: Address) => pub.getBalance({address: of ?? account.address})
  const settlementBalance = (slotId: Hex) =>
    pub.readContract({address: requireAddress(addr, 'Settlement'), abi: settlementAbi, functionName: 'balanceOf', args: [slotId]}) as Promise<bigint>

  return {
    account,
    address: account.address,
    createSlot,
    createSlotCommitReveal,
    fundSlot,
    sendEth,
    transferTsra,
    // slot lifecycle
    rotateKey,
    reshareKey,
    cancelSlot,
    renewSlot,
    setVerifierPolicy,
    setRulePolicy,
    // tokenomics
    buyTsra,
    approveEurcForCurve,
    mintMockEurc,
    eurcBalance,
    /** True when sender-bound calls are relayed. */
    relayEnabled: !!relay,
    /** Receipt of the most recent relayed call (id, tx, gas the relayer paid). */
    lastRelay: () => lastRelay,
    pendingRelayAttempt: () => registeredRelay?.pendingAttempt(),
    reconcileRelay: async () => {
      const result = await registeredRelay?.reconcile()
      if (result?.receipt) lastRelay = result.receipt
      return result
    },
    redeemTsra,
    burnTsra,
    spotPrice,
    priceAt,
    // treasury / vault
    treasuryWithdraw,
    treasuryRefund,
    vaultRelease,
    // reads
    tsraBalance,
    ethBalance,
    settlementBalance,
    wallet,
    pub,
  }
}

/**
 * A write client for a deployment: slot lifecycle, funding, token and treasury
 * operations, signed by the configured account.
 *
 * Written out rather than inferred for the same reason as {@link TasraChainClient}
 * — inference expands viem's client types inline, and once expanded they reference
 * internal viem module paths a consumer cannot name (TS2742).
 */
export interface TasraWriteClient {
  /** The account every write is signed with. */
  account: Account
  /** Convenience alias for `account.address`. */
  address: Address
  /** The underlying wallet client. */
  wallet: WalletClient<Transport, Chain, Account>
  /** A read client on the same RPC, used for receipts and balance reads. */
  pub: PublicClient

  /**
   * Create a key slot on chain.
   *
   * ⚠⚠ **PERSIST `slotId` AND `ruleSalt` DURABLY BEFORE DOING ANYTHING ELSE.** This is
   * the only time you are given the salt. The chain stores only the salted commitment
   * `keccak256(DOMAIN ‖ ruleSalt ‖ rule)`, the salt is random and cannot be re-derived,
   * and the SDK persists nothing.
   *
   * Lose it and the slot is **permanently unusable**: a keeper recomputes that
   * commitment before accepting the clear rule, so provisioning fails with
   * `dcql_rule does not match the slot's on-chain commitment` — which reads like a typo
   * in a rule that is fine. There is no recovery path, on chain or off.
   */
  createSlot(args: CreateSlotArgs): Promise<{slotId: Hex; txHash: Hex; ruleSalt: Hex; relay?: RelayReceipt}>
  /**
   * Create a key slot through commit/reveal, so the committee is drawn from a seed that
   * did not exist when the parameters were committed. Tries an accountant seed
   * first and falls back to waiting for a beacon epoch when unavailable.
   *
   * ⚠⚠ The same durability requirement as {@link TasraWriteClient.createSlot}: persist
   * `slotId` and `ruleSalt` before anything else. The fallback can wait on the beacon,
   * increasing the time in which a crash could lose the salt.
   */
  createSlotCommitReveal(
    args: CreateSlotArgs & CommitRevealOptions,
  ): Promise<{slotId: Hex; commitTx: Hex; revealTx: Hex; targetEpoch: number; ruleSalt: Hex; seeded: boolean}>
  fundSlot(slotId: Hex, amount: bigint): Promise<{approveTx: Hex; fundTx: Hex; relay?: RelayReceipt}>
  sendEth(to: Address, wei: bigint): Promise<Hex>
  transferTsra(to: Address, amount: bigint): Promise<Hex>
  rotateKey(slotId: Hex, reason?: string): Promise<Hex>
  reshareKey(slotId: Hex, newOperators: Address[], k: number, n: number, reason?: string): Promise<Hex>
  cancelSlot(slotId: Hex): Promise<Hex>
  renewSlot(slotId: Hex): Promise<Hex>
  setVerifierPolicy(slotId: Hex, committee: number, quorum: number): Promise<Hex>
  setRulePolicy(slotId: Hex, policy: RulePolicyArgs): Promise<Hex>

  buyTsra(eurcAmount: bigint, minTsraOut: bigint): Promise<Hex>
  approveEurcForCurve(amount: bigint): Promise<Hex>
  mintMockEurc(to: Address, amount: bigint): Promise<Hex>
  eurcBalance(a: Address): Promise<bigint>
  redeemTsra(tsraAmount: bigint, minEurcOut?: bigint): Promise<{approveTx: Hex; redeemTx: Hex}>
  burnTsra(amount: bigint): Promise<Hex>
  spotPrice(): Promise<bigint>
  priceAt(sold: bigint): Promise<bigint>

  treasuryWithdraw(to: Address, amount: bigint): Promise<Hex>
  treasuryRefund(to: Address, amount: bigint): Promise<Hex>
  vaultRelease(tranche: VaultTranche): Promise<Hex>

  tsraBalance(of?: Address): Promise<bigint>
  ethBalance(of?: Address): Promise<bigint>
  settlementBalance(slotId: Hex): Promise<bigint>

  /** Whether writes are submitted through a registered relay rather than directly. */
  relayEnabled: boolean
  lastRelay(): RelayReceipt | undefined
  pendingRelayAttempt(): RelayAttempt | undefined
  reconcileRelay(): Promise<{receipt?: RelayReceipt; expired: boolean} | undefined>
}
