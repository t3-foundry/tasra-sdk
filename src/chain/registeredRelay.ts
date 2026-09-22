import {decodeEventLog, encodeFunctionData, hashTypedData, parseAbi, type Account, type Address, type Chain, type Hex, type Transport, type WalletClient} from 'viem'
import type {TasraChainClient} from './client.js'
import {authenticateApprovedService, type ServiceDiscoveryTransport} from './serviceIdentity.js'
import {SERVICE_TYPES, type ServiceApproval} from './services.js'
import {revertError} from './revertReason.js'

export interface RelayTransport extends ServiceDiscoveryTransport {
  /** Guard the socket just like discovery. Accept bounded JSON status bodies for 200/202/422. */
  relayRequest(url: string, options: {body?: Uint8Array; maxBytes: number; signal: AbortSignal}): Promise<Uint8Array>
}

export interface RelayIntent {
  chainId: number
  forwarder: Address
  from: Address
  to: Address
  data: Hex
  label: string
}

export interface RegisteredRelayConfig {
  /** Application approvals, in preference order. Registry membership alone never selects a service. */
  approvals: readonly ServiceApproval[]
  transport: RelayTransport
  /** Independently pinned deployment forwarder; never supplied by a relayer manifest. */
  forwarder: Address
  label?: string
  /** Persist the signed reconciliation handle before its first POST. */
  persistAttempt?: (attempt: RelayAttempt) => Promise<void>
  /** Load this durable operation's previous attempt before signing, including after a restart. */
  resumeAttempt?: (intent: RelayIntent) => Promise<RelayAttempt | undefined>
  pollMs?: number
  timeoutMs?: number
  /** At most three authenticated providers receive the identical signed request. */
  maxAttempts?: number
  attemptMs?: number
}

export interface RelayReceipt {
  id: string
  txHash: Hex
  gasUsed?: number
  costWei?: string
}

export const relayForwarderAbi = parseAbi([
  'function nonces(address owner) view returns (uint256)',
  'function execute((address from, address to, uint256 value, uint256 gas, uint48 deadline, bytes data, bytes signature) request) payable',
  'event ExecutedForwardRequest(address indexed signer, uint256 nonce, bool success)',
])
const types = {ForwardRequest: [
  {name: 'from', type: 'address'}, {name: 'to', type: 'address'}, {name: 'value', type: 'uint256'},
  {name: 'gas', type: 'uint256'}, {name: 'nonce', type: 'uint256'}, {name: 'deadline', type: 'uint48'}, {name: 'data', type: 'bytes'},
]} as const

/** JSON-safe reconciliation handle. Persist before POST to resume safely after a client restart. */
export interface RelayAttempt {
  chainId: number
  forwarder: Address
  fromBlock: string
  id: Hex
  request: {from: Address; to: Address; value: '0'; gas: number; nonce: number; deadline: number; data: Hex; signature: Hex; label: string}
}

export class RelayOutcomeUnknownError extends Error {
  constructor(readonly attempt: RelayAttempt, reason = 'No verified chain result before the relay deadline') {
    super(`${reason}; reconcile request ${attempt.id} before signing another operation`)
    this.name = 'RelayOutcomeUnknownError'
  }
}

function typed(attempt: Pick<RelayAttempt, 'chainId' | 'forwarder' | 'request'>) {
  const r = attempt.request
  return {domain: {name: 'KeykeeperForwarder', version: '1', chainId: attempt.chainId, verifyingContract: attempt.forwarder},
    types, primaryType: 'ForwardRequest' as const,
    message: {from: r.from, to: r.to, value: 0n, gas: BigInt(r.gas), nonce: BigInt(r.nonce), deadline: r.deadline, data: r.data}}
}

function executeData(attempt: RelayAttempt): Hex {
  const r = attempt.request
  return encodeFunctionData({abi: relayForwarderAbi, functionName: 'execute', args: [{...r, value: 0n, gas: BigInt(r.gas)}]})
}

function scope(timeoutMs: number) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new Error('Relay deadline exceeded')), timeoutMs)
  return {signal: controller.signal, close: () => { clearTimeout(timer); controller.abort() },
    async run<T>(work: () => Promise<T>): Promise<T> {
      controller.signal.throwIfAborted()
      let abort = () => {}
      try {
        return await Promise.race([work(), new Promise<never>((_, reject) => {
          abort = () => reject(controller.signal.reason)
          controller.signal.addEventListener('abort', abort, {once: true})
        })])
      } finally { controller.signal.removeEventListener('abort', abort) }
    },
  }
}
type Scope = ReturnType<typeof scope>

async function verifiedReceipt(chain: TasraChainClient, attempt: RelayAttempt, hash: Hex, budget: Scope): Promise<RelayReceipt | undefined> {
  const tx = await budget.run(() => chain.client.getTransaction({hash}))
  if (tx.to?.toLowerCase() !== attempt.forwarder.toLowerCase() || tx.value !== 0n || tx.input.toLowerCase() !== executeData(attempt).toLowerCase()) return
  const receipt = await budget.run(() => chain.client.getTransactionReceipt({hash}))
  if (receipt.status !== 'success') return
  const matches = receipt.logs.some(log => {
    if (log.address.toLowerCase() !== attempt.forwarder.toLowerCase()) return false
    try {
      const event = decodeEventLog({abi: relayForwarderAbi, eventName: 'ExecutedForwardRequest', data: log.data, topics: log.topics})
      return event.args.signer.toLowerCase() === attempt.request.from.toLowerCase() && event.args.nonce === BigInt(attempt.request.nonce) && event.args.success
    } catch { return false }
  })
  if (!matches) return
  return {id: attempt.id, txHash: hash, gasUsed: Number(receipt.gasUsed), costWei: (receipt.gasUsed * receipt.effectiveGasPrice).toString()}
}

/**
 * The outcome of reconciling one signed attempt against the chain.
 *
 * ⚠⚠ THREE OUTCOMES, NOT TWO, AND THE THIRD IS THE ONE THAT MATTERS OPERATIONALLY.
 *  - `receipt`      — it executed; here is the proof.
 *  - `expired`      — it never executed and never can (its deadline passed with the nonce still
 *                     free), so the same operation is safe to sign again.
 *  - `unresolvable` — its nonce HAS been consumed, so this request can never execute again
 *                     whatever took it, but the window in which that happened is now further back
 *                     than the log scan can reach. TERMINAL, outcome unknown.
 *
 * Collapsing `unresolvable` into "unknown, try again later" is what wedged a live deployment: a
 * caller that blocks until an attempt resolves blocks FOREVER, because every new block moves the
 * attempt further out of scan range. It is not a transient condition and retrying cannot fix it.
 *
 * ⚠ `unresolvable` is NOT a statement that the operation did not happen — it very probably did.
 * A caller must not blindly redo the work; it must re-read the state the operation would have
 * changed, or surface the attempt for a human. Conflating it with `expired` would turn one
 * uncertain write into a duplicated one.
 */
export interface RelayReconciliation {
  receipt?: RelayReceipt
  expired: boolean
  unresolvable?: boolean
}

async function reconcile(chain: TasraChainClient, attempt: RelayAttempt, budget: Scope): Promise<RelayReconciliation> {
  if (await budget.run(() => chain.client.getChainId()) !== attempt.chainId || hashTypedData(typed(attempt)) !== attempt.id) throw new Error('Relay reconciliation domain or request mismatch')
  const head = await budget.run(() => chain.client.getBlock({blockTag: 'latest'}))
  const nonce = await budget.run(() => chain.client.readContract({address: attempt.forwarder, abi: relayForwarderAbi, functionName: 'nonces', args: [attempt.request.from], blockNumber: head.number}))
  if (nonce < BigInt(attempt.request.nonce)) throw new RelayOutcomeUnknownError(attempt, 'Forwarder nonce moved backwards')
  if (nonce > BigInt(attempt.request.nonce)) {
    const start = BigInt(attempt.fromBlock)
    // ⚠⚠ OUT OF RANGE IS TERMINAL, NOT TRANSIENT. The nonce is already consumed, so this exact
    //    request can never execute again whatever took it — the forwarder rejects a spent nonce.
    //    All that is lost is WHICH request consumed it, and no amount of waiting recovers that:
    //    every new block moves `start` further outside the window. Throwing here made callers
    //    retry forever and permanently wedged a deployment's entire write path.
    if (start < 0n || head.number - start > 10_000n) return {expired: false, unresolvable: true}
    for (let from = start; from <= head.number; from += 2_000n) {
      const logs = await budget.run(() => chain.client.getLogs({address: attempt.forwarder,
        event: relayForwarderAbi[2], args: {signer: attempt.request.from}, fromBlock: from,
        toBlock: from + 1_999n < head.number ? from + 1_999n : head.number, strict: true}))
      for (const log of logs) {
        if (log.args.nonce !== BigInt(attempt.request.nonce) || !log.args.success) continue
        const receipt = await verifiedReceipt(chain, attempt, log.transactionHash, budget)
        if (receipt) return {receipt, expired: false}
      }
    }
    throw new RelayOutcomeUnknownError(attempt, 'Nonce consumed without a matching successful forward request')
  }
  return {expired: head.timestamp > BigInt(attempt.request.deadline)}
}

/** Recover from a lost HTTP response or process restart using the trusted RPC, without broadcasting. */
export async function reconcileRelayAttempt(chain: TasraChainClient, attempt: RelayAttempt, timeoutMs = 30_000): Promise<RelayReconciliation> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new Error('Invalid reconciliation timeout')
  const budget = scope(timeoutMs)
  try { return await reconcile(chain, attempt, budget) } finally { budget.close() }
}

/** One signer per instance. Serializes nonces and blocks new signatures after an uncertain result. */
export function createRegisteredRelaySubmitter(chain: TasraChainClient, config: RegisteredRelayConfig, wallet: WalletClient<Transport, Chain, Account>,
  options: {persistAttempt?: (attempt: RelayAttempt) => Promise<void>} = {}) {
  if (!Array.isArray(config.approvals) || typeof config.transport?.request !== 'function' || typeof config.transport?.relayRequest !== 'function') {
    throw new Error('Relay requires approved registry profiles and a guarded RelayTransport; a URL alone is insufficient')
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(config.forwarder) || /^0x0{40}$/.test(config.forwarder)) throw new Error('Invalid pinned relay forwarder')
  const cfg = {...config, approvals: config.approvals.map(a => Object.freeze({...a}))}
  const timeout = cfg.timeoutMs ?? 120_000, pollMs = cfg.pollMs ?? 1_500, attemptMs = cfg.attemptMs ?? 10_000
  const attempts = cfg.maxAttempts ?? Math.min(3, cfg.approvals.length)
  if (!cfg.approvals.length || cfg.approvals.length > 16 || cfg.approvals.some(a => a.serviceType !== SERVICE_TYPES.gasRelayer) ||
    !Number.isInteger(attempts) || attempts < 1 || attempts > 3 || attempts > cfg.approvals.length ||
    !Number.isSafeInteger(timeout) || timeout < 1 || timeout > 120_000 || !Number.isSafeInteger(pollMs) || pollMs < 10 ||
    !Number.isSafeInteger(attemptMs) || attemptMs < 1 || attemptMs > 30_000) throw new Error('Invalid registered relayer policy')
  let serial = Promise.resolve()
  let pending: RelayAttempt | undefined

  async function submit(to: Address, data: Hex, label?: string): Promise<RelayReceipt> {
    const previous = serial
    let release = () => {}
    serial = new Promise<void>(resolve => { release = resolve })
    await previous
    const budget = scope(timeout)
    let attempt: RelayAttempt | undefined
    try {
      if (pending) throw new RelayOutcomeUnknownError(pending)
      const chainId = await budget.run(() => chain.client.getChainId())
      if (chainId !== wallet.chain.id || cfg.approvals.some(a => a.chainId !== chainId)) throw new Error('Relay chain mismatch')
      const from = wallet.account.address
      const previousAttempt = await budget.run(async () => cfg.resumeAttempt?.({chainId, forwarder: cfg.forwarder, from, to, data, label: label ?? cfg.label ?? ''}))
      if (previousAttempt) {
        if (previousAttempt.chainId !== chainId || previousAttempt.forwarder.toLowerCase() !== cfg.forwarder.toLowerCase() ||
            previousAttempt.request.from.toLowerCase() !== from.toLowerCase() || previousAttempt.request.to.toLowerCase() !== to.toLowerCase() ||
            previousAttempt.request.data.toLowerCase() !== data.toLowerCase()) throw new Error('Persisted relay operation does not match this request')
        const result = await reconcile(chain, previousAttempt, budget)
        if (result.receipt) return result.receipt
        // ⚠⚠ `unresolvable` must NOT resume and must NOT block. Its nonce is spent, so replaying
        //    the stored attempt is guaranteed to be rejected; but blocking on it never clears
        //    either, because the scan window only recedes. Fall through and sign a FRESH request
        //    at the current nonce — the caller was told (via the journal) that the old one is
        //    terminal-with-unknown-outcome and is responsible for not redoing work that landed.
        if (result.unresolvable) pending = undefined
        else if (!result.expired) { pending = previousAttempt; throw new RelayOutcomeUnknownError(previousAttempt) }
      }
      const fromBlock = await budget.run(() => chain.client.getBlockNumber({cacheTime: 0}))
      const nonce = await budget.run(() => chain.client.readContract({address: cfg.forwarder, abi: relayForwarderAbi, functionName: 'nonces', args: [from]}))
      // The inner call is estimated without an ABI, so viem cannot name a custom error; decode it, or a
      // deployment that refuses the write (CommitRevealRequired(), say) reads as an unexplained revert.
      const estimate = await budget.run(() => chain.client.estimateGas({account: from, to, data}))
        .catch(e => {throw revertError(e, 'relay: the inner call reverts at estimation')})
      const gas = estimate + estimate / 4n + 10_000n
      if (nonce > BigInt(Number.MAX_SAFE_INTEGER) || gas > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Relay nonce or gas exceeds the exact JSON integer range')
      const request: RelayAttempt['request'] = {from, to, value: '0', gas: Number(gas), nonce: Number(nonce), deadline: Math.floor(Date.now() / 1000) + 300, data, signature: '0x', label: label ?? cfg.label ?? ''}
      const unsigned = {chainId, forwarder: cfg.forwarder, request}
      request.signature = await budget.run(() => wallet.signTypedData({account: wallet.account, ...typed(unsigned)}))
      attempt = Object.freeze({...unsigned, request: Object.freeze(request), fromBlock: fromBlock.toString(), id: hashTypedData(typed(unsigned))})
      const body = new TextEncoder().encode(JSON.stringify(request))
      if (body.length > 65_536) throw new Error('Relay request too large')
      // The application can durably store this handle before any endpoint receives it.
      const persist = cfg.persistAttempt ?? options.persistAttempt
      if (persist) await budget.run(() => persist(attempt!))
      let contacted = false
      for (const approval of cfg.approvals.slice(0, attempts)) {
        if (contacted) {
          const result = await reconcile(chain, attempt, budget)
          if (result.receipt) { pending = undefined; return result.receipt }
          if (result.expired) { pending = undefined; throw new Error('Forward request expired without execution') }
        }
        let endpoint: string
        try {
          const authenticated = await budget.run(() => authenticateApprovedService(chain, approval, {
            request: (url, opts) => cfg.transport.request(url, {...opts, signal: AbortSignal.any([opts.signal, budget.signal])}),
          }))
          if (!authenticated.manifest.capabilities.includes('relay-forward')) throw new Error('Service does not advertise relay-forward')
          endpoint = authenticated.record.endpoint
        } catch { budget.signal.throwIfAborted(); continue }
        pending = attempt
        contacted = true
        try {
          await budget.run(() => cfg.transport.relayRequest(endpoint + '/v1/relay/forward', {body, maxBytes: 4_096, signal: budget.signal}))
        } catch { budget.signal.throwIfAborted() }
        const until = Date.now() + attemptMs
        do {
          // A lost POST response still has a deterministic status ID.
          try {
            const bytes = await budget.run(() => cfg.transport.relayRequest(endpoint + '/v1/relay/' + attempt!.id, {maxBytes: 4_096, signal: budget.signal}))
            if (bytes.length > 4_096) throw new Error('Relay status too large')
            const status = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes)) as {id: string; tx_hash?: Hex; state: string}
            if (status.id !== attempt.id) throw new Error('Relay status request mismatch')
            if (status.state === 'mined' && /^0x[0-9a-fA-F]{64}$/.test(status.tx_hash ?? '')) {
              const receipt = await verifiedReceipt(chain, attempt, status.tx_hash!, budget)
              if (receipt) { pending = undefined; return receipt }
            }
            if (['failed', 'rejected', 'unknown'].includes(status.state)) break
          } catch { budget.signal.throwIfAborted(); break }
          const result = await reconcile(chain, attempt, budget)
          if (result.receipt) { pending = undefined; return result.receipt }
          if (result.expired) { pending = undefined; throw new Error('Forward request expired without execution') }
          await budget.run(() => new Promise(resolve => setTimeout(resolve, Math.min(pollMs, Math.max(1, until - Date.now())))))
        } while (Date.now() < until)
      }
      if (!contacted) throw new Error('No approved relayer authenticated')
      const result = await reconcile(chain, attempt, budget)
      if (result.receipt) { pending = undefined; return result.receipt }
      if (result.expired) { pending = undefined; throw new Error('Forward request expired without execution') }
      throw new RelayOutcomeUnknownError(attempt)
    } catch (error) {
      if (pending) throw new RelayOutcomeUnknownError(pending, error instanceof Error ? error.message : undefined)
      throw error
    } finally { budget.close(); release() }
  }
  return {submit, pendingAttempt: () => pending,
    async reconcile() {
      if (!pending) return undefined
      const current = pending
      const result = await reconcileRelayAttempt(chain, current)
      // `unresolvable` frees the signer too: the nonce is spent, so holding the slot blocks
      // every future write for an attempt that can never complete.
      if (pending === current && (result.receipt || result.expired || result.unresolvable)) pending = undefined
      return result
    },
  }
}
