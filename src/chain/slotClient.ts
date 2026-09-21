// Slot-driven managed JWT client. Same ergonomics as `createTasraClient`, but you
// bring a slot id + a chain client instead of hardcoding `{nodes, verifier}`:
//
//   • the keeper NODES come from the slot's on-chain committee (assignedNodes → nodeOf().url)
//   • the VERIFIER is CHOSEN from the on-chain verifier set (NodeRegistry operators tagged
//     keccak256("verifier")) at random — that verifier validates your VP and issues the JWT
//   • the JWT then authorizes the operation at a keeper node
//
// So the verifier is genuinely part of every session: `openSession` picks one from chain,
// and the returned session's JWT was minted by it. This composes the existing verifier-auth
// + session machinery (src/client) with chain discovery (src/chain/discovery) — no new
// crypto, just endpoint resolution moved from static config to the registry.

import type {TasraChainClient} from './client.js'
import {resolveSlotKeeperUrls, resolveVerifierDirectory} from './discovery.js'
import {
  createTasraClient,
  type SessionAuth,
  type OpenSessionOpts,
  type Session,
} from '../client/index.js'
import type {CommitteeVerifier} from '../committee/request.js'

/** How the session's endpoints were resolved from chain — surfaced so callers can SEE
 *  which verifier was chosen and which keeper committee the slot is bound to. */
export interface ResolvedEndpoints {
  slotId: string
  /** The slot's on-chain assigned keeper node URLs. */
  nodes: string[]
  /** The verifier chosen (at random) from the on-chain set — it issued the JWT. */
  verifier: string
  /** Size of the on-chain verifier set the choice was drawn from. */
  verifierCount: number
}

export interface TasraSlotClientConfig {
  /** Read client for the deployment (RPC + address book). */
  chain: TasraChainClient
  /** This holder's DID (recipient_did / holder for the JWT). */
  identity?: string
  /**
   * Map an on-chain (in-cluster) node/verifier URL to a reachable one — e.g. rewrite the
   * demo fleet's `tasra-node-7:8080` to a host port. Default: identity (URLs used as-is,
   * correct when the caller shares the nodes' network).
   */
  rewriteUrl?: (url: string) => string
  /** Observe the per-session resolution (chosen verifier + discovered nodes). */
  onResolve?: (r: ResolvedEndpoints) => void
  /** JWT refresh skew (ms), forwarded to the session. */
  skewMs?: number
}

export interface TasraSlotClient {
  /** Discover the slot's nodes + choose a verifier from chain, mint the JWT via that
   *  verifier, and return a managed session (encrypt / decrypt / sign). */
  openSession(slotId: string, auth: SessionAuth, opts?: OpenSessionOpts): Promise<Session>
  /** Resolve the endpoints for a slot WITHOUT opening a session (which verifier would be
   *  chosen + the slot's keeper committee). Handy for inspection. */
  resolveEndpoints(slotId: string): Promise<ResolvedEndpoints>
  /** The discovered active verifier directory (cached). */
  verifierDirectory(): Promise<CommitteeVerifier[]>
  sessions(): readonly Session[]
  closeAll(): Promise<void>
}

/**
 * Slot-driven managed JWT client — the same ergonomics as
 * {@link createTasraClient}, but you bring a slot id + a chain client instead of
 * hardcoding `{nodes, verifier}`:
 *
 * - the keeper **nodes** come from the slot's on-chain committee
 *   (`assignedNodes` → `nodeOf().url`)
 * - the **verifier** is chosen at random from the on-chain verifier set
 *   (`NodeRegistry` operators tagged `keccak256("verifier")`) — that verifier
 *   validates your VP and issues the JWT
 * - the JWT then authorizes the operation at a keeper node
 *
 * So the verifier is genuinely part of every session: `openSession` picks one from
 * chain, and the returned session's JWT was minted by it. Pass `onResolve` to see
 * which one. This is the production access path.
 *
 * Composes the verifier-auth + session machinery with chain discovery — no new
 * crypto, just endpoint resolution moved from static config to the registry.
 * Contrast {@link createCommitteeSlotClient}, which takes the committee
 * path instead and never reconstructs the key.
 *
 * @param cfg a {@link TasraChainClient} plus this holder's DID. Use `rewriteUrl`
 *   when on-chain URLs are not reachable as-is (e.g. mapping a demo fleet's
 *   in-cluster `tasra-node-7:8080` to a host port).
 * @returns a client that opens managed sessions from a bare slot id
 *
 * @example
 * ```ts
 * const chain = createTasraChainClient({rpcUrl, addresses: addressBookFromEnv(process.env)})
 * const kk = createTasraSlotClient({
 *   chain,
 *   identity: 'did:example:alice',
 *   onResolve: r => console.log('verifier chosen:', r.verifier, 'of', r.verifierCount),
 * })
 *
 * const s = await kk.openSession(slotId, {vpJwt: {dcqlRule, credentials, holderProof}})
 * const sig = await s.sign(messageBytes)
 * await s.close()
 * ```
 */
export function createTasraSlotClient(cfg: TasraSlotClientConfig): TasraSlotClient {
  const rewrite = cfg.rewriteUrl ?? ((u: string) => u)
  const open = new Set<Session>()

  // The verifier set is network-wide (not per-slot), so discover it once and cache.
  let verifiersPromise: Promise<CommitteeVerifier[]> | undefined
  const verifierDirectory = () => (verifiersPromise ??= resolveVerifierDirectory(cfg.chain))

  async function resolveEndpoints(slotId: string): Promise<ResolvedEndpoints> {
    const [nodesRaw, dir] = await Promise.all([
      resolveSlotKeeperUrls(cfg.chain, slotId as `0x${string}`),
      verifierDirectory(),
    ])
    const nodes = nodesRaw.map(rewrite).filter(Boolean)
    if (nodes.length === 0) throw new Error(`slot ${slotId.slice(0, 10)}… has no on-chain assigned keeper node with a URL`)
    const verifiers = dir.map(v => rewrite(v.url)).filter(Boolean)
    if (verifiers.length === 0) throw new Error('no verifiers discovered on chain (NodeRegistry has no active keccak256("verifier")-tagged node with a URL)')
    // Choose the verifier at random — the SDK "queries the chain and picks the verifier".
    const verifier = verifiers[Math.floor(Math.random() * verifiers.length)]!
    return {slotId, nodes, verifier, verifierCount: verifiers.length}
  }

  return {
    resolveEndpoints,
    verifierDirectory,

    async openSession(slotId, auth, opts) {
      const resolved = await resolveEndpoints(slotId)
      cfg.onResolve?.(resolved)
      // Compose the existing managed JWT client with the chain-resolved endpoints. The
      // chosen verifier mints the JWT (openSession → resolveAuth → verify against it).
      const inner = createTasraClient({nodes: resolved.nodes, verifier: resolved.verifier, identity: cfg.identity})
      const session = await inner.openSession(slotId, auth, {skewMs: cfg.skewMs, ...opts})
      open.add(session)
      return session
    },

    sessions() {
      return [...open]
    },
    async closeAll() {
      await Promise.all([...open].map(s => s.close()))
      open.clear()
    },
  }
}
