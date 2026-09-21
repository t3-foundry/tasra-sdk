// TasraClient — configure connection params once (nodes + verifier +
// identity), then open managed Sessions per slot. The few-lines integration
// surface; product-agnostic (no transport/roster/messaging).

import {
  redeemRenewalToken,
  redeemCredential,
  verifyVpJwt,
  decodeJwtClaims,
} from '../auth/verifier.js'
import {createHolderProof, type HolderSigner} from '../auth/holderProof.js'
import {fetchMpk} from '../keys/node-client.js'
import {hexToBytes} from '../crypto/hex.js'
import {newSession, type Session} from './session.js'

/**
 * Connection parameters for {@link createTasraClient}. Set once and reused by
 * every session the client opens.
 *
 * `verifier` and `identity` are optional in the type because `{jwt}` auth needs
 * neither, but each is enforced at `openSession` time for the modes that do.
 */
export interface TasraClientConfig {
  /** k-of-n keykeeper-node base URLs. */
  nodes: string[]
  /** Verifier base URL — required for renewalToken / redemptionToken / vpJwt auth. */
  verifier?: string
  /** This holder's DID — recipient_did / holder for credential & vp-jwt auth. */
  identity?: string
}

/**
 * Holder proof-of-possession options (F1/F4). The SDK fetches a `/v1/nonce` and
 * signs a holder proof with `signer` (the holder DID's authentication key), bound
 * to `audience` (the verifier's token `iss`) and the presented credentials.
 */
export interface HolderProofAuth {
  signer: HolderSigner
  /** The verifier's expected audience (its token `iss`). */
  audience: string
  /** Optionally scope the proof to a slot / action (must match the slot being opened). */
  slotId?: string
  action?: string
  ttlSecs?: number
}

/** The `vpJwt` auth mode's payload: signed VCs + a holder-key proof → JWT. */
export interface VpJwtAuth {
  dcqlRule: string
  credentials: string[]
  holderProof: HolderProofAuth
}

/**
 * How to obtain the slot JWT — exactly one of four modes.
 *
 * `renewalToken` is the ONLY mode that silently auto-renews; the other three
 * resolve once and then fail loud on expiry, prompting a fresh `openSession`.
 *
 * The `?: undefined` members make the modes **mutually exclusive at compile
 * time**. Without them `{jwt, renewalToken}` type-checked (it structurally
 * satisfies `{jwt: string}`) and the loser was silently ignored at runtime.
 */
export type SessionAuth =
  | {jwt: string; renewalToken?: undefined; redemptionToken?: undefined; vpJwt?: undefined}
  | {renewalToken: string; jwt?: undefined; redemptionToken?: undefined; vpJwt?: undefined}
  | {redemptionToken: string; jwt?: undefined; renewalToken?: undefined; vpJwt?: undefined}
  | {vpJwt: VpJwtAuth; jwt?: undefined; renewalToken?: undefined; redemptionToken?: undefined}

export interface OpenSessionOpts {
  /** AAD for envelopes this session encrypts. Default = the 32-byte slot id. */
  identity?: Uint8Array
  /** JWT refresh skew (ms) for isJwtExpiringSoon. Default 30_000. */
  skewMs?: number
}

/**
 * A configured client. Holds no key material itself — each {@link Session} it
 * opens owns its own JWT and (lazily) assembled master key.
 */
export interface TasraClient {
  readonly config: Readonly<TasraClientConfig>
  /** Obtain a JWT (per `auth`), assemble the slot key, and return a managed Session. */
  openSession(
    slotId: string,
    auth: SessionAuth,
    opts?: OpenSessionOpts,
  ): Promise<Session>
  /** Currently-open sessions (live references). */
  sessions(): readonly Session[]
  /** Zeroize + close every open session. */
  closeAll(): Promise<void>
}

interface ResolvedAuth {
  jwt: string
  holder: string
  renewalToken?: string
}

async function resolveAuth(
  auth: SessionAuth,
  verifier: string | undefined,
  identity: string | undefined,
): Promise<ResolvedAuth> {
  if (auth.jwt !== undefined) {
    return {jwt: auth.jwt, holder: decodeJwtClaims(auth.jwt)?.sub ?? identity ?? ''}
  }
  if (auth.renewalToken !== undefined) {
    if (!verifier) throw new Error('openSession({renewalToken}): config.verifier is required')
    const t = await redeemRenewalToken(verifier, auth.renewalToken)
    return {jwt: t.token, holder: t.holder, renewalToken: auth.renewalToken}
  }
  if (auth.redemptionToken !== undefined) {
    if (!verifier) throw new Error('openSession({redemptionToken}): config.verifier is required')
    if (!identity) throw new Error('openSession({redemptionToken}): config.identity (recipient DID) is required')
    const t = await redeemCredential(verifier, auth.redemptionToken, identity)
    return {jwt: t.token, holder: t.holder}
  }
  if (auth.vpJwt !== undefined) {
    if (!verifier) throw new Error('openSession({vpJwt}): config.verifier is required')
    if (!identity) throw new Error('openSession({vpJwt}): config.identity (holder DID) is required')
    if (!auth.vpJwt.holderProof) {
      throw new Error('openSession({vpJwt}): holderProof is required to prove control of the holder DID')
    }
    // F1/F4: fetch a nonce + sign a proof bound to these exact credentials.
    const holderProof = await createHolderProof(verifier, {
      signer: auth.vpJwt.holderProof.signer,
      audience: auth.vpJwt.holderProof.audience,
      credentials: auth.vpJwt.credentials,
      slotId: auth.vpJwt.holderProof.slotId,
      action: auth.vpJwt.holderProof.action,
      ttlSecs: auth.vpJwt.holderProof.ttlSecs,
    })
    const t = await verifyVpJwt(verifier, {
      dcql_rule: auth.vpJwt.dcqlRule,
      holder: identity,
      credentials: auth.vpJwt.credentials,
      holder_proof: holderProof,
    })
    return {jwt: t.token, holder: t.holder}
  }
  throw new Error('openSession: unrecognized auth (expected jwt | renewalToken | redemptionToken | vpJwt)')
}

/**
 * The high-level integration surface: configure connection parameters once, then
 * open a managed {@link Session} per slot.
 *
 * The session obtains a DCQL-gated JWT, keeps it fresh, and Lagrange-assembles the
 * slot's master key from the fleet **lazily — on the first `decrypt`** (so
 * `encrypt`/`sign` never pay a shard fetch, and a sign-only slot never reconstructs
 * a key at all), re-assembling when the slot rotates. `Session.close()` zeroizes it.
 *
 * This is the layer most integrations want. Below it sit the composable primitives
 * (`redeemCredential`, `fetchAndAssembleKey`, `encryptEnvelope`, …) that it
 * orchestrates — drop to those when you need finer control. To resolve endpoints
 * from chain instead of hardcoding them, use {@link createTasraSlotClient}.
 *
 * @param config `nodes` is always required. `verifier` is required for every auth
 *   mode except `{jwt}`; `identity` is required for `{redemptionToken}` and
 *   `{vpJwt}`. Both are validated when `openSession` runs.
 * @returns a client whose sessions you open per slot
 * @throws {Error} if `nodes` is empty
 *
 * @example
 * ```ts
 * const kk = createTasraClient({
 *   nodes: ['https://node-1', 'https://node-2', 'https://node-3'],
 *   verifier: 'https://verifier',
 *   identity: 'did:example:alice',
 * })
 *
 * const s = await kk.openSession(slotId, {renewalToken})
 * const env = s.encrypt(new TextEncoder().encode('only slot members can read this'))
 * const msg = await s.decrypt(env)      // assembles the key on first use
 * const sig = await s.sign(messageBytes)
 * await s.close()                       // zeroizes the assembled key
 * ```
 *
 * @see {@link SessionAuth} for the four ways to authorize a session — only
 *   `{renewalToken}` silently auto-renews; the others fail loud on expiry.
 */
export function createTasraClient(
  config: TasraClientConfig,
): TasraClient {
  if (!config.nodes || config.nodes.length === 0) {
    throw new Error('createTasraClient: at least one node URL is required')
  }
  const open = new Set<Session>()
  const frozen = Object.freeze({...config})

  return {
    config: frozen,
    async openSession(slotId, auth, opts) {
      const resolved = await resolveAuth(auth, frozen.verifier, frozen.identity)
      const {mpkBytes, epoch} = await fetchMpk(frozen.nodes[0]!, slotId)
      const slotIdBytes = hexToBytes(slotId)
      const session = newSession({
        slotId,
        slotIdBytes,
        nodes: frozen.nodes,
        verifier: frozen.verifier,
        jwt: resolved.jwt,
        holder: resolved.holder,
        renewalToken: resolved.renewalToken,
        mpkBytes,
        // Assembled lazily on the first decrypt — sign/encrypt need no shard fetch.
        msk: null,
        epoch,
        identity: opts?.identity ?? slotIdBytes,
        skewMs: opts?.skewMs ?? 30_000,
        onClose: s => open.delete(s),
      })
      open.add(session)
      return session
    },
    sessions() {
      return [...open]
    },
    async closeAll() {
      await Promise.all([...open].map(s => s.close()))
    },
  }
}
