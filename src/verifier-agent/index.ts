// Verifier Agent client — creates OID4VP sessions on the platform verifier-agent and
// polls for the compound token result.
//
// Usage:
//   const session = await createOid4vpSession(verifierAgentUrl, {
//     operation: { chain_id, slot_id, action, payload_digest, description, exp },
//     operationSig: '0x...',
//     messageHex: '0x...',
//   })
//   // ... wallet scans session.qrPayload ...
//   const result = await pollOid4vpSession(verifierAgentUrl, session.sessionId, session.pollSecret)
//   // result.compoundToken + result.bindingPreimage → committeeSign()

import {sha256} from '@noble/hashes/sha256'
import {bytesToHex} from '@noble/hashes/utils'
import {TasraError} from '../errors.js'

/** The operation the holder is authorizing — signed by the creator's EIP-712 key. */
import type {DpopSigner} from '../auth/dpop.js'

export interface PresentationOperation {
  chain_id: number
  /** 0x-hex 32-byte slot identifier */
  slot_id: string
  /** "sign" | "decrypt" | "ibe-extract" | "dual-approve" */
  action: string
  /** 0x-hex 32-byte digest (sha256 of the message for sign/ibe-extract) */
  payload_digest: string
  /** Human-readable description shown in transaction_data */
  description: string
  /** Unix timestamp — when the authorization expires */
  exp: number
}

/** EIP-712 delegation from the slot creator to a delegate address. */
export interface PresentationDelegation {
  chain_id: number
  slot_ids: string[]
  /** 0x-hex 20-byte delegate address */
  delegate: string
  actions: string[]
  exp: number
  nonce: number
  /** 0x-hex 65-byte EIP-712 signature */
  signature: string
}

export interface CreateSessionParams {
  operation: PresentationOperation
  /** 0x-hex 65-byte EIP-712 signature over the operation */
  operationSig: string
  /** Optional EIP-712 delegation from the slot creator */
  delegation?: PresentationDelegation
  /** The raw payload as 0x-hex */
  messageHex: string
}

export interface CreateSessionResult {
  sessionId: string
  /** Bearer token for polling — treat as a secret */
  pollSecret: string
  qrPayload: string
  requestUri: string
}

/** an `oauth` session — the client brings a DPoP-bound access token. */
export interface CreateOauthSessionResult {
  sessionId: string
  /** Treat as a secret. Rides `X-Poll-Secret` on the response endpoint, `Authorization:
   *  Bearer` when polling — DPoP owns `Authorization` on the response endpoint. */
  pollSecret: string
  /** The nonce the DPoP proof must carry. Returned so a client that can mint a proof
   *  directly needs no RFC 9449 challenge round trip. */
  nonce: string
  /** The `htu` the DPoP proof must name. Session-INDEPENDENT by RFC 9449 (`htu` excludes
   *  query and fragment), which is why any conformant client library derives the same
   *  string from the URL it is about to call. */
  dpopHtu: string
  /** The `aud` the tenant must have registered with its IdP for tokens minted for this
   *  platform. A token whose `aud` does not contain it is refused by every drawn verifier,
   *  and that is the single most common onboarding mistake — surfaced so a client can say
   *  so instead of showing a bare 400. */
  platformAudience: string
}

/** What the client may show while `status` is `pending` (gap-closure P6): never a secret,
 *  never a promise — `done` means the committee answered, not that the operation ran. */
export type SessionPhase = 'awaiting_wallet' | 'verifying' | 'done' | 'failed'

export interface SessionStatusResult {
  status: 'pending' | 'done' | 'failed'
  phase: SessionPhase
  compoundToken?: Record<string, unknown>
  verifierProofs?: unknown
  bindingPreimage?: Record<string, unknown>
  error?: string
}

/** Why a session did not yield a token — the class the UI explains, with a NON-SECRET
 *  correlation reference (the session id; the poll secret is never part of an error). */
export type VerifierAgentSessionErrorKind =
  /** The deadline passed while the verifier-agent still reported `pending`. */
  | 'timeout'
  /** The verifier-agent reported `failed`: a verifier or the wallet refused (`error` says which). */
  | 'refused'
  /** The verifier-agent (or its store) could not answer — retry later, the session may still complete. */
  | 'unavailable'
  /** The verifier-agent answered something the contract does not allow (a malformed reply, 401/404). */
  | 'protocol'
  /** The caller's `AbortSignal` fired. */
  | 'cancelled'

/**
 * A Verifier Agent session did not produce a compound token. `kind` says why;
 * `retryable` is true only for `timeout` and `unavailable` — the session may
 * still complete, so poll again. Extends {@link TasraError}.
 */
export class VerifierAgentSessionError extends TasraError {
  readonly kind: VerifierAgentSessionErrorKind
  /** The session id — safe to show and to log. */
  readonly correlation: string
  /** The HTTP status that produced a `protocol`/`unavailable` error, when there was one. */
  readonly httpStatus?: number
  constructor(kind: VerifierAgentSessionErrorKind, correlation: string, message: string, httpStatus?: number) {
    super(`${message} (session ${correlation.slice(0, 12)}…)`, {
      retryable: kind === 'timeout' || kind === 'unavailable',
    })
    this.kind = kind
    this.correlation = correlation
    this.httpStatus = httpStatus
  }
}

const PHASES: ReadonlySet<string> = new Set(['awaiting_wallet', 'verifying', 'done', 'failed'])
const STATUSES: ReadonlySet<string> = new Set(['pending', 'done', 'failed'])
const HEX32 = /^0x[0-9a-f]{64}$/i

/** The compound token the verifier-agent hands back must be the wire shape the keepers verify —
 *  checked field by field before anything is built on it. */
export function assertCompoundTokenWire(raw: unknown, correlation: string): Record<string, unknown> {
  const bad: (why: string) => never = (why) => {
    throw new VerifierAgentSessionError('protocol', correlation, `compound_token: ${why}`)
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) bad('not an object')
  const t = {...raw as Record<string, unknown>}
  // Reference-side optional fields are serialized as null for non-IBE operations. Normalize
  // absence before consumers decode the token; never replace it with a zero hash.
  for (const key of ['identity_hash', 'request_hash'] as const) if (t[key] === null) delete t[key]
  for (const k of ['seed', 'slot_id', 'vp_hash', 'holder_hash', 'rule_hash'] as const) {
    if (typeof t[k] !== 'string' || !HEX32.test(t[k] as string)) bad(`${k} is not a 32-byte hex string`)
  }
  if (typeof t.token_type !== 'string') bad('token_type missing')
  for (const k of ['epoch', 'iat', 'exp'] as const) {
    if (typeof t[k] !== 'number' || !Number.isFinite(t[k] as number)) bad(`${k} is not a number`)
  }
  if ((t.exp as number) <= (t.iat as number)) bad('exp is not after iat')
  if (t.request_hash !== undefined && (typeof t.request_hash !== 'string' || !HEX32.test(t.request_hash))) bad('request_hash is not a 32-byte hex string')
  if (t.identity_hash !== undefined && (typeof t.identity_hash !== 'string' || !HEX32.test(t.identity_hash))) bad('identity_hash is not a 32-byte hex string')
  if (t.binding !== undefined && !['unbound', 'holder_key', 'issuer_asserted'].includes(t.binding as string)) bad('binding is not a known strength')
  if (!Array.isArray(t.verifier_indexes) || !t.verifier_indexes.every(i => Number.isInteger(i) && (i as number) >= 0)) bad('verifier_indexes is not an index list')
  if (!Array.isArray(t.signatures) || t.signatures.length === 0) bad('signatures missing')
  for (const sig of t.signatures as unknown[]) {
    const sg = sig as Record<string, unknown> | null
    if (!sg || typeof sg !== 'object' || !Number.isInteger(sg.verifier_index) || typeof sg.signature !== 'string') bad('a signature entry is not {verifier_index, signature}')
    if (!(t.verifier_indexes as number[]).includes(sg.verifier_index as number)) bad('a signature names an index outside the committee')
  }
  return t
}

/**
 * Compute the `payload_digest` for a given action and message.
 *
 * For `sign` and `ibe-extract`, this is `sha256(message_bytes)` as 0x-hex.
 * Other actions should supply the digest directly.
 */
export function payloadDigest(action: string, messageHex: string): string {
  const clean = messageHex.replace(/^0x/, '')
  const messageBytes = new Uint8Array(
    clean.match(/.{1,2}/g)?.map((b) => parseInt(b, 16)) ?? [],
  )
  if (action === 'sign' || action === 'ibe-extract') {
    return '0x' + bytesToHex(sha256(messageBytes))
  }
  throw new Error(
    `payloadDigest not implemented for action "${action}" — supply it directly`,
  )
}

/**
 * Create an OID4VP session on the Verifier Agent.
 *
 * The verifier-agent derives a nonce, generates an ECDH key for JWE, and returns a QR
 * payload the wallet scans. The session ID and poll secret are used to poll
 * for the result.
 */
export async function createOid4vpSession(
  verifierAgentUrl: string,
  params: CreateSessionParams,
): Promise<CreateSessionResult> {
  const url = `${verifierAgentUrl.replace(/\/$/, '')}/v1/sessions`
  const resp = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      operation: params.operation,
      operation_sig: params.operationSig,
      delegation: params.delegation,
      message_hex: params.messageHex,
    }),
  })
  if (!resp.ok) {
    const body = await resp.text()
    throw new Error(`createOid4vpSession failed (${resp.status}): ${body}`)
  }
  const data = (await resp.json()) as Record<string, unknown>
  for (const k of ['session_id', 'poll_secret', 'qr_payload', 'request_uri'] as const) {
    if (typeof data[k] !== 'string' || !(data[k] as string)) throw new Error(`createOid4vpSession: reply lacks ${k}`)
  }
  if (!(data.qr_payload as string).startsWith('openid4vp://')) throw new Error('createOid4vpSession: qr_payload is not an openid4vp:// request')
  return {
    sessionId: data.session_id as string,
    pollSecret: data.poll_secret as string,
    qrPayload: data.qr_payload as string,
    requestUri: data.request_uri as string,
  }
}

/**
 * Open an `oauth` session — same creator authorisation, same committee draw, same
 * derived nonce, same poll contract as {@link createOid4vpSession}. No QR, no Request
 * Object, no JWE key: the client presents an access token its own IdP minted.
 */
export async function createOauthSession(
  verifierAgentUrl: string,
  params: CreateSessionParams,
): Promise<CreateOauthSessionResult> {
  const url = `${verifierAgentUrl.replace(/\/$/, '')}/v1/sessions`
  const resp = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      operation: params.operation,
      operation_sig: params.operationSig,
      delegation: params.delegation,
      message_hex: params.messageHex,
      kind: 'oauth',
    }),
  })
  if (!resp.ok) {
    const body = await resp.text()
    throw new Error(`createOauthSession failed (${resp.status}): ${body}`)
  }
  const data = (await resp.json()) as Record<string, unknown>
  for (const k of ['session_id', 'poll_secret', 'nonce', 'dpop_htu', 'platform_audience'] as const) {
    if (typeof data[k] !== 'string' || !(data[k] as string)) {
      throw new Error(`createOauthSession: reply lacks ${k}`)
    }
  }
  // A wallet session's reply would carry a QR. Getting one back means the agent ignored
  // `kind` — an older build — and the client would otherwise wait forever for a wallet that
  // is never coming.
  if (data.qr_payload !== undefined) {
    throw new Error(
      'createOauthSession: the agent returned a wallet session (qr_payload present) — it ' +
        'predates and does not support the oauth session kind',
    )
  }
  return {
    sessionId: data.session_id as string,
    pollSecret: data.poll_secret as string,
    nonce: data.nonce as string,
    dpopHtu: data.dpop_htu as string,
    platformAudience: data.platform_audience as string,
  }
}

/**
 * Deliver an access token + DPoP proof to an `oauth` session.
 *
 * Speaks the RFC 9449 §9 resource-server contract — token in `Authorization: DPoP`, proof in
 * `DPoP:` — so a conformant client library needs no custom code. It also handles the
 * `use_dpop_nonce` challenge ITSELF: on a `401` carrying `DPoP-Nonce`, it re-mints the proof
 * with the server's nonce and resends ONCE. One retry, not a loop: a server that keeps
 * challenging is broken, and retrying forever would hide that.
 *
 * `signer` must be the key the token is bound to — see `../auth/dpop.js` for the two shapes.
 */
export async function submitOauthResponse(
  verifierAgentUrl: string,
  args: {
    sessionId: string
    pollSecret: string
    accessToken: string
    /** From {@link createOauthSession}. */
    nonce: string
    dpopHtu: string
    signer: DpopSigner
  },
): Promise<void> {
  const base = verifierAgentUrl.replace(/\/$/, '')
  const url = `${base}/v1/sessions/${encodeURIComponent(args.sessionId)}/oauth-response`

  const send = async (nonce: string): Promise<Response> => {
    const proof = await args.signer.proof({
      htm: 'POST',
      htu: args.dpopHtu,
      nonce,
      accessToken: args.accessToken,
    })
    return fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `DPoP ${args.accessToken}`,
        DPoP: proof,
        'X-Poll-Secret': args.pollSecret,
      },
    })
  }

  let resp = await send(args.nonce)
  if (resp.status === 401) {
    const challenge = resp.headers.get('dpop-nonce')
    const wantsNonce = (resp.headers.get('www-authenticate') ?? '').includes('use_dpop_nonce')
    if (challenge && wantsNonce) {
      resp = await send(challenge)
    }
  }
  if (!resp.ok) {
    const body = await resp.text()
    throw new Error(`submitOauthResponse failed (${resp.status}): ${body}`)
  }
}

/**
 * Poll an OID4VP session on the Verifier Agent for its result — ONE poll.
 *
 * The reply is validated against the contract: `status` ∈ {pending, done, failed}, a
 * `phase` the UI may show, and, when done, a well-formed compound token. The poll secret
 * travels only in the `Authorization` header and never appears in an error.
 *
 * Throws `VerifierAgentSessionError`: `unavailable` for 502/503/504 (the session may still complete —
 * `waitForSession` keeps polling), `protocol` for any other non-2xx or a malformed reply.
 */
export async function pollOid4vpSession(
  verifierAgentUrl: string,
  sessionId: string,
  pollSecret: string,
): Promise<SessionStatusResult> {
  const url = `${verifierAgentUrl.replace(/\/$/, '')}/v1/sessions/${encodeURIComponent(sessionId)}`
  let resp: Response
  try {
    resp = await fetch(url, {headers: {'Authorization': `Bearer ${pollSecret}`}})
  } catch (e) {
    throw new VerifierAgentSessionError('unavailable', sessionId, `poll: ${e instanceof Error ? e.message : String(e)}`)
  }
  if (!resp.ok) {
    const body = (await resp.text()).slice(0, 300)
    const kind: VerifierAgentSessionErrorKind = resp.status === 502 || resp.status === 503 || resp.status === 504 ? 'unavailable' : 'protocol'
    throw new VerifierAgentSessionError(kind, sessionId, `poll: HTTP ${resp.status}${body ? `: ${body}` : ''}`, resp.status)
  }
  let data: Record<string, unknown>
  try {
    data = (await resp.json()) as Record<string, unknown>
  } catch {
    throw new VerifierAgentSessionError('protocol', sessionId, 'poll: reply is not JSON')
  }
  return parseVerifierAgentSessionStatus(data, sessionId)
}

/** Shared validation for the explicit-URL and registered-agent transports. */
export function parseVerifierAgentSessionStatus(data: Record<string, unknown>, sessionId: string): SessionStatusResult {
  if (typeof data.status !== 'string' || !STATUSES.has(data.status)) throw new VerifierAgentSessionError('protocol', sessionId, `poll: status ${JSON.stringify(data.status)} is not pending | done | failed`)
  const status = data.status as SessionStatusResult['status']
  const phase: SessionPhase = typeof data.phase === 'string' && PHASES.has(data.phase)
    ? (data.phase as SessionPhase)
    : status === 'pending' ? 'awaiting_wallet' : status
  if ((status === 'done') !== (phase === 'done') || (status === 'failed') !== (phase === 'failed')) throw new VerifierAgentSessionError('protocol', sessionId, `poll: phase ${phase} contradicts status ${status}`)
  if (status === 'done') data.compound_token = assertCompoundTokenWire(data.compound_token, sessionId)
  // Absent optional fields arrive as JSON `null` from the verifier-agent (serde `Option`): null = absent.
  if (data.error != null && typeof data.error !== 'string') throw new VerifierAgentSessionError('protocol', sessionId, 'poll: error is not a string')
  return {
    status,
    phase,
    compoundToken: (data.compound_token ?? undefined) as Record<string, unknown> | undefined,
    verifierProofs: data.verifier_proofs ?? undefined,
    bindingPreimage: (data.binding_preimage ?? undefined) as Record<string, unknown> | undefined,
    error: (data.error ?? undefined) as string | undefined,
  }
}

export interface WaitOpts {
  /** Ceiling for the growing interval (default 4 × intervalMs). */
  maxIntervalMs?: number
  /** Cancel (a user closed the wallet prompt): rejects with `cancelled`. */
  signal?: AbortSignal
  /** Called on every poll with the phase the UI may show. */
  onPhase?: (phase: SessionPhase) => void
  /** Randomness for the jitter (tests inject a fixed value). */
  random?: () => number
}

/** The next polling delay: geometric growth (×1.5) capped at `max`, ±20 % full jitter.
 *  Pure, so the schedule is testable without timers. */
export function nextPollDelay(previousMs: number, baseMs: number, maxMs: number, random: () => number = Math.random): number {
  const grown = previousMs <= 0 ? baseMs : Math.min(maxMs, previousMs * 1.5)
  const jitter = (random() * 2 - 1) * 0.2 * grown
  return Math.max(1, Math.round(grown + jitter))
}

/**
 * Poll until the session reaches a terminal state (done or failed) — bounded by
 * `timeoutMs`, with a growing jittered interval so many clients never poll in lock-step.
 * A transient `unavailable` answer (a 503, a dropped connection) is retried within the
 * deadline; a `protocol` answer stops at once; the deadline is a `timeout` error; the
 * caller's `signal` is a `cancelled` error. A terminal `failed` is RETURNED (the caller
 * decides how to explain it) — see `awaitVerifierAgentResult` for the version that throws `refused`.
 *
 * @param pollSecret - bearer token returned by `createOid4vpSession`
 * @param intervalMs - initial polling interval in milliseconds (default 2000)
 * @param timeoutMs - total deadline in milliseconds (default 300000 = 5 min)
 */
export async function waitForSession(
  verifierAgentUrl: string,
  sessionId: string,
  pollSecret: string,
  intervalMs = 2000,
  timeoutMs = 300_000,
  opts: WaitOpts = {},
): Promise<SessionStatusResult> {
  const deadline = Date.now() + timeoutMs
  const max = opts.maxIntervalMs ?? intervalMs * 4
  let delay = 0
  let lastUnavailable: VerifierAgentSessionError | undefined
  while (true) {
    if (opts.signal?.aborted) throw new VerifierAgentSessionError('cancelled', sessionId, 'polling cancelled')
    if (Date.now() >= deadline) {
      throw new VerifierAgentSessionError('timeout', sessionId, lastUnavailable ? `no answer within ${timeoutMs} ms (last: ${lastUnavailable.message})` : `still pending after ${timeoutMs} ms`)
    }
    try {
      const result = await pollOid4vpSession(verifierAgentUrl, sessionId, pollSecret)
      opts.onPhase?.(result.phase)
      if (result.status !== 'pending') return result
      lastUnavailable = undefined
    } catch (e) {
      if (e instanceof VerifierAgentSessionError && e.kind === 'unavailable') {
        lastUnavailable = e
      } else {
        throw e
      }
    }
    delay = nextPollDelay(delay, intervalMs, max, opts.random)
    const remaining = deadline - Date.now()
    if (remaining <= 0) continue
    await new Promise<void>((resolve) => {
      const t = setTimeout(() => { opts.signal?.removeEventListener('abort', onAbort); resolve() }, Math.min(delay, remaining))
      const onAbort = () => { clearTimeout(t); resolve() }
      opts.signal?.addEventListener('abort', onAbort, {once: true})
    })
  }
}
