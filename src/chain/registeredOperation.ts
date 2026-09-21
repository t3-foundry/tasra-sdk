import {hexToBytes} from '../crypto/hex.js'
import {presentationOperationTypedData, verifierAgentResult, type OperationInput, type TypedDataSigner, type VerifierAgentResult} from '../oid4vp/verifier-agent.js'
import {decodeJson} from '../oid4vp/jose.js'
import type {VerifiedRequestObject} from '../oid4vp/request-object.js'
import type {SessionStatusResult} from '../verifier-agent/index.js'
import {derivedNonce, requestHash} from '../oid4vp/binding.js'
import {VerifierAgentSessionError, nextPollDelay, type PresentationDelegation, type PresentationOperation, type WaitOpts} from '../verifier-agent/index.js'
import {type RegisteredAgentSession, type createRegisteredAgentClient} from './registeredAgent.js'

export interface RegisteredVerifierAgentSession extends RegisteredAgentSession {
  readonly operation: PresentationOperation
  readonly requestHash: Uint8Array
  readonly verifierAgentUrl: string
}

/** Sign once, authenticate an explicitly approved provider, and retain its pinned poll closure. */
export async function openRegisteredVerifierAgentSession(
  client: ReturnType<typeof createRegisteredAgentClient>,
  opts: OperationInput & {signer: TypedDataSigner; delegation?: PresentationDelegation; profileIndex?: number; signal?: AbortSignal},
): Promise<RegisteredVerifierAgentSession> {
  opts.signal?.throwIfAborted()
  const {typedData, operation, messageHex, payloadDigest} = presentationOperationTypedData(opts)
  const operationSig = await opts.signer.signTypedData(typedData)
  opts.signal?.throwIfAborted()
  const session = await client.createSession({operation, operationSig, messageHex, delegation: opts.delegation}, {profileIndex: opts.profileIndex, signal: opts.signal})
  const slot = typeof opts.slotId === 'string' ? hexToBytes(opts.slotId) : opts.slotId
  const expectedHash = requestHash(opts.chainId, slot, opts.action, payloadDigest)
  return Object.freeze({...session, operation: Object.freeze(operation), verifierAgentUrl: session.profile.endpoint,
    get requestHash() { return expectedHash.slice() },
  })
}

/** Poll the original authenticated session only; no URL reconstruction or provider failover. */
export async function awaitRegisteredVerifierAgentResult(
  session: RegisteredVerifierAgentSession,
  opts: {intervalMs?: number; timeoutMs?: number} & WaitOpts = {},
): Promise<VerifierAgentResult> {
  const interval = opts.intervalMs ?? 2000, timeout = opts.timeoutMs ?? 300_000
  const max = opts.maxIntervalMs ?? interval * 4
  if (![interval, timeout, max].every(n => Number.isSafeInteger(n) && n > 0 && n <= 2_147_483_647) || max < interval) throw new Error('Invalid polling interval or timeout')
  const controller = new AbortController()
  const cancelled = () => controller.abort(new VerifierAgentSessionError('cancelled', session.sessionId, 'polling cancelled'))
  opts.signal?.addEventListener('abort', cancelled, {once: true})
  if (opts.signal?.aborted) cancelled()
  const timer = setTimeout(() => controller.abort(new VerifierAgentSessionError('timeout', session.sessionId, `still pending after ${timeout} ms`)), timeout)
  let delay = 0
  let onAbort = () => {}
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(controller.signal.reason)
    controller.signal.addEventListener('abort', onAbort, {once: true})
  })
  try {
    controller.signal.throwIfAborted()
    return await Promise.race([(async () => {
      for (;;) {
        controller.signal.throwIfAborted()
        // Identity and policy failures propagate immediately; never disclose a bearer to another provider.
        const result = await session.poll(controller.signal)
        controller.signal.throwIfAborted()
        opts.onPhase?.(result.phase)
        if (result.status !== 'pending') return verifierAgentResult(session, result)
        delay = nextPollDelay(delay, interval, max, opts.random)
        await new Promise<void>(resolve => {
          const done = () => { clearTimeout(wait); controller.signal.removeEventListener('abort', done); resolve() }
          const wait = setTimeout(done, delay)
          controller.signal.addEventListener('abort', done, {once: true})
          if (controller.signal.aborted) done()
        })
      }
    })(), aborted])
  } finally {
    clearTimeout(timer)
    controller.signal.removeEventListener('abort', onAbort)
    opts.signal?.removeEventListener('abort', cancelled)
    controller.abort()
  }
}

/** Bind the wallet's signed request to the operation and authenticated session before disclosure. */
export function assertRegisteredWalletRequest(session: RegisteredVerifierAgentSession, ro: VerifiedRequestObject, status: SessionStatusResult): void {
  const claims = ro.claims, op = session.operation, binding = status.bindingPreimage
  if (status.status === 'failed') throw new VerifierAgentSessionError('refused', session.sessionId, status.error ?? 'Session failed')
  if (!binding || claims.client_id !== session.profile.clientId || claims.response_uri !== session.profile.endpoint + '/v1/response?session=' + session.sessionId ||
      claims.response_mode !== 'direct_post.jwt' || ro.signerDid !== session.profile.clientId.replace(/^decentralized_identifier:/, '')) throw new Error('Wallet request is outside the approved session')
  const signedOperation = binding.operation as Record<string, unknown> | undefined
  if (!signedOperation || Object.entries(op).some(([k, v]) => signedOperation[k] !== v)) throw new Error('Wallet operation differs from the creator authorization')
  const integer = (key: string): number => {
    const value = binding[key]
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new Error('Invalid wallet nonce context')
    return value
  }
  const hex = (key: string) => {
    const value = binding[key]
    if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/i.test(value)) throw new Error('Invalid wallet nonce hash')
    return hexToBytes(value)
  }
  const expected = derivedNonce(session.requestHash, hex('random'), {epoch: integer('epoch'), snapshotRoot: hex('snapshot_root'),
    registrySize: integer('registry_size'), committee: integer('committee_count'), quorum: integer('quorum'), operationExp: op.exp})
  if (claims.nonce !== expected || binding.nonce !== expected) throw new Error('Wallet nonce does not bind the opened operation')
  if (!Number.isSafeInteger(claims.exp) || Number(claims.exp) > op.exp || Number(claims.exp) < Math.floor(Date.now() / 1000)) throw new Error('Wallet request expiry exceeds its authorization')
  if (!Array.isArray(claims.transaction_data) || claims.transaction_data.length !== 1) throw new Error('Wallet request has no unique transaction data')
  const td = decodeJson<Record<string, unknown>>(claims.transaction_data[0]!)
  if (td.type !== 'keykeeper-op/v1' || ['chain_id', 'slot_id', 'action', 'payload_digest', 'description'].some(k => td[k] !== op[k as keyof PresentationOperation])) throw new Error('Wallet transaction data differs from the creator authorization')
}
