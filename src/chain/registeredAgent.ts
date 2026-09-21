import {authenticateApprovedService, validateServiceEndpoint, type ServiceDiscoveryTransport} from './serviceIdentity.js'
import type {TasraChainClient} from './client.js'
import type {ServiceApproval, ServiceRecord} from './services.js'
import {parseVerifierAgentSessionStatus, type CreateSessionParams, type CreateSessionResult, type SessionStatusResult} from '../verifier-agent/index.js'

export interface AgentTransport extends ServiceDiscoveryTransport {
  /** Same socket/TLS policy as discovery; bearer is allowed only on a session GET. */
  agentRequest(url: string, options: {body?: Uint8Array; bearer?: string; maxBytes: number; signal: AbortSignal}): Promise<Uint8Array>
}

/** Both the application and committee verifiers must independently approve this verifier-agent identity. */
export interface ApprovedAgentProfile {
  approval: ServiceApproval
  endpoint: string
  clientId: string
}

export interface RegisteredAgentSession extends Readonly<CreateSessionResult> {
  readonly profile: Readonly<ApprovedAgentProfile>
  /** Poll only the original endpoint/profile. A provider change requires a fresh wallet session. */
  poll(signal?: AbortSignal): Promise<SessionStatusResult>
}

export class AgentSessionCreationUnknownError extends Error {
  constructor(readonly profile: Readonly<ApprovedAgentProfile>) {
    super('Agent session creation has an uncertain result; explicitly open a fresh wallet session to retry. No session secret or presentation is transferred.')
    this.name = 'AgentSessionCreationUnknownError'
  }
}

function decode(bytes: Uint8Array, limit: number): Record<string, unknown> {
  if (bytes.length > limit) throw new Error('Agent response too large')
  const value: unknown = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes))
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid agent reply')
  return value as Record<string, unknown>
}

async function bounded<T>(signal: AbortSignal | undefined, work: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController()
  const combined = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal
  const timer = setTimeout(() => controller.abort(new Error('Agent request timed out')), 60_000)
  let abort = () => {}
  try {
    combined.throwIfAborted()
    return await Promise.race([work(combined), new Promise<never>((_, reject) => {
      abort = () => reject(combined.reason)
      combined.addEventListener('abort', abort, {once: true})
    })])
  } finally { clearTimeout(timer); combined.removeEventListener('abort', abort); controller.abort() }
}

function pin(profile: ApprovedAgentProfile, record: ServiceRecord) {
  const a = profile.approval
  return {chainId: a.chainId, registry: a.registry.toLowerCase(), serviceId: a.serviceId.toLowerCase(), serviceType: 1,
    owner: a.owner.toLowerCase(), revision: a.revision.toString(), manifestHash: a.manifestHash.toLowerCase(),
    authKey: record.authKey.toLowerCase(), endpoint: profile.endpoint, clientId: profile.clientId}
}

function equalPin(actual: unknown, expected: ReturnType<typeof pin>): boolean {
  if (!actual || typeof actual !== 'object') return false
  return Object.entries(expected).every(([key, value]) => (actual as Record<string, unknown>)[key] === value)
}

/** Selection authenticates public metadata first. Once POSTed, never silently switch providers. */
export function createRegisteredAgentClient(chain: TasraChainClient, config: {profiles: readonly ApprovedAgentProfile[]; transport: AgentTransport}) {
  if (!Array.isArray(config.profiles) || !config.profiles.length || config.profiles.length > 16 || typeof config.transport?.agentRequest !== 'function' || typeof config.transport.request !== 'function') throw new Error('Approved agent profiles and a guarded transport are required')
  const profiles = config.profiles.map(p => {
    validateServiceEndpoint(p.endpoint)
    if (p.approval.serviceType !== 1 || !/^decentralized_identifier:did:web:[a-z0-9.-]+(?:(?:%3A)[0-9]+)?$/.test(p.clientId)) throw new Error('Invalid verifier-agent profile')
    return Object.freeze({...p, approval: Object.freeze({...p.approval})})
  })
  const transport = config.transport
  return {
    /** At most three discovery candidates; optional index explicitly starts a new independent session. */
    async createSession(params: CreateSessionParams, options: {profileIndex?: number; signal?: AbortSignal} = {}): Promise<RegisteredAgentSession> {
      const start = options.profileIndex ?? 0
      if (!Number.isInteger(start) || start < 0 || start >= profiles.length) throw new Error('Invalid agent profile index')
      return bounded(options.signal, async signal => {
        for (const profile of profiles.slice(start, start + 3)) {
          let record: ServiceRecord
          try {
            const result = await authenticateApprovedService(chain, profile.approval, {
              request: (url, opts) => transport.request(url, {...opts, signal: AbortSignal.any([signal, opts.signal])}),
            })
            signal.throwIfAborted()
            if (result.record.endpoint !== profile.endpoint || !result.manifest.capabilities.includes('oid4vp')) throw new Error('Agent endpoint/capability approval mismatch')
            record = result.record
          } catch { signal.throwIfAborted(); continue }
          if (params.operation.chain_id !== profile.approval.chainId) throw new Error('Agent operation chain mismatch')
          const body = new TextEncoder().encode(JSON.stringify({operation: params.operation, operation_sig: params.operationSig, delegation: params.delegation, message_hex: params.messageHex}))
          if (body.length > 65_536) throw new Error('Agent session request too large')
          signal.throwIfAborted()
          let data: Record<string, unknown>
          try { data = decode(await transport.agentRequest(profile.endpoint + '/v1/sessions', {body, maxBytes: 32_768, signal}), 32_768) }
          catch { throw new AgentSessionCreationUnknownError(profile) }
          const expected = pin(profile, record)
          if (!equalPin(data.service_profile, expected) || typeof data.session_id !== 'string' || !/^[0-9a-f]{64}$/.test(data.session_id)
            || typeof data.poll_secret !== 'string' || !/^[0-9a-f]{64}$/.test(data.poll_secret)) throw new Error('Agent session profile or identifiers mismatch')
          const sessionId = data.session_id, pollSecret = data.poll_secret
          const requestUri = `${profile.endpoint}/v1/request/${sessionId}`
          if (data.request_uri !== requestUri || typeof data.qr_payload !== 'string' || !data.qr_payload.startsWith('openid4vp://?')) throw new Error('Agent wallet request destination mismatch')
          const qr = new URL(data.qr_payload)
          if (qr.searchParams.get('client_id') !== profile.clientId || qr.searchParams.get('request_uri') !== requestUri || [...qr.searchParams.keys()].length !== 2) throw new Error('Agent wallet audience or request URI mismatch')
          // Closure-owned routing and secret prevent a caller's mutable session object from
          // redirecting a bearer. Replicas sit behind this ONE approved base endpoint.
          return Object.freeze({sessionId, pollSecret, requestUri, qrPayload: data.qr_payload, profile,
            poll: (pollSignal?: AbortSignal) => bounded(pollSignal, async activeSignal => {
              const a = profile.approval
              if (chain.addresses.ServiceRegistry?.toLowerCase() !== a.registry.toLowerCase() || await chain.client.getChainId() !== a.chainId) throw new Error('Agent session chain/registry changed')
              activeSignal.throwIfAborted()
              const block = await chain.client.getBlockNumber({cacheTime: 0})
              activeSignal.throwIfAborted()
              const current = await chain.readers.serviceRegistry.getService(a.serviceId, block)
              activeSignal.throwIfAborted()
              if (current.status > 1 || current.revision < a.revision || current.serviceType !== 1
                || current.owner.toLowerCase() !== record.owner.toLowerCase() || current.authKey.toLowerCase() !== record.authKey.toLowerCase()
                || current.pendingOwner.toLowerCase() !== record.pendingOwner.toLowerCase() || current.manifestHash.toLowerCase() !== a.manifestHash.toLowerCase()
                || current.endpoint !== profile.endpoint) throw new Error('Agent session profile changed; open a fresh wallet session')
              const reply = decode(await transport.agentRequest(`${profile.endpoint}/v1/sessions/${sessionId}`, {bearer: pollSecret, maxBytes: 1_048_576, signal: activeSignal}), 1_048_576)
              if (!(reply.status === 'failed' && reply.binding_preimage == null && reply.compound_token == null) && !equalPin((reply.binding_preimage as Record<string, unknown> | null)?.service_profile, expected)) throw new Error('Agent result belongs to another session profile')
              return parseVerifierAgentSessionStatus(reply, sessionId)
            }),
          })
        }
        throw new Error('No approved verifier-agent authenticated')
      })
    },
  }
}
