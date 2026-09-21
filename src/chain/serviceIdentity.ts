import {hashTypedData, recoverAddress, type Address, type Hex} from 'viem'
import {hashServiceManifest, readApprovedServiceRecord, type ServiceApproval, type ServiceRecord, type ServiceType} from './services.js'
import type {TasraChainClient} from './client.js'

export const SERVICE_MANIFEST_PATH = '/.well-known/keykeeper-service.json'
export const SERVICE_IDENTITY_PATH = '/v1/service/identity'
export const SERVICE_MANIFEST_MAX_BYTES = 16_384
export const SERVICE_IDENTITY_MAX_BYTES = 2_048
export const SERVICE_CHALLENGE_SECONDS = 30
// Leave five seconds inside the responder acceptance window for ordinary clock differences.
export const SERVICE_CHALLENGE_LIFETIME_SECONDS = 25
export const SERVICE_IDENTITY_PROTOCOL = 'keykeeper-service-identity-v1'

export interface ServiceManifest {
  schemaVersion: 1
  chainId: number
  registry: Address
  serviceId: Hex
  serviceType: ServiceType
  endpoint: string
  protocol: typeof SERVICE_IDENTITY_PROTOCOL
  capabilities: string[]
}

/** JSON wire shape. Revision is decimal text to preserve all uint64 values in JavaScript. */
export interface ServiceChallenge {
  version: 1
  chainId: number
  registry: Address
  serviceId: Hex
  revision: string
  endpoint: string
  manifestHash: Hex
  nonce: Hex
  expiresAt: number
}

function requireHex(value: unknown, bytes: number): asserts value is Hex {
  if (typeof value !== 'string' || !new RegExp(`^0x[0-9a-f]{${bytes * 2}}$`).test(value)) {
    throw new Error('Service identity requires lowercase fixed-width hex')
  }
}
function safeInteger(value: number): boolean { return Number.isSafeInteger(value) && value > 0 }

/** Reject aliases instead of signing a URL which another implementation normalizes differently. */
export function validateServiceEndpoint(endpoint: string): URL {
  if (endpoint.length > 512 || !/^https:\/\/[\x21-\x7e]+$/.test(endpoint) || /[%\\?#@]/.test(endpoint)) {
    throw new Error('Service endpoint must be canonical HTTPS without escapes, userinfo, query or fragment')
  }
  const url = new URL(endpoint)
  const canonical = url.origin + (url.pathname === '/' ? '' : url.pathname)
  if (canonical !== endpoint || url.pathname.endsWith('/') && url.pathname !== '/' || url.pathname.includes('//') || url.hostname.endsWith('.')) {
    throw new Error('Service endpoint is not canonical')
  }
  return url
}

/** Canonical v1 bytes: fixed field order, compact ASCII JSON, one LF. No optional/unknown fields. */
export function encodeServiceManifest(manifest: ServiceManifest): Uint8Array {
  if (manifest.schemaVersion !== 1 || !safeInteger(manifest.chainId) || ![0, 1, 2].includes(manifest.serviceType) || manifest.protocol !== SERVICE_IDENTITY_PROTOCOL) {
    throw new Error('Unsupported service manifest')
  }
  requireHex(manifest.registry, 20)
  requireHex(manifest.serviceId, 32)
  validateServiceEndpoint(manifest.endpoint)
  if (!Array.isArray(manifest.capabilities) || manifest.capabilities.length > 16 || new Set(manifest.capabilities).size !== manifest.capabilities.length || manifest.capabilities.some(c => typeof c !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(c))) {
    throw new Error('Invalid service capabilities')
  }
  const bytes = new TextEncoder().encode(JSON.stringify({
    schemaVersion: manifest.schemaVersion, chainId: manifest.chainId, registry: manifest.registry,
    serviceId: manifest.serviceId, serviceType: manifest.serviceType, endpoint: manifest.endpoint,
    protocol: manifest.protocol, capabilities: manifest.capabilities,
  }) + '\n')
  if (bytes.length > SERVICE_MANIFEST_MAX_BYTES) throw new Error('Service manifest too large')
  return bytes
}

export function verifyServiceManifest(bytes: Uint8Array, approval: ServiceApproval, record: ServiceRecord): ServiceManifest {
  if (bytes.length > SERVICE_MANIFEST_MAX_BYTES || hashServiceManifest(bytes).toLowerCase() !== approval.manifestHash.toLowerCase() || record.manifestHash.toLowerCase() !== approval.manifestHash.toLowerCase()) {
    throw new Error('Service manifest hash mismatch or size exceeded')
  }
  const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes)
  const manifest = JSON.parse(text) as ServiceManifest
  const canonical = encodeServiceManifest(manifest)
  if (canonical.length !== bytes.length || canonical.some((byte, i) => bytes[i] !== byte)) throw new Error('Noncanonical service manifest')
  if (manifest.chainId !== approval.chainId || manifest.registry !== approval.registry.toLowerCase() || manifest.serviceId !== approval.serviceId.toLowerCase() || manifest.serviceType !== approval.serviceType || manifest.endpoint !== record.endpoint) {
    throw new Error('Service manifest profile mismatch')
  }
  return manifest
}

export function serviceChallengeTypedData(challenge: ServiceChallenge) {
  requireHex(challenge.registry, 20)
  requireHex(challenge.serviceId, 32)
  requireHex(challenge.manifestHash, 32)
  requireHex(challenge.nonce, 32)
  validateServiceEndpoint(challenge.endpoint)
  if (challenge.version !== 1 || !safeInteger(challenge.chainId) || !safeInteger(challenge.expiresAt) || typeof challenge.revision !== 'string' || !/^[1-9][0-9]{0,19}$/.test(challenge.revision) || BigInt(challenge.revision) > (1n << 64n) - 1n) {
    throw new Error('Invalid service challenge')
  }
  return {
    domain: {name: 'Keykeeper Service Identity', version: '1', chainId: challenge.chainId, verifyingContract: challenge.registry},
    primaryType: 'ServiceIdentity' as const,
    types: {ServiceIdentity: [
      {name: 'serviceId', type: 'bytes32'}, {name: 'revision', type: 'uint64'},
      {name: 'endpoint', type: 'string'}, {name: 'manifestHash', type: 'bytes32'},
      {name: 'nonce', type: 'bytes32'}, {name: 'expiresAt', type: 'uint64'},
    ]},
    message: {serviceId: challenge.serviceId, revision: BigInt(challenge.revision), endpoint: challenge.endpoint,
      manifestHash: challenge.manifestHash, nonce: challenge.nonce, expiresAt: BigInt(challenge.expiresAt)},
  }
}

/** Canonical wire encoding accepted by both responder implementations. */
export function encodeServiceChallenge(challenge: ServiceChallenge): Uint8Array {
  serviceChallengeTypedData(challenge)
  const bytes = new TextEncoder().encode(JSON.stringify({
    version: challenge.version, chainId: challenge.chainId, registry: challenge.registry,
    serviceId: challenge.serviceId, revision: challenge.revision, endpoint: challenge.endpoint,
    manifestHash: challenge.manifestHash, nonce: challenge.nonce, expiresAt: challenge.expiresAt,
  }))
  if (bytes.length > SERVICE_IDENTITY_MAX_BYTES) throw new Error('Service challenge too large')
  return bytes
}

/** Call only after enforcing the same limit while receiving the HTTP body. */
export function parseServiceChallenge(bytes: Uint8Array): ServiceChallenge {
  if (bytes.length > SERVICE_IDENTITY_MAX_BYTES) throw new Error('Service challenge too large')
  const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes)
  const challenge = JSON.parse(text) as ServiceChallenge
  const canonical = encodeServiceChallenge(challenge)
  if (canonical.length !== bytes.length || canonical.some((byte, i) => bytes[i] !== byte)) throw new Error('Noncanonical service challenge')
  return challenge
}

/** Responder must validate against its own configured profile before asking its dedicated key to sign. */
export function validateServiceChallenge(challenge: ServiceChallenge, approval: ServiceApproval, endpoint: string, now: number): void {
  serviceChallengeTypedData(challenge)
  if (!Number.isSafeInteger(now) || now < 0 || challenge.expiresAt <= now || challenge.expiresAt - now > SERVICE_CHALLENGE_SECONDS) throw new Error('Service challenge expired or too far ahead')
  if (challenge.chainId !== approval.chainId || challenge.registry !== approval.registry.toLowerCase() || challenge.serviceId !== approval.serviceId.toLowerCase() || challenge.revision !== approval.revision.toString() || challenge.manifestHash !== approval.manifestHash.toLowerCase() || challenge.endpoint !== endpoint) {
    throw new Error('Service challenge profile mismatch')
  }
}

export async function verifyServiceIdentity(challenge: ServiceChallenge, signature: Hex, authKey: Address, now: number): Promise<void> {
  serviceChallengeTypedData(challenge)
  if (!Number.isSafeInteger(now) || now < 0 || challenge.expiresAt <= now || challenge.expiresAt - now > SERVICE_CHALLENGE_SECONDS) throw new Error('Service challenge expired or too far ahead')
  requireHex(signature, 65)
  // One canonical Ethereum signature encoding: low-s and v=27/28, shared with the reference implementation.
  const s = BigInt(`0x${signature.slice(66, 130)}`)
  if (s === 0n || s > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n || !['1b', '1c'].includes(signature.slice(130))) throw new Error('Noncanonical service signature')
  if ((await recoverAddress({hash: hashTypedData(serviceChallengeTypedData(challenge)), signature})).toLowerCase() !== authKey.toLowerCase()) throw new Error('Service endpoint key mismatch')
}

/** Trusted transport boundary. Implementations must enforce destination policy at connection time,
 * verified TLS, no redirects/proxies/credentials, body limits and cancellation. Use chain/node in Node.
 * Native browser fetch cannot enforce DNS policy; it is intentionally not a default implementation. */
export interface ServiceDiscoveryTransport {
  request(url: string, options: {body?: Uint8Array; maxBytes: number; signal: AbortSignal}): Promise<Uint8Array>
}
export interface AuthenticatedService {
  approval: ServiceApproval
  record: ServiceRecord
  manifest: ServiceManifest
  blockNumber: bigint
  expiresAt: number
}

/** Uncached, bounded discovery only. A result is a short-lived observation, not verifier-agent or gas authorization. */
export async function authenticateApprovedService(chain: TasraChainClient, approved: ServiceApproval, transport: ServiceDiscoveryTransport): Promise<AuthenticatedService> {
  const approval = Object.freeze({...approved})
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new Error('Service discovery timed out')), SERVICE_CHALLENGE_SECONDS * 1000)
  const expiresAt = Math.floor(Date.now() / 1000) + SERVICE_CHALLENGE_LIFETIME_SECONDS
  // RPC calls do not accept our abort signal. Race them, and stop the workflow after each await.
  const bounded = async <T>(work: Promise<T>): Promise<T> => {
    controller.signal.throwIfAborted()
    let onAbort: () => void = () => {}
    try {
      return await Promise.race([work, new Promise<never>((_, reject) => {
        onAbort = () => reject(controller.signal.reason)
        controller.signal.addEventListener('abort', onAbort, {once: true})
      })])
    } finally { controller.signal.removeEventListener('abort', onAbort) }
  }
  try {
    const first = await bounded(readApprovedServiceRecord(chain, approval))
    validateServiceEndpoint(first.record.endpoint)
    const bytes = await bounded(transport.request(first.record.endpoint + SERVICE_MANIFEST_PATH, {maxBytes: SERVICE_MANIFEST_MAX_BYTES, signal: controller.signal}))
    const manifest = verifyServiceManifest(bytes, approval, first.record)
    const nonce = `0x${Array.from(globalThis.crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('')}` as Hex
    const challenge: ServiceChallenge = {version: 1, chainId: approval.chainId, registry: approval.registry.toLowerCase() as Address,
      serviceId: approval.serviceId.toLowerCase() as Hex, revision: approval.revision.toString(), endpoint: first.record.endpoint,
      manifestHash: approval.manifestHash.toLowerCase() as Hex, nonce, expiresAt}
    validateServiceChallenge(challenge, approval, first.record.endpoint, Math.floor(Date.now() / 1000))
    const reply = await bounded(transport.request(first.record.endpoint + SERVICE_IDENTITY_PATH, {body: encodeServiceChallenge(challenge), maxBytes: SERVICE_IDENTITY_MAX_BYTES, signal: controller.signal}))
    if (reply.length > SERVICE_IDENTITY_MAX_BYTES) throw new Error('Service identity reply too large')
    const parsed = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(reply)) as {signature: Hex}
    if (!parsed || Object.keys(parsed).length !== 1 || !('signature' in parsed)) throw new Error('Invalid service identity reply')
    await bounded(verifyServiceIdentity(challenge, parsed.signature, first.record.authKey, Math.floor(Date.now() / 1000)))
    const last = await bounded(readApprovedServiceRecord(chain, approval))
    if (last.blockNumber < first.blockNumber || Object.keys(first.record).some(k => first.record[k as keyof ServiceRecord] !== last.record[k as keyof ServiceRecord])) throw new Error('Service changed during authentication')
    controller.signal.throwIfAborted()
    validateServiceChallenge(challenge, approval, first.record.endpoint, Math.floor(Date.now() / 1000))
    return {approval, record: last.record, manifest, blockNumber: last.blockNumber, expiresAt}
  } finally { clearTimeout(timer); controller.abort() }
}
