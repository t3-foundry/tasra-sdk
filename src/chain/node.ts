/** Node-only service discovery transport; never imported by the browser-safe chain barrel. */
import {didWebUrl} from '../oid4vp/did-web.js'
import type {RegisteredAgentSession} from './registeredAgent.js'
import type {AgentTransport} from './registeredAgent.js'
import type {RelayTransport} from './registeredRelay.js'
import {lookup} from 'node:dns'
import {request} from 'node:https'
import {rootCertificates} from 'node:tls'
import {BlockList, isIP, type LookupFunction} from 'node:net'
import {SERVICE_MANIFEST_PATH, SERVICE_IDENTITY_PATH, validateServiceEndpoint, type ServiceDiscoveryTransport} from './serviceIdentity.js'

const denied = new BlockList()
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 3],
] as const) denied.addSubnet(address, prefix, 'ipv4')
for (const [address, prefix] of [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]] as const) denied.addSubnet(address, prefix, 'ipv6')
const globalV6 = new BlockList()
globalV6.addSubnet('2000::', 3, 'ipv6')

/** Conservative globally routable destinations; special-purpose exceptions require explicit policy. */
export function isPublicServiceAddress(address: string): boolean {
  const family = isIP(address)
  return family === 4 ? !denied.check(address, 'ipv4')
    : family === 6 && globalV6.check(address, 'ipv6') && !denied.check(address, 'ipv6')
}

export interface ServiceTransportPolicy {
  /** Exact, canonical hostnames/IPs only. Application configuration, never downloaded metadata. */
  allowedPrivateHosts?: readonly string[]
  /** Additional deployment CA roots. Certificate and hostname verification remain mandatory. */
  ca?: string | Buffer | (string | Buffer)[]
}

export function createNodeServiceDiscoveryTransport(policy: ServiceTransportPolicy = {}): ServiceDiscoveryTransport {
  return guardedTransport(policy, 'discovery')
}

/** Public readiness and relay-policy observations, with the same socket/TLS policy. */
export function createNodeServiceStatusTransport(policy: ServiceTransportPolicy = {}): ServiceDiscoveryTransport {
  return guardedTransport(policy, 'status')
}

/** Discovery and relay traffic use the same socket-bound destination and TLS policy. */
export function createNodeRelayTransport(policy: ServiceTransportPolicy = {}): RelayTransport {
  const discovery = guardedTransport(policy, 'discovery')
  const relay = guardedTransport(policy, 'relay')
  return {...discovery, relayRequest: relay.request}
}

/** Session secrets use this same guarded connection and can only travel to a session GET. */
export function createNodeAgentTransport(policy: ServiceTransportPolicy = {}): AgentTransport {
  const discovery = guardedTransport(policy, 'discovery')
  const agent = guardedTransport(policy, 'agent')
  return {...discovery, agentRequest: agent.request}
}

/** Wallet protocol requests restricted to the selected session and approved DID, with socket checks. */
export function createNodeAgentWalletFetch(session: Pick<RegisteredAgentSession, 'profile' | 'requestUri' | 'sessionId'>, policy: ServiceTransportPolicy = {}): typeof fetch {
  const did = session.profile.clientId.replace(/^decentralized_identifier:/, '')
  if (!/^[0-9a-f]{64}$/.test(session.sessionId)) throw new Error('Invalid wallet session ID')
  const didUrl = didWebUrl(did), responseUrl = session.profile.endpoint + '/v1/response?session=' + session.sessionId
  const requestUri = session.requestUri
  const transport = guardedTransport(policy, 'wallet')
  return async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = init?.method ?? 'GET'
    const post = method === 'POST' && url === responseUrl
    if (!(method === 'GET' && (url === requestUri || url === didUrl)) && !post) throw new Error('Wallet request is outside the approved session')
    if (post && typeof init?.body !== 'string' || !post && init?.body != null) throw new Error('Invalid wallet request body')
    const signal = init?.signal ?? AbortSignal.timeout(30_000)
    const bytes = await transport.request(url, {body: post ? new TextEncoder().encode(init!.body as string) : undefined, maxBytes: post ? 16_384 : 65_536, signal})
    return new Response(new TextDecoder('utf-8', {fatal: true}).decode(bytes), {status: 200, headers: {'content-type': url === requestUri ? 'application/oauth-authz-req+jwt' : 'application/json'}})
  }
}

function guardedTransport(policy: ServiceTransportPolicy, mode: 'discovery' | 'relay' | 'agent' | 'wallet' | 'status') {
  const relay = mode === 'relay', agent = mode === 'agent', wallet = mode === 'wallet', status = mode === 'status'

  const allowed = new Set(policy.allowedPrivateHosts ?? [])
  // Snapshot mutable caller configuration before the first asynchronous request.
  const ca = Array.isArray(policy.ca) ? policy.ca.map(c => typeof c === 'string' ? c : Buffer.from(c))
    : typeof policy.ca === 'string' || policy.ca === undefined ? policy.ca : Buffer.from(policy.ca)
  return {
    request(url: string, {body, maxBytes, signal, bearer}: {body?: Uint8Array; maxBytes: number; signal: AbortSignal; bearer?: string}) {
      signal.throwIfAborted()
      if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > (agent || wallet ? 1_048_576 : relay ? 4_096 : 16_384) || body && body.length > (wallet ? 1_048_576 : agent || relay ? 65_536 : 2_048)) throw new Error('Invalid service HTTP bounds')
      // The registry's 512-byte limit applies to the base, excluding appended protocol paths.
      const relaySuffix = url.match(/\/v1\/relay\/(forward|0x[0-9a-f]{64})$/)?.[0]
      if (relay && (!relaySuffix || Boolean(body) !== relaySuffix.endsWith('/forward'))) throw new Error('Invalid relay path or method')
      const agentSuffix = url.match(/\/v1\/sessions(?:\/[0-9a-f]{64})?$/)?.[0]
      if (agent && (!agentSuffix || (body ? agentSuffix !== '/v1/sessions' || bearer !== undefined : agentSuffix === '/v1/sessions' || !/^[0-9a-f]{64}$/.test(bearer ?? '')))) throw new Error('Invalid agent path, method or poll secret')
      if (!agent && bearer !== undefined) throw new Error('Bearer is only allowed for agent polling')
      const walletSuffix = url.match(/(?:\/\.well-known\/did\.json|\/v1\/request\/[0-9a-f]{64}|\/v1\/response\?session=[0-9a-f]{64})$/)?.[0]
      if (wallet && (!walletSuffix || Boolean(body) !== walletSuffix.startsWith('/v1/response?session='))) throw new Error('Invalid wallet path or method')
      const statusSuffix = url.match(/(?:\/readyz|\/v1\/relay\/policy)$/)?.[0]
      if (status && (!statusSuffix || body !== undefined)) throw new Error('Invalid service status path or method')
      const contentType = status && statusSuffix === '/readyz' ? 'text/plain' : wallet && !body && !url.endsWith('/did.json') ? 'application/oauth-authz-req+jwt' : 'application/json'
      const responseTypes = wallet && walletSuffix === '/.well-known/did.json'
        ? ['application/json', 'application/did+json', 'application/did+ld+json'] : [contentType]
      const suffix = status ? statusSuffix : wallet ? walletSuffix : agent ? agentSuffix : relay ? relaySuffix : [SERVICE_MANIFEST_PATH, SERVICE_IDENTITY_PATH].find(path => url.endsWith(path))
      validateServiceEndpoint(suffix ? url.slice(0, -suffix.length) : url)
      const parsed = new URL(url)
      const host = parsed.hostname.replace(/^\[|\]$/g, '')
      const permits = (address: string) => allowed.has(host) || isPublicServiceAddress(address)
      if (isIP(host) && !permits(host)) throw new Error('Service destination policy refuses address')
      const checkedLookup: LookupFunction = (hostname, options, callback) => {
        lookup(hostname, {all: true, verbatim: true}, (error, addresses) => {
          if (error) { callback(error, '', 4); return }
          if (!addresses.length || addresses.some(a => !permits(a.address))) {
            callback(new Error('Service destination policy refuses DNS answer'), '', 4); return
          }
          // These exact checked addresses are handed to the socket. No second DNS lookup.
          if (options.all) callback(null, addresses)
          else callback(null, addresses[0]!.address, addresses[0]!.family)
        })
      }
      return new Promise<Uint8Array>((resolve, reject) => {
        const req = request(parsed, {
          method: body ? 'POST' : 'GET', agent: false, lookup: checkedLookup,
          ca: ca === undefined ? undefined : [...rootCertificates, ...(Array.isArray(ca) ? ca : [ca])], rejectUnauthorized: true, signal, maxHeaderSize: 8_192,
          headers: {...(bearer ? {authorization: `Bearer ${bearer}`} : {}), accept: responseTypes.join(', '), 'accept-encoding': 'identity', ...(body ? {'content-type': wallet ? 'application/x-www-form-urlencoded' : 'application/json', 'content-length': body.length} : {})},
        }, res => {
          const fail = (error: Error) => { reject(error); req.destroy(error) }
          if (!(agent ? res.statusCode === (body ? 201 : 200) : relay ? [200, 202, 422].includes(res.statusCode ?? 0) : res.statusCode === 200) || !responseTypes.includes(res.headers['content-type']?.split(';')[0]?.trim().toLowerCase() ?? '') || res.headers['content-encoding'] && res.headers['content-encoding'] !== 'identity') {
            fail(new Error('Service HTTP status, content type or encoding refused')); return
          }
          const advertised = res.headers['content-length']
          if (advertised && (!/^\d+$/.test(advertised) || Number(advertised) > maxBytes)) {
            fail(new Error('Service response too large')); return
          }
          const chunks: Buffer[] = []
          let size = 0
          res.on('data', (chunk: Buffer) => {
            if (size + chunk.length > maxBytes) { fail(new Error('Service response too large')); return }
            size += chunk.length
            chunks.push(chunk)
          })
          res.on('error', reject)
          res.on('end', () => resolve(Buffer.concat(chunks, size)))
        })
        // Absolute request deadline also bounds DNS/TLS and slow trickle responses.
        const timer = setTimeout(() => req.destroy(new Error('Service HTTP timed out')), agent || wallet ? 30_000 : 5_000)
        req.on('close', () => clearTimeout(timer))
        req.on('error', reject)
        req.end(body)
      })
    },
  }
}
