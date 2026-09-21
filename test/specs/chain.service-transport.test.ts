import {readFileSync} from 'node:fs'
import {createServer, type Server} from 'node:https'
import {lookup} from 'node:dns'
import {afterEach, describe, expect, it, vi} from 'vitest'
import {createNodeServiceStatusTransport, createNodeAgentWalletFetch, createNodeAgentTransport, createNodeRelayTransport, createNodeServiceDiscoveryTransport, isPublicServiceAddress} from '../../src/chain/node.js'
import {authenticateApprovedService, encodeServiceManifest, serviceChallengeTypedData, type ServiceChallenge, type ServiceManifest} from '../../src/chain/serviceIdentity.js'
import {createTasraChainClient} from '../../src/chain/client.js'
import {hashServiceManifest, type ServiceApproval, type ServiceRecord} from '../../src/chain/services.js'
import {privateKeyToAccount} from 'viem/accounts'
import type {Address, Hex} from 'viem'
import type {RegisteredAgentSession} from '../../src/chain/registeredAgent.js'
vi.mock('node:dns', async importOriginal => {
  const original = await importOriginal<typeof import('node:dns')>()
  return {...original, lookup: vi.fn(original.lookup)}
})
const fixture = (name: string) => readFileSync(new URL(`../fixtures/${name}`, import.meta.url))
const vector = JSON.parse(fixture('service-identity-v1.json').toString()) as {publicAddresses: string[]; privateAddresses: string[]; privateKey: Hex; owner: Address; challenge: ServiceChallenge; manifestBytes: string}
const ca = fixture('service-test-ca.pem')
const servers: Server[] = []
async function serve(handler: Parameters<typeof createServer>[1]) {
  const server = createServer({key: fixture('service-test-key.pem'), cert: fixture('service-test-cert.pem')}, handler)
  servers.push(server)
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address() as {port: number}
  return `https://localhost:${address.port}`
}
const options = () => ({maxBytes: 128, signal: new AbortController().signal})
afterEach(async () => {
  for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())) }
  vi.restoreAllMocks()
})

describe('service HTTPS destination boundary', () => {
  it('measures plaintext readiness and JSON policy only over bounded, approved TLS destinations', async () => {
    const hits = vi.fn()
    const endpoint = await serve((req, res) => {
      hits(req.url)
      res.setHeader('content-type', req.url === '/readyz' ? 'text/plain; charset=utf-8' : 'application/json')
      res.end(req.url === '/readyz' ? 'ready' : '{"entries":[]}')
    })
    const transport = createNodeServiceStatusTransport({allowedPrivateHosts: ['localhost'], ca})
    expect(new TextDecoder().decode(await transport.request(endpoint + '/readyz', options()))).toBe('ready')
    expect(new TextDecoder().decode(await transport.request(endpoint + '/v1/relay/policy', options()))).toBe('{"entries":[]}')
    expect(() => transport.request(endpoint + '/v1/rpc', options())).toThrow(/path/)
    expect(() => transport.request(endpoint + '/readyz', {...options(), body: new Uint8Array()})).toThrow(/method/)
    await expect(createNodeServiceStatusTransport({ca}).request(endpoint + '/readyz', options())).rejects.toThrow(/destination policy/)
    expect(hits).toHaveBeenCalledTimes(2)
  })

  it.each([200, 202, 422])('bounds relay JSON separately from discovery (HTTP %s)', async status => {
    const endpoint = await serve((req, res) => { req.resume(); res.writeHead(status, {'content-type': 'application/json'}); res.end('{}') })
    const transport = createNodeRelayTransport({allowedPrivateHosts: ['localhost'], ca})
    await expect(transport.relayRequest(endpoint + '/v1/relay/forward', {...options(), body: new Uint8Array(3_000)})).resolves.toBeDefined()
    expect(() => transport.request(endpoint + '/v1/service/identity', {...options(), body: new Uint8Array(3_000)})).toThrow('bounds')
    expect(() => transport.relayRequest(endpoint + '/v1/relay/forward', {...options(), body: new Uint8Array(65_537)})).toThrow('bounds')
    expect(() => transport.relayRequest(endpoint + '/arbitrary', options())).toThrow('path')
    expect(() => transport.relayRequest(endpoint + '/v1/relay/forward', options())).toThrow('method')
  })
  it('applies destination and redirect checks to relay POSTs', async () => {
    const endpoint = await serve((req, res) => { req.resume(); res.writeHead(307, {location: 'https://127.0.0.1/secret', 'content-type': 'application/json'}); res.end('{}') })
    const body = new TextEncoder().encode('{}')
    await expect(createNodeRelayTransport({ca}).relayRequest(endpoint + '/v1/relay/forward', {...options(), body})).rejects.toThrow('destination policy')
    await expect(createNodeRelayTransport({ca, allowedPrivateHosts: ['localhost']}).relayRequest(endpoint + '/v1/relay/forward', {...options(), body})).rejects.toThrow('status')
  })
  it.each(vector.publicAddresses)('allows public address %s', address => expect(isPublicServiceAddress(address)).toBe(true))
  it.each(vector.privateAddresses)('refuses special address %s', address => expect(isPublicServiceAddress(address)).toBe(false))
  it('refuses private DNS before connecting and permits an explicit host with verified TLS', async () => {
    const hits = vi.fn()
    const endpoint = await serve((req, res) => { hits(req.headers); res.writeHead(200, {'content-type': 'application/json'}); res.end('{}') })
    await expect(createNodeServiceDiscoveryTransport({ca}).request(endpoint, options())).rejects.toThrow('destination policy')
    expect(hits).not.toHaveBeenCalled()
    const result = await createNodeServiceDiscoveryTransport({allowedPrivateHosts: ['localhost'], ca}).request(endpoint, options())
    expect(new TextDecoder().decode(result)).toBe('{}')
    expect(hits).toHaveBeenCalledTimes(1)
    expect(hits.mock.calls[0]![0].authorization).toBeUndefined()
    expect(hits.mock.calls[0]![0].cookie).toBeUndefined()
  })
  it('accepts the maximum registered base length plus the manifest path', async () => {
    const endpoint = await serve((_req, res) => { res.setHeader('content-type', 'application/json'); res.end('{}') })
    const base = endpoint + '/' + 'a'.repeat(511 - endpoint.length)
    expect(base.length).toBe(512)
    await expect(createNodeServiceDiscoveryTransport({allowedPrivateHosts: ['localhost'], ca}).request(base + '/.well-known/keykeeper-service.json', options())).resolves.toBeDefined()
  })
  it('rejects mixed public/private DNS answers', async () => {
    const original = await vi.importActual<typeof import('node:dns')>('node:dns')
    vi.mocked(lookup).mockImplementationOnce((...args: Parameters<typeof lookup>) => {
      const callback = args.at(-1) as unknown as (error: null, addresses: {address: string; family: number}[]) => void
      callback(null, [{address: '8.8.8.8', family: 4}, {address: '127.0.0.1', family: 4}])
    })
    await expect(createNodeServiceDiscoveryTransport().request('https://mixed.example.org', options())).rejects.toThrow('DNS answer')
    vi.mocked(lookup).mockImplementation(original.lookup)
  })
  it('does not turn a private-host exception into a TLS-verification exception', async () => {
    const endpoint = await serve((_req, res) => res.end('{}'))
    await expect(createNodeServiceDiscoveryTransport({allowedPrivateHosts: ['localhost']}).request(endpoint, options())).rejects.toThrow()
  })
  it('does not follow redirects or send another request', async () => {
    const hits = vi.fn()
    const endpoint = await serve((_req, res) => { hits(); res.writeHead(302, {location: 'https://127.0.0.1/secret', 'content-type': 'application/json'}); res.end('{}') })
    await expect(createNodeServiceDiscoveryTransport({allowedPrivateHosts: ['localhost'], ca}).request(endpoint, options())).rejects.toThrow('status')
    expect(hits).toHaveBeenCalledTimes(1)
  })
  it.each([false, true])('bounds chunked and declared bodies (content length=%s)', async length => {
    const endpoint = await serve((_req, res) => {
      res.writeHead(200, {'content-type': 'application/json', ...(length ? {'content-length': 129} : {})})
      res.write('x'.repeat(100)); res.end('x'.repeat(29))
    })
    await expect(createNodeServiceDiscoveryTransport({allowedPrivateHosts: ['localhost'], ca}).request(endpoint, options())).rejects.toThrow('too large')
  })
  it.each([{'content-type': 'text/html'}, {'content-type': 'application/json', 'content-encoding': 'gzip'}])('rejects unexpected response formats %#', async headers => {
    const endpoint = await serve((_req, res) => { res.writeHead(200, headers); res.end('{}') })
    await expect(createNodeServiceDiscoveryTransport({allowedPrivateHosts: ['localhost'], ca}).request(endpoint, options())).rejects.toThrow('encoding refused')
  })
  it('cancels a stalled HTTPS response', async () => {
    const endpoint = await serve(() => {})
    const controller = new AbortController()
    const result = createNodeServiceDiscoveryTransport({allowedPrivateHosts: ['localhost'], ca}).request(endpoint, {...options(), signal: controller.signal})
    const assertion = expect(result).rejects.toThrow()
    controller.abort()
    await assertion
  })
  it('completes a real TLS manifest and signed challenge handshake before returning an endpoint', async () => {
    const signer = privateKeyToAccount(vector.privateKey)
    const requests: string[] = []
    const endpoint = await serve((req, res) => {
      requests.push(`${req.method} ${req.url}`)
      res.setHeader('content-type', 'application/json')
      if (req.method === 'GET') { res.end(manifest); return }
      const chunks: Buffer[] = []
      req.on('data', chunk => chunks.push(chunk))
      req.on('end', () => {
        const challenge = JSON.parse(Buffer.concat(chunks).toString()) as ServiceChallenge
        void signer.signTypedData(serviceChallengeTypedData(challenge)).then(signature => res.end(JSON.stringify({signature})))
      })
    })
    const manifest = encodeServiceManifest({...JSON.parse(vector.manifestBytes) as ServiceManifest, endpoint})
    const approval: ServiceApproval = {...vector.challenge, owner: vector.owner, serviceType: 1, revision: 1n, manifestHash: hashServiceManifest(manifest)}
    const record: ServiceRecord = {owner: approval.owner, pendingOwner: '0x0000000000000000000000000000000000000000', authKey: signer.address,
      serviceType: 1, status: 0, revision: 1n, manifestHash: approval.manifestHash, endpoint}
    const chain = createTasraChainClient({rpcUrl: 'http://127.0.0.1:1', chainId: approval.chainId, addresses: {ServiceRegistry: approval.registry}})
    vi.spyOn(chain.client, 'getChainId').mockResolvedValue(approval.chainId)
    vi.spyOn(chain.client, 'getBlockNumber').mockResolvedValue(10n)
    vi.spyOn(chain.readers.serviceRegistry, 'getService').mockResolvedValue(record)
    const result = await authenticateApprovedService(chain, approval, createNodeServiceDiscoveryTransport({allowedPrivateHosts: ['localhost'], ca}))
    expect(result.record.endpoint).toBe(endpoint)
    expect(requests).toEqual(['GET /.well-known/keykeeper-service.json', 'POST /v1/service/identity'])
  })
})


describe('agent session HTTPS transport', () => {
  it('restricts bearer secrets to pinned session GET paths', async () => {
    const hits: {method?: string; bearer?: string}[] = []
    const endpoint = await serve((req, res) => { hits.push({method: req.method, bearer: req.headers.authorization}); req.resume(); res.writeHead(req.method === 'POST' ? 201 : 200, {'content-type': 'application/json'}); res.end('{}') })
    const transport = createNodeAgentTransport({ca, allowedPrivateHosts: ['localhost']})
    await transport.agentRequest(endpoint + '/v1/sessions', {...options(), body: new TextEncoder().encode('{}')})
    await transport.agentRequest(endpoint + '/v1/sessions/' + 'ab'.repeat(32), {...options(), bearer: 'cd'.repeat(32)})
    expect(hits).toEqual([{method: 'POST', bearer: undefined}, {method: 'GET', bearer: 'Bearer ' + 'cd'.repeat(32)}])
    expect(() => transport.agentRequest(endpoint + '/arbitrary', {...options(), bearer: 'cd'.repeat(32)})).toThrow()
    expect(() => transport.agentRequest(endpoint + '/v1/sessions', {...options(), body: new Uint8Array(), bearer: 'cd'.repeat(32)})).toThrow()
    expect(() => transport.agentRequest(endpoint + '/v1/sessions/' + 'ab'.repeat(32), options())).toThrow()
  })
  it('refuses private destinations and redirects for session traffic', async () => {
    const endpoint = await serve((req, res) => { req.resume(); res.writeHead(307, {location: 'https://other.example', 'content-type': 'application/json'}); res.end('{}') })
    const opts = {...options(), body: new TextEncoder().encode('{}')}
    await expect(createNodeAgentTransport({ca}).agentRequest(endpoint + '/v1/sessions', opts)).rejects.toThrow('destination policy')
    await expect(createNodeAgentTransport({ca, allowedPrivateHosts: ['localhost']}).agentRequest(endpoint + '/v1/sessions', opts)).rejects.toThrow('status')
  })
})

describe('registered wallet HTTPS transport', () => {
  it.each(['application/json', 'application/did+json', 'application/did+ld+json'])('accepts %s only for the approved DID document', async type => {
    const endpoint = await serve((req, res) => {req.resume(); res.writeHead(200, {'content-type': type}); res.end('{}')})
    const session = {sessionId: 'aa'.repeat(32), profile: {endpoint, clientId: `decentralized_identifier:did:web:localhost%3A${new URL(endpoint).port}`}, requestUri: endpoint + '/v1/request/' + 'aa'.repeat(32)} as RegisteredAgentSession
    const fetcher = createNodeAgentWalletFetch(session, {ca, allowedPrivateHosts: ['localhost']})
    expect(await (await fetcher(endpoint + '/.well-known/did.json')).json()).toEqual({})
    await expect(fetcher(session.requestUri)).rejects.toThrow(/content type/)
    if (type !== 'application/json') await expect(fetcher(endpoint + '/v1/response?session=' + session.sessionId, {method: 'POST', body: 'response=fixture'})).rejects.toThrow(/content type/)
  })
  it('preserves request/form bytes only on the approved session routes', async () => {
    const hits: Array<{path?: string; type?: string; bearer?: string; body: string}> = []
    // A RequestListener returns void, so the async body is wrapped rather than passed
    // directly: a rejection in a handler handed straight to createServer is unhandled,
    // and the request would hang until the fetch timed out instead of failing here.
    const endpoint = await serve((req, res) => {
      void (async () => {
        const chunks = []
        for await (const chunk of req) chunks.push(chunk as Buffer)
        hits.push({path: req.url, type: req.headers['content-type'], bearer: req.headers.authorization, body: Buffer.concat(chunks).toString()})
        res.writeHead(200, {'content-type': req.url?.startsWith('/v1/request/') ? 'application/oauth-authz-req+jwt' : 'application/json'})
        res.end(req.url?.startsWith('/v1/request/') ? 'header.claims.signature' : '{}')
      })().catch((error: unknown) => {
        res.writeHead(500, {'content-type': 'text/plain'})
        res.end(String(error))
      })
    })
    const session = {sessionId: 'aa'.repeat(32), profile: {endpoint, clientId: `decentralized_identifier:did:web:localhost%3A${new URL(endpoint).port}`}, requestUri: endpoint + '/v1/request/' + 'aa'.repeat(32)} as RegisteredAgentSession
    const fetcher = createNodeAgentWalletFetch(session, {ca, allowedPrivateHosts: ['localhost']})
    expect(await (await fetcher(session.requestUri)).text()).toBe('header.claims.signature')
    await fetcher(endpoint + '/.well-known/did.json')
    await fetcher(endpoint + '/v1/response?session=' + session.sessionId, {method: 'POST', headers: {authorization: 'secret'}, body: 'response=abc%2Bdef'})
    expect(hits.at(-1)).toMatchObject({body: 'response=abc%2Bdef', type: 'application/x-www-form-urlencoded', bearer: undefined})
    await expect(fetcher(endpoint + '/v1/request/' + 'bb'.repeat(32))).rejects.toThrow(/outside/)
    await expect(fetcher(endpoint + '/v1/response?session=' + 'bb'.repeat(32), {method: 'POST', body: 'response=secret'})).rejects.toThrow(/outside/)
    await expect(fetcher(endpoint + '/v1/response', {method: 'POST', body: 'response=secret'})).rejects.toThrow(/outside/)
    await expect(fetcher('https://other.example/v1/response', {method: 'POST', body: 'secret'})).rejects.toThrow(/outside/)
    await expect(fetcher(endpoint + '/v1/response?session=' + session.sessionId, {method: 'POST', body: 'x'.repeat(1_048_577)})).rejects.toThrow(/bounds/)
    expect(hits).toHaveLength(3)
  })
})
