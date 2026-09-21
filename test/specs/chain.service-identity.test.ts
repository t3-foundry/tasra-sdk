import {readFileSync} from 'node:fs'
import {afterEach, describe, expect, it, vi} from 'vitest'
import {hashTypedData, type Address, type Hex} from 'viem'
import {privateKeyToAccount} from 'viem/accounts'
import {createTasraChainClient} from '../../src/chain/client.js'
import {hashServiceManifest, type ServiceApproval, type ServiceRecord} from '../../src/chain/services.js'
import {authenticateApprovedService, encodeServiceChallenge, parseServiceChallenge, encodeServiceManifest, serviceChallengeTypedData, validateServiceChallenge, validateServiceEndpoint, verifyServiceIdentity, verifyServiceManifest, type ServiceChallenge, type ServiceDiscoveryTransport, type ServiceManifest} from '../../src/chain/serviceIdentity.js'

const vector = JSON.parse(readFileSync(new URL('../fixtures/service-identity-v1.json', import.meta.url), 'utf8')) as {
  privateKey: Hex; authKey: Address; owner: Address; now: number; manifestBytes: string; challenge: ServiceChallenge;
  digest: Hex; signature: Hex; validEndpoints: string[]; invalidEndpoints: string[]
}
const signer = privateKeyToAccount(vector.privateKey)
const bytes = new TextEncoder().encode(vector.manifestBytes)
const approval: ServiceApproval = {...vector.challenge, serviceType: 1, owner: vector.owner, revision: BigInt(vector.challenge.revision)}
const record: ServiceRecord = {owner: vector.owner, pendingOwner: '0x0000000000000000000000000000000000000000', authKey: vector.authKey,
  serviceType: 1, status: 0, revision: approval.revision, manifestHash: approval.manifestHash, endpoint: vector.challenge.endpoint}
function fixture() {
  const chain = createTasraChainClient({rpcUrl: 'http://127.0.0.1:1', chainId: approval.chainId, addresses: {ServiceRegistry: approval.registry}})
  vi.spyOn(chain.client, 'getChainId').mockResolvedValue(approval.chainId)
  vi.spyOn(chain.client, 'getBlockNumber').mockResolvedValue(10n)
  const read = vi.spyOn(chain.readers.serviceRegistry, 'getService').mockResolvedValue(record)
  const challenges: ServiceChallenge[] = []
  const request = vi.fn<ServiceDiscoveryTransport['request']>(async (_url, {body}) => {
    if (!body) return bytes
    const challenge = JSON.parse(new TextDecoder().decode(body)) as ServiceChallenge
    // The responder can be five seconds behind without relaxing the client expiry check.
    validateServiceChallenge(challenge, approval, record.endpoint, Math.floor(Date.now() / 1000) - 5)
    challenges.push(challenge)
    return new TextEncoder().encode(JSON.stringify({signature: await signer.signTypedData(serviceChallengeTypedData(challenge))}))
  })
  return {chain, read, request, challenges}
}
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers() })

describe('service identity protocol shared with the reference implementation', () => {
  it('matches exact manifest, uint64 revision digest and signature vector', async () => {
    expect(encodeServiceManifest(JSON.parse(vector.manifestBytes))).toEqual(bytes)
    expect(verifyServiceManifest(bytes, approval, record).serviceType).toBe(1)
    expect(hashTypedData(serviceChallengeTypedData(vector.challenge))).toBe(vector.digest)
    expect(await signer.signTypedData(serviceChallengeTypedData(vector.challenge))).toBe(vector.signature)
    await verifyServiceIdentity(vector.challenge, vector.signature, vector.authKey, vector.now)
  })
  it.each(vector.validEndpoints)('accepts canonical endpoint %s', endpoint => { expect(validateServiceEndpoint(endpoint).protocol).toBe('https:') })
  it.each(vector.invalidEndpoints)('rejects ambiguous endpoint %s', endpoint => { expect(() => validateServiceEndpoint(endpoint)).toThrow() })
  it.each([
    {chainId: 43114}, {registry: vector.owner}, {serviceId: vector.challenge.nonce}, {revision: '1'},
    {endpoint: 'https://other.example.org/api'}, {manifestHash: vector.challenge.nonce}, {nonce: vector.challenge.serviceId}, {expiresAt: vector.challenge.expiresAt - 1},
  ])('binds every domain and challenge field %#', async change => {
    await expect(verifyServiceIdentity({...vector.challenge, ...change}, vector.signature, vector.authKey, vector.now)).rejects.toThrow()
  })
  it('enforces the shared canonical responder request shape', () => {
    const encoded = encodeServiceChallenge(vector.challenge)
    expect(parseServiceChallenge(encoded)).toEqual(vector.challenge)
    const text = new TextDecoder().decode(encoded)
    for (const malformed of ['\uFEFF' + text, text + '\n', text.replace('"version":1', '"version":1,"version":1'), text.replace('18446744073709551615', '018446744073709551615'), text.replace('"18446744073709551615"', '1')]) {
      expect(() => parseServiceChallenge(new TextEncoder().encode(malformed))).toThrow()
    }
  })
  it('refuses another key and noncanonical signature encoding', async () => {
    await expect(verifyServiceIdentity(vector.challenge, vector.signature, vector.owner, vector.now)).rejects.toThrow('key mismatch')
    await expect(verifyServiceIdentity(vector.challenge, `${vector.signature.slice(0, -2)}00` as Hex, vector.authKey, vector.now)).rejects.toThrow('Noncanonical')
    const highS = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n - BigInt(`0x${vector.signature.slice(66, 130)}`)
    const malleated = `${vector.signature.slice(0, 66)}${highS.toString(16).padStart(64, '0')}${vector.signature.endsWith('1b') ? '1c' : '1b'}` as Hex
    await expect(verifyServiceIdentity(vector.challenge, malleated, vector.authKey, vector.now)).rejects.toThrow('Noncanonical')
  })
  it('bounds freshness and rejects signing requests for another profile', async () => {
    for (const now of [vector.now - 1, vector.challenge.expiresAt, vector.challenge.expiresAt + 1]) {
      await expect(verifyServiceIdentity(vector.challenge, vector.signature, vector.authKey, now)).rejects.toThrow('expired or too far')
    }
    expect(() => validateServiceChallenge({...vector.challenge, endpoint: 'https://evil.example.org'}, approval, record.endpoint, vector.now)).toThrow('profile')
  })
  it('refuses changed bytes, unknown schemas, duplicate fields and capabilities', () => {
    expect(() => verifyServiceManifest(new TextEncoder().encode(vector.manifestBytes + '\n'), approval, record)).toThrow('hash')
    for (const text of ['\uFEFF' + vector.manifestBytes, vector.manifestBytes.replace('"schemaVersion":1', '"schemaVersion":2'), vector.manifestBytes.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'), vector.manifestBytes.trim(), vector.manifestBytes.replace('"oid4vp"', '"oid4vp","oid4vp"')]) {
      const malformed = new TextEncoder().encode(text)
      const manifestHash = hashServiceManifest(malformed)
      expect(() => verifyServiceManifest(malformed, {...approval, manifestHash}, {...record, manifestHash})).toThrow()
    }
    const manifest = JSON.parse(vector.manifestBytes) as ServiceManifest
    const wrong = encodeServiceManifest({...manifest, endpoint: 'https://other.example.org'})
    const manifestHash = hashServiceManifest(wrong)
    expect(() => verifyServiceManifest(wrong, {...approval, manifestHash}, {...record, manifestHash})).toThrow('profile')
  })
})

describe('approved discovery handshake', () => {
  it('authenticates, rechecks uncached registry state and generates a new nonce each time', async () => {
    const {chain, read, request, challenges} = fixture()
    expect((await authenticateApprovedService(chain, approval, {request})).record).toEqual(record)
    await authenticateApprovedService(chain, approval, {request})
    expect(read).toHaveBeenCalledTimes(4)
    expect(chain.client.getBlockNumber).toHaveBeenCalledWith({cacheTime: 0})
    expect(challenges[0]!.nonce).not.toBe(challenges[1]!.nonce)
    expect(Object.keys(challenges[0]!)).toEqual(['version', 'chainId', 'registry', 'serviceId', 'revision', 'endpoint', 'manifestHash', 'nonce', 'expiresAt'])
  })
  it('does not contact an unapproved service', async () => {
    const {chain, read, request} = fixture()
    read.mockResolvedValue({...record, status: 1})
    await expect(authenticateApprovedService(chain, approval, {request})).rejects.toThrow('not accepting')
    expect(request).not.toHaveBeenCalled()
  })
  it.each([{status: 1}, {authKey: vector.owner}, {endpoint: 'https://new.example.org'}, {pendingOwner: vector.owner}])('rejects a mutation during proof %#', async change => {
    const {chain, read, request} = fixture()
    read.mockResolvedValueOnce(record).mockResolvedValue({...record, ...change})
    await expect(authenticateApprovedService(chain, approval, {request})).rejects.toThrow()
  })
  it('stops before a challenge when the manifest hash is wrong', async () => {
    const {chain, request} = fixture()
    request.mockResolvedValue(new TextEncoder().encode('{}'))
    await expect(authenticateApprovedService(chain, approval, {request})).rejects.toThrow('hash')
    expect(request).toHaveBeenCalledTimes(1)
  })
  it('refuses replay of a valid signature from a different challenge', async () => {
    const {chain, request} = fixture()
    request.mockResolvedValueOnce(bytes).mockResolvedValue(new TextEncoder().encode(JSON.stringify({signature: vector.signature})))
    await expect(authenticateApprovedService(chain, approval, {request})).rejects.toThrow('key mismatch')
  })
  it('bounds an unavailable RPC without later contacting the endpoint', async () => {
    vi.useFakeTimers()
    const {chain, request} = fixture()
    vi.mocked(chain.client.getChainId).mockReturnValue(new Promise(() => {}))
    const result = expect(authenticateApprovedService(chain, approval, {request})).rejects.toThrow('timed out')
    await vi.advanceTimersByTimeAsync(30_000)
    await result
    expect(request).not.toHaveBeenCalled()
  })
})
