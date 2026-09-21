import {afterEach, describe, expect, it, vi} from 'vitest'
import {createTasraChainClient} from '../../src/chain/client.js'
import {addressBookFromEnv} from '../../src/chain/deployments.js'
import {eventNamesOf} from '../../src/chain/events.js'
import {deriveServiceId, hashServiceManifest, readApprovedServiceRecord, type ServiceApproval, type ServiceRecord} from '../../src/chain/services.js'

const registry = '0x0000000000000000000000000000000000000010' as const
const owner = '0x0000000000000000000000000000000000000020' as const
const salt = `0x${'00'.repeat(32)}` as const
const chainId = 43113
const serviceId = deriveServiceId(BigInt(chainId), registry, owner, salt)
const manifestHash = hashServiceManifest(new TextEncoder().encode('{"version":1}'))
const approval: ServiceApproval = {chainId, registry, serviceId, owner, serviceType: 1, revision: 1n, manifestHash}
const record: ServiceRecord = {
  owner, pendingOwner: '0x0000000000000000000000000000000000000000', authKey: owner,
  serviceType: 1, status: 0, revision: 1n, manifestHash, endpoint: 'https://agent.example.org',
}

function fixture(overrides: Partial<ServiceRecord> = {}) {
  const chain = createTasraChainClient({rpcUrl: 'http://127.0.0.1:1', chainId, addresses: {ServiceRegistry: registry}})
  vi.spyOn(chain.client, 'getChainId').mockResolvedValue(chainId)
  vi.spyOn(chain.client, 'getBlockNumber').mockResolvedValue(123n)
  const read = vi.spyOn(chain.readers.serviceRegistry, 'getService').mockResolvedValue({...record, ...overrides})
  return {chain, read}
}

afterEach(() => vi.restoreAllMocks())

describe('ServiceRegistry approval boundary', () => {
  it('requires the exact approved profile and pins the record read to one block', async () => {
    const {chain, read} = fixture()
    expect(await readApprovedServiceRecord(chain, approval)).toEqual({record, blockNumber: 123n})
    expect(read).toHaveBeenCalledExactlyOnceWith(serviceId, 123n)
    expect(chain.client.getBlockNumber).toHaveBeenCalledWith({cacheTime: 0})
  })

  it.each([
    [{status: 1}, 'not accepting'],
    [{status: 2}, 'not accepting'],
    [{serviceType: 0}, 'type approval'],
    [{owner: registry}, 'owner approval'],
    [{revision: 2n}, 'revision approval'],
    [{revision: 0n}, 'revision approval'],
    [{manifestHash: salt}, 'manifest approval'],
  ] as const)('rejects changed or unusable records: %#', async (change, message) => {
    const {chain} = fixture(change)
    await expect(readApprovedServiceRecord(chain, approval)).rejects.toThrow(message)
  })

  it('rejects a different registry before consulting the RPC', async () => {
    const {chain, read} = fixture()
    await expect(readApprovedServiceRecord(chain, {...approval, registry: owner})).rejects.toThrow('registry approval')
    expect(chain.client.getChainId).not.toHaveBeenCalled()
    expect(read).not.toHaveBeenCalled()
  })

  it('rejects a different RPC chain before reading any provider record', async () => {
    const {chain, read} = fixture()
    vi.mocked(chain.client.getChainId).mockResolvedValue(43114)
    await expect(readApprovedServiceRecord(chain, approval)).rejects.toThrow('chain approval')
    expect(read).not.toHaveBeenCalled()
  })

  it('propagates an unavailable chain instead of choosing an unverified URL', async () => {
    const {chain, read} = fixture()
    read.mockRejectedValue(new Error('RPC unavailable'))
    await expect(readApprovedServiceRecord(chain, approval)).rejects.toThrow('RPC unavailable')
  })

  it('does not cache approval across a rotation', async () => {
    const {chain, read} = fixture()
    await readApprovedServiceRecord(chain, approval)
    read.mockResolvedValue({...record, revision: 2n, authKey: registry})
    await expect(readApprovedServiceRecord(chain, approval)).rejects.toThrow('revision approval')
  })

  it('hashes original manifest bytes, including whitespace', () => {
    expect(hashServiceManifest(new TextEncoder().encode('{ "version": 1 }'))).not.toBe(manifestHash)
  })

  it('domain-binds service IDs to chain, proxy and original provider', () => {
    expect(deriveServiceId(43114n, registry, owner, salt)).not.toBe(serviceId)
    expect(deriveServiceId(BigInt(chainId), owner, owner, salt)).not.toBe(serviceId)
    expect(deriveServiceId(BigInt(chainId), registry, registry, salt)).not.toBe(serviceId)
  })

  it('includes the proxy in the address book and its lifecycle events in discovery', () => {
    expect(addressBookFromEnv({SERVICE_REGISTRY: registry}).ServiceRegistry).toBe(registry)
    expect(eventNamesOf('ServiceRegistry')).toContain('ServiceRegistered')
    expect(eventNamesOf('ServiceRegistry')).toContain('ServiceChanged')
    const {chain} = fixture()
    expect(chain.deployedContracts()).toContain('ServiceRegistry')
  })

  it('rejects unbounded pages before making an RPC request', () => {
    const {chain} = fixture()
    expect(() => chain.readers.serviceRegistry.serviceIds(0n, 101n)).toThrow('page')
    expect(() => chain.readers.serviceRegistry.serviceIds(-1n, 1n)).toThrow('page')
    expect(() => chain.readers.serviceRegistry.serviceIds(0n, 0n)).toThrow('page')
  })
})
