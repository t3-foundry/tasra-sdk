import {encodeAbiParameters, keccak256, type Address, type Hex, type PublicClient, type ReadContractReturnType} from 'viem'
import {serviceRegistryAbi} from './abis/serviceRegistry.js'
import {requireAddress, type AddressBook} from './deployments.js'

/** Permanent ServiceRegistry ABI ordinals. Registration grants no operator privileges. */
export const SERVICE_TYPES = {gasRelayer: 0, verifierAgent: 1, vaultService: 2} as const
export const SERVICE_STATUSES = {active: 0, draining: 1, retired: 2} as const
export type ServiceType = (typeof SERVICE_TYPES)[keyof typeof SERVICE_TYPES]
export type ServiceStatus = (typeof SERVICE_STATUSES)[keyof typeof SERVICE_STATUSES]

/** Provider claims, not authenticated endpoints or platform endorsements. */
export interface ServiceRecord {
  owner: Address
  pendingOwner: Address
  authKey: Address
  serviceType: ServiceType
  status: ServiceStatus
  revision: bigint
  manifestHash: Hex
  endpoint: string
}

/** Pin the approved revision so an endpoint, key or provider change requires a new decision. */
export interface ServiceApproval {
  chainId: number
  registry: Address
  serviceId: Hex
  serviceType: ServiceType
  owner: Address
  revision: bigint
  manifestHash: Hex
}

/** Matches serviceIdFor on the proxy. Provider transfer does not change this ID. */
export function deriveServiceId(chainId: bigint, registry: Address, creator: Address, salt: Hex): Hex {
  return keccak256(encodeAbiParameters(
    [{type: 'uint256'}, {type: 'address'}, {type: 'address'}, {type: 'bytes32'}],
    [chainId, registry, creator, salt],
  ))
}

/**
 * The slice of a chain client this module needs, declared structurally.
 *
 * Deliberately NOT `import type {TasraChainClient} from './client.js'`: `client.ts`
 * imports this module to build its `serviceRegistry` readers, so importing its client
 * type back creates a type-level cycle between the two modules. TypeScript then cannot
 * name `PublicClient` when emitting declarations and inlines the fully expanded client
 * type instead — which stops being nameable from a consumer's tree as soon as viem's
 * internal action types appear in it, failing the build with TS2742. Structural typing
 * here keeps the modules independent, and `TasraChainClient` still satisfies it.
 */
export interface ServiceRegistryChainReader {
  readonly addresses: AddressBook
  readonly client: PublicClient
  readonly readers: {
    readonly serviceRegistry: {
      getService(serviceId: Hex, blockNumber?: bigint):
        Promise<ReadContractReturnType<typeof serviceRegistryAbi, 'getService'>>
    }
  }
}

/** Hash the exact downloaded/published bytes; never parse and re-serialize before checking. */
export function hashServiceManifest(bytes: Uint8Array): Hex {
  return keccak256(bytes)
}

/**
 * Low-level registry readers. Use one blockNumber for a consistent multi-page snapshot.
 *
 * The return type is written out rather than inferred so that consumers of this module
 * (and the declarations emitted for them) name each result through viem's public
 * `ReadContractReturnType` instead of expanding viem's client internals.
 */
export interface ServiceRegistryReaders {
  getService(serviceId: Hex, blockNumber?: bigint):
    Promise<ReadContractReturnType<typeof serviceRegistryAbi, 'getService'>>
  serviceCount(blockNumber?: bigint):
    Promise<ReadContractReturnType<typeof serviceRegistryAbi, 'serviceCount'>>
  serviceIds(offset: bigint, limit: bigint, blockNumber?: bigint):
    Promise<ReadContractReturnType<typeof serviceRegistryAbi, 'serviceIds'>>
}

export function createServiceRegistryReaders(client: PublicClient, address: () => Address): ServiceRegistryReaders {
  return {
    getService: (serviceId: Hex, blockNumber?: bigint) => client.readContract({
      address: address(), abi: serviceRegistryAbi, functionName: 'getService', args: [serviceId], blockNumber,
    }),
    serviceCount: (blockNumber?: bigint) => client.readContract({
      address: address(), abi: serviceRegistryAbi, functionName: 'serviceCount', blockNumber,
    }),
    serviceIds: (offset: bigint, limit: bigint, blockNumber?: bigint) => {
      if (offset < 0n || limit < 1n || limit > 100n) throw new Error('Invalid ServiceRegistry page')
      return client.readContract({
        address: address(), abi: serviceRegistryAbi, functionName: 'serviceIds', args: [offset, limit], blockNumber,
      })
    },
  }
}

/**
 * Read metadata only after matching an explicit application approval. Never contacts the service.
 * This does NOT authenticate its endpoint, verify its manifest or authorize a verifier-agent
 * origin. Those checks must precede sending any credentials, session secrets or transactions.
 */
export async function readApprovedServiceRecord(
  chain: ServiceRegistryChainReader,
  approval: ServiceApproval,
): Promise<{record: ServiceRecord; blockNumber: bigint}> {
  const registry = requireAddress(chain.addresses, 'ServiceRegistry')
  if (registry.toLowerCase() !== approval.registry.toLowerCase()) throw new Error('Service registry approval mismatch')
  const chainId = await chain.client.getChainId()
  if (chainId !== approval.chainId || (chain.client.chain && chain.client.chain.id !== chainId)) {
    throw new Error('Service chain approval mismatch')
  }
  const blockNumber = await chain.client.getBlockNumber({cacheTime: 0})
  const record = await chain.readers.serviceRegistry.getService(approval.serviceId, blockNumber)
  if (record.status !== SERVICE_STATUSES.active) throw new Error('Service is not accepting new work')
  if (record.serviceType !== approval.serviceType || !Object.values(SERVICE_TYPES).includes(record.serviceType)) {
    throw new Error('Service type approval mismatch')
  }
  if (record.owner.toLowerCase() !== approval.owner.toLowerCase()) throw new Error('Service owner approval mismatch')
  if (record.revision !== approval.revision || record.revision < 1n) throw new Error('Service revision approval mismatch')
  if (record.manifestHash.toLowerCase() !== approval.manifestHash.toLowerCase()) {
    throw new Error('Service manifest approval mismatch')
  }
  return {record: {...record, serviceType: approval.serviceType, status: SERVICE_STATUSES.active}, blockNumber}
}
