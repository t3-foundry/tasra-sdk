import type {Address, Hex} from 'viem'
import {validateServiceEndpoint} from './serviceIdentity.js'
import type {ServiceApproval, ServiceType} from './services.js'
import type {ApprovedAgentProfile} from './registeredAgent.js'

export interface ApprovedServiceProfile {
  approval: ServiceApproval
  endpoint: string
}

/** Reviewed application configuration, never a list downloaded from a service registry. */
export interface ApplicationServiceProfiles {
  chainId: number
  registry: Address
  relayers: ApprovedServiceProfile[]
  verifierAgents: ApprovedAgentProfile[]
  vaultServices: ApprovedServiceProfile[]
}

function object(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid service profile object')
  const o = value as Record<string, unknown>
  if (Object.keys(o).length !== fields.length || fields.some(k => !Object.hasOwn(o, k))) throw new Error('Unexpected or missing service profile fields')
  return o
}

function hex(value: unknown, bytes: number): Hex {
  if (typeof value !== 'string' || !new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(value) || /^0x0+$/.test(value)) throw new Error('Invalid service profile address or hash')
  return value.toLowerCase() as Hex
}

/** Parse the public, JSON-safe deployment approval file. Decimal revisions preserve uint64. */
export function parseApplicationServiceProfiles(value: unknown): ApplicationServiceProfiles {
  if (typeof value === 'string') {
    if (new TextEncoder().encode(value).length > 65_536) throw new Error('Service profile file too large')
    value = JSON.parse(value) as unknown
  }
  const o = object(value, ['schemaVersion', 'chainId', 'registry', 'relayers', 'verifierAgents', 'vaultServices'])
  if (o.schemaVersion !== 1 || !Number.isSafeInteger(o.chainId) || Number(o.chainId) < 1) throw new Error('Invalid service profile version or chain')
  const chainId = Number(o.chainId), registry = hex(o.registry, 20)
  const ids = new Set<string>()
  function profiles(input: unknown, serviceType: ServiceType): Array<ApprovedServiceProfile & {clientId?: string}> {
    if (!Array.isArray(input) || input.length > 16) throw new Error('At most 16 profiles per service type are allowed')
    return input.map(item => {
      const p = object(item, ['serviceId', 'owner', 'revision', 'manifestHash', 'endpoint', ...(serviceType === 1 ? ['clientId'] : [])])
      const serviceId = hex(p.serviceId, 32), owner = hex(p.owner, 20), manifestHash = hex(p.manifestHash, 32)
      if (ids.has(serviceId)) throw new Error('Duplicate approved service ID')
      ids.add(serviceId)
      if (typeof p.revision !== 'string' || !/^[1-9][0-9]{0,19}$/.test(p.revision) || BigInt(p.revision) > (1n << 64n) - 1n) throw new Error('Invalid service revision')
      if (typeof p.endpoint !== 'string') throw new Error('Service endpoint is required')
      validateServiceEndpoint(p.endpoint)
      const approval = {chainId, registry, serviceId, serviceType, owner, revision: BigInt(p.revision), manifestHash}
      if (serviceType === 1) {
        if (typeof p.clientId !== 'string' || !/^decentralized_identifier:did:web:[a-z0-9.-]+(?:(?:%3A)[0-9]+)?$/.test(p.clientId)) throw new Error('Invalid verifier-agent audience')
        return {approval, endpoint: p.endpoint, clientId: p.clientId}
      }
      return {approval, endpoint: p.endpoint}
    })
  }
  const relayers = profiles(o.relayers, 0), verifierAgents = profiles(o.verifierAgents, 1) as ApprovedAgentProfile[], vaultServices = profiles(o.vaultServices, 2)
  if (new Set(verifierAgents.map(p => new URL(p.endpoint).origin)).size !== verifierAgents.length || new Set(verifierAgents.map(p => p.clientId)).size !== verifierAgents.length) throw new Error('Independent verifier-agents require distinct origins and audiences')
  return {chainId, registry, relayers, verifierAgents, vaultServices}
}

/** Publish only public approvals, with no runtime transport or private key material. */
export function applicationServiceProfilesDocument(profiles: ApplicationServiceProfiles): Record<string, unknown> {
  function entries(values: readonly (ApprovedServiceProfile & {clientId?: string})[], serviceType: ServiceType) {
    return values.map(({approval: a, endpoint, clientId}) => {
      if (a.serviceType !== serviceType || a.chainId !== profiles.chainId || a.registry.toLowerCase() !== profiles.registry.toLowerCase()) throw new Error('Service profile deployment mismatch')
      return {serviceId: a.serviceId, owner: a.owner, revision: a.revision.toString(), manifestHash: a.manifestHash, endpoint, ...(clientId !== undefined ? {clientId} : {})}
    })
  }
  const document = {schemaVersion: 1, chainId: profiles.chainId, registry: profiles.registry,
    relayers: entries(profiles.relayers, 0), verifierAgents: entries(profiles.verifierAgents, 1), vaultServices: entries(profiles.vaultServices, 2)}
  parseApplicationServiceProfiles(document)
  return document
}
