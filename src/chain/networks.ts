import document from './network-profiles.json' with {type: 'json'}
import type {Address} from './deployments.js'

export type NetworkName = 'local' | 'testnet' | 'mainnet'
export interface NetworkPreset {
  readonly chainId: number
  readonly rpcUrl: string
  readonly nativeCurrency: Readonly<{name: string; symbol: string; decimals: number}>
  readonly eurc: Readonly<{kind: 'mock' | 'circle'; address: string | null; name: string; symbol: string; decimals: number; faucet: boolean}>
  readonly governance: Readonly<{delaySecs: number; floorSecs: number}>
  readonly productionPosture: boolean
}
export interface ResolvedNetworkProfile extends NetworkPreset {
  readonly environment: NetworkName
  readonly eurc: NetworkPreset['eurc'] & {readonly address: Address}
}

// Vendored deployment policy; refresh manually from the network configuration.
export const NETWORKS: Readonly<Record<NetworkName, NetworkPreset>> = Object.freeze(
  Object.fromEntries(Object.entries(document.profiles).map(([name, p]) => [name, Object.freeze({
    ...p, eurc: Object.freeze(p.eurc), nativeCurrency: Object.freeze(p.nativeCurrency), governance: Object.freeze(p.governance),
  })])) as Record<NetworkName, NetworkPreset>,
)

export function networkNameForChain(chainId: number): NetworkName {
  if ([43112, 1337, 31337].includes(chainId)) return 'local'
  if (chainId === 43113) return 'testnet'
  if (chainId === 43114) return 'mainnet'
  throw new Error(`Unsupported network chain ID: ${chainId}`)
}

export function resolveNetworkProfile(environment: NetworkName, options: {
  chainId?: number; rpcUrl?: string; eurcAddress?: string
} = {}): ResolvedNetworkProfile {
  if (!Object.hasOwn(NETWORKS, environment)) throw new Error(`Unknown network profile: ${environment}`)
  const preset = NETWORKS[environment]
  const chainId = options.chainId ?? preset.chainId
  if (networkNameForChain(chainId) !== environment) throw new Error('Network profile does not match chain ID')
  const rpcUrl = options.rpcUrl ?? preset.rpcUrl
  const rpc = new URL(rpcUrl)
  if (!['http:', 'https:'].includes(rpc.protocol) || rpc.username || rpc.password || rpc.hash ||
      (environment !== 'local' && rpc.protocol !== 'https:')) throw new Error('Invalid RPC URL for network profile')
  const address = (options.eurcAddress ?? preset.eurc.address)?.toLowerCase()
  if (!address || !/^0x[0-9a-f]{40}$/.test(address) || /^0x0{40}$/.test(address)) {
    throw new Error('Network profile requires the deployed EURC token address')
  }
  if (environment === 'mainnet' && address !== preset.eurc.address) throw new Error('Mainnet requires official Circle EURC')
  if (environment !== 'mainnet' && [NETWORKS.mainnet.eurc.address, '0x5e44db7996c682e92a960b65ac713a54ad815c6b'].includes(address)) {
    throw new Error('Local and testnet require our own Mock EURC, not a Circle token')
  }
  return Object.freeze({...preset, environment, chainId, rpcUrl, eurc: Object.freeze({...preset.eurc, address: address as Address})})
}

/** Recheck the actual RPC chain immediately before any faucet transaction. */
export function assertEurcFaucetAllowed(profile: ResolvedNetworkProfile, actualChainId: number, actualEurcAddress: string): void {
  const validated = resolveNetworkProfile(profile.environment, {chainId: actualChainId, eurcAddress: actualEurcAddress})
  if (!validated.eurc.faucet || !profile.eurc.faucet || profile.eurc.kind !== 'mock' ||
      profile.chainId !== actualChainId || profile.eurc.address.toLowerCase() !== actualEurcAddress.toLowerCase()) {
    throw new Error('EURC faucet is disabled for this network or token')
  }
}
