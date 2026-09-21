import {describe, expect, it} from 'vitest'
import {NETWORKS, resolveNetworkProfile, assertEurcFaucetAllowed} from '../../src/chain/networks.js'
const mock = '0x1111111111111111111111111111111111111111'
describe('network currency policy', () => {
  it.each(['local', 'testnet'] as const)('uses our six-decimal mock on %s', environment => {
    const p = resolveNetworkProfile(environment, {eurcAddress: mock})
    expect(p.eurc).toMatchObject({kind: 'mock', decimals: 6, symbol: 'KKEUR', faucet: true})
    expect(() => assertEurcFaucetAllowed(p, p.chainId, mock)).not.toThrow()
    expect(() => resolveNetworkProfile(environment)).toThrow(/deployed/)
    expect(() => resolveNetworkProfile(environment, {eurcAddress: NETWORKS.mainnet.eurc.address!})).toThrow(/own Mock/)
    expect(() => resolveNetworkProfile(environment, {eurcAddress: '0x5E44db7996c682E92a960b65AC713a54AD815c6B'})).toThrow(/own Mock/)
  })
  it('pins Circle mainnet and refuses minting without relying on a token revert', () => {
    const p = resolveNetworkProfile('mainnet')
    expect(p.chainId).toBe(43114)
    expect(p.eurc.address).toBe('0xc891eb4cbdeff6e073e859e987815ed1505c2acd')
    expect(p.eurc.faucet).toBe(false)
    expect(() => assertEurcFaucetAllowed(p, 43114, p.eurc.address)).toThrow(/disabled/)
    expect(() => resolveNetworkProfile('mainnet', {eurcAddress: mock})).toThrow(/official Circle/)
  })
  it('rejects mislabelled mainnet RPC, unknown chains, and changed tokens', () => {
    const p = resolveNetworkProfile('testnet', {eurcAddress: mock})
    expect(() => assertEurcFaucetAllowed(p, 43114, mock)).toThrow(/chain ID/)
    expect(() => assertEurcFaucetAllowed(p, 43113, '0x2222222222222222222222222222222222222222')).toThrow(/disabled/)
    expect(() => resolveNetworkProfile('local', {chainId: 1, eurcAddress: mock})).toThrow(/Unsupported/)
    expect(() => resolveNetworkProfile('mainnet', {rpcUrl: 'http://localhost:8545'})).toThrow(/RPC/)
    expect(Object.isFrozen(NETWORKS.mainnet.eurc)).toBe(true)
  })
})
