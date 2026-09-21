import {expect, it} from 'vitest'
import {parseApplicationServiceProfiles, applicationServiceProfilesDocument} from '../../src/chain/serviceProfiles.js'
const entry = {serviceId: `0x${'11'.repeat(32)}`, owner: `0x${'22'.repeat(20)}`, revision: '18446744073709551615', manifestHash: `0x${'33'.repeat(32)}`, endpoint: 'https://relay.example'}
const document = {schemaVersion: 1, chainId: 43113, registry: `0x${'44'.repeat(20)}`, relayers: [entry], verifierAgents: [], vaultServices: []}
it('roundtrips reviewed approval pins without losing uint64 revision precision', () => {
  const profiles = parseApplicationServiceProfiles(JSON.stringify(document))
  expect(profiles.relayers[0]!.approval.revision).toBe(18446744073709551615n)
  expect(profiles.relayers[0]!.approval.serviceType).toBe(0)
  expect(applicationServiceProfilesDocument(profiles)).toEqual(document)
})
it('rejects duplicate identities and invalid approval pins', () => {
  expect(() => parseApplicationServiceProfiles({...document, vaultServices: [entry]})).toThrow(/Duplicate/)
  expect(() => parseApplicationServiceProfiles({...document, relayers: [{...entry, revision: '18446744073709551616'}]})).toThrow(/revision/)
  expect(() => parseApplicationServiceProfiles({...document, relayers: [{...entry, endpoint: 'http://relay.example'}]})).toThrow()
  expect(() => parseApplicationServiceProfiles({...document, faucet: true})).toThrow(/fields/)
})
it('does not silently relabel a verifier-agent as a gas relayer when publishing', () => {
  const profiles = parseApplicationServiceProfiles(document)
  profiles.relayers[0]!.approval.serviceType = 1
  expect(() => applicationServiceProfilesDocument(profiles)).toThrow(/mismatch/)
})
