import {derivedNonce} from '../../src/oid4vp/binding.js'
import type {VerifiedRequestObject} from '../../src/oid4vp/request-object.js'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'
import {bytesToHex, type Address, type Hex} from 'viem'
import {privateKeyToAccount} from 'viem/accounts'
import {openRegisteredVerifierAgentSession, awaitRegisteredVerifierAgentResult, assertRegisteredWalletRequest} from '../../src/chain/registeredOperation.js'
import {createRegisteredAgentClient, AgentSessionCreationUnknownError, type ApprovedAgentProfile, type AgentTransport} from '../../src/chain/registeredAgent.js'
import {authenticateApprovedService} from '../../src/chain/serviceIdentity.js'
import type {ServiceRecord} from '../../src/chain/services.js'
import type {TasraChainClient} from '../../src/chain/client.js'
import type {CreateSessionParams} from '../../src/verifier-agent/index.js'
vi.mock('../../src/chain/serviceIdentity.js', async original => ({...await original<typeof import('../../src/chain/serviceIdentity.js')>(), authenticateApprovedService: vi.fn()}))
const address = (s: string) => `0x${s.repeat(20)}` as Address
const hash = (s: string) => `0x${s.repeat(32)}` as Hex
const encoded = (value: unknown) => new TextEncoder().encode(JSON.stringify(value))
const params: CreateSessionParams = {operation: {chain_id: 31337, slot_id: hash('11'), action: 'sign', payload_digest: hash('22'), description: 'Sign', exp: 1900000000}, operationSig: 'signature', messageHex: 'aabb'}

function harness() {
  const profiles: ApprovedAgentProfile[] = ['one', 'two'].map((host, i) => ({endpoint: `https://${host}.example/api`, clientId: `decentralized_identifier:did:web:${host}.example`,
    approval: {chainId: 31337, registry: address('11'), serviceId: hash(i ? '22' : '33'), serviceType: 1, owner: address(i ? '44' : '55'), revision: 1n, manifestHash: hash('66')}}))
  const records: ServiceRecord[] = profiles.map(p => ({owner: p.approval.owner, pendingOwner: address('00'), authKey: address('77'), serviceType: 1, status: 0, revision: 1n, manifestHash: p.approval.manifestHash, endpoint: p.endpoint}))
  const chain = {addresses: {ServiceRegistry: address('11')}, client: {getChainId: vi.fn(async () => 31337), getBlockNumber: vi.fn(async () => 1n)}, readers: {serviceRegistry: {getService: vi.fn(async (id: Hex) => ({...records[profiles.findIndex(p => p.approval.serviceId === id)]!}))}}} as unknown as TasraChainClient
  vi.mocked(authenticateApprovedService).mockImplementation(async (_, a) => {
    const i = profiles.findIndex(p => p.approval.serviceId === a.serviceId)
    if (records[i]!.status !== 0) throw new Error('inactive')
    return {record: {...records[i]!}, manifest: {capabilities: ['oid4vp']}} as Awaited<ReturnType<typeof authenticateApprovedService>>
  })
  const profilePin = (i: number) => { const p = profiles[i]!, a = p.approval; return {chainId: a.chainId, registry: a.registry, serviceId: a.serviceId, serviceType: 1, owner: a.owner, revision: '1', manifestHash: a.manifestHash, authKey: records[i]!.authKey, endpoint: p.endpoint, clientId: p.clientId} }
  const sessionId = (i: number) => (i ? '22' : '11').repeat(32)
  const reply = (i: number) => {
    const p = profiles[i]!, id = sessionId(i), request = `${p.endpoint}/v1/request/${id}`
    return {session_id: id, poll_secret: 'ab'.repeat(32), request_uri: request, qr_payload: `openid4vp://?client_id=${encodeURIComponent(p.clientId)}&request_uri=${encodeURIComponent(request)}`, service_profile: profilePin(i)}
  }
  const transport: AgentTransport = {request: vi.fn(), agentRequest: vi.fn(async (url, opts) => {
    const i = url.startsWith(profiles[0]!.endpoint) ? 0 : 1
    return encoded(opts.body ? reply(i) : {status: 'pending', phase: 'awaiting_wallet', binding_preimage: {service_profile: profilePin(i)}})
  })}
  return {profiles, records, chain, transport, reply, profilePin, client: createRegisteredAgentClient(chain, {profiles, transport})}
}
beforeEach(() => { vi.mocked(authenticateApprovedService).mockReset() })

describe('registered verifier-agent sessions', () => {
  it('pins the original provider while draining, with no bearer sent during discovery', async () => {
    const h = harness(), session = await h.client.createSession(params)
    h.records[0]!.status = 1; h.records[0]!.revision = 2n
    expect((await session.poll()).phase).toBe('awaiting_wallet')
    expect(authenticateApprovedService).toHaveBeenCalledTimes(1)
    const calls = vi.mocked(h.transport.agentRequest).mock.calls
    expect(calls[0]![1].bearer).toBeUndefined()
    expect(calls[1]![0]).toBe(`${h.profiles[0]!.endpoint}/v1/sessions/${session.sessionId}`)
    expect(calls[1]![1].bearer).toBe(session.pollSecret)
    expect(Object.isFrozen(session)).toBe(true)
  })
  it.each(['owner', 'authKey', 'manifestHash', 'endpoint', 'retired', 'chain'])('refuses %s changes before sending the poll secret', async change => {
    const h = harness(), session = await h.client.createSession(params)
    if (change === 'owner' || change === 'authKey') h.records[0]![change] = address('99')
    else if (change === 'manifestHash') h.records[0]!.manifestHash = hash('99')
    else if (change === 'endpoint') h.records[0]!.endpoint = 'https://attacker.example'
    else if (change === 'retired') h.records[0]!.status = 2
    else vi.mocked(h.chain.client.getChainId).mockResolvedValue(999)
    await expect(session.poll()).rejects.toThrow()
    expect(h.transport.agentRequest).toHaveBeenCalledTimes(1)
  })
  it('skips inactive discovery candidates and explicitly creates a fresh session at another provider', async () => {
    const h = harness(), original = await h.client.createSession(params)
    h.records[0]!.status = 1; h.records[0]!.revision = 2n
    const next = await h.client.createSession(params, {profileIndex: 1})
    expect(next.sessionId).not.toBe(original.sessionId)
    await original.poll()
    const last = vi.mocked(h.transport.agentRequest).mock.calls.at(-1)!
    expect(last[0]).toContain('one.example')
    const selected = await h.client.createSession(params)
    expect(selected.profile.endpoint).toContain('two.example')
  })
  it('does not fail over an uncertain creation POST automatically', async () => {
    const h = harness()
    vi.mocked(h.transport.agentRequest).mockRejectedValue(new Error('lost reply'))
    await expect(h.client.createSession(params)).rejects.toBeInstanceOf(AgentSessionCreationUnknownError)
    expect(h.transport.agentRequest).toHaveBeenCalledTimes(1)
    expect(authenticateApprovedService).toHaveBeenCalledTimes(1)
  })
  it.each(['request_uri', 'qr_payload', 'service_profile'])('refuses substituted wallet/profile metadata: %s', async field => {
    const h = harness()
    vi.mocked(h.transport.agentRequest).mockResolvedValue(encoded({...h.reply(0), [field]: 'https://attacker.example'}))
    await expect(h.client.createSession(params)).rejects.toThrow()
  })
  it('does not send operations to an unapproved endpoint returned by discovery', async () => {
    const h = harness(); h.records[0]!.endpoint = 'https://attacker.example'; h.records[1]!.status = 1
    await expect(h.client.createSession(params)).rejects.toThrow('No approved')
    expect(h.transport.agentRequest).not.toHaveBeenCalled()
  })
  it('bounds ignored cancellation without sending late secrets', async () => {
    const h = harness(), session = await h.client.createSession(params), controller = new AbortController()
    let release: (id: number) => void = () => {}
    vi.mocked(h.chain.client.getChainId).mockImplementation(() => new Promise<number>(resolve => {release = resolve}))
    const waiting = session.poll(controller.signal)
    const assertion = expect(waiting).rejects.toThrow()
    controller.abort(); await assertion; release(31337); await Promise.resolve(); await Promise.resolve()
    expect(h.transport.agentRequest).toHaveBeenCalledTimes(1)
  })
})

afterEach(() => vi.useRealTimers())

const input = () => ({chainId: 31337, keyRegistry: address('12'), slotId: hash('11'), action: 'sign' as const,
  message: new Uint8Array([1, 2, 3]), description: 'Approve this exact message', signer: privateKeyToAccount(hash('01'))})
describe('registered application operation flow', () => {
  it('retains authenticated polling and checks the returned operation binding', async () => {
    const h = harness(), session = await openRegisteredVerifierAgentSession(h.client, input())
    const expected = bytesToHex(session.requestHash)
    session.requestHash.fill(0) // callers cannot mutate the stored expected binding
    expect(bytesToHex(session.requestHash)).toBe(expected)
    const token = {token_type: 'JWT', seed: hash('12'), slot_id: hash('11'), vp_hash: hash('12'), holder_hash: hash('12'), rule_hash: hash('12'), epoch: 1, iat: 100, exp: 200,
      request_hash: expected, binding: 'holder_key', verifier_indexes: [0], signatures: [{verifier_index: 0, signature: '0x' + '34'.repeat(64)}]}
    vi.mocked(h.transport.agentRequest).mockResolvedValue(encoded({status: 'done', phase: 'done', compound_token: token, binding_preimage: {service_profile: h.profilePin(0)}}))
    expect((await awaitRegisteredVerifierAgentResult(session)).token.request_hash).toBe(expected)
    vi.mocked(h.transport.agentRequest).mockResolvedValue(encoded({status: 'done', phase: 'done', compound_token: {...token, request_hash: hash('99')}, binding_preimage: {service_profile: h.profilePin(0)}}))
    await expect(awaitRegisteredVerifierAgentResult(session)).rejects.toThrow(/does not bind/)
    h.records[0]!.authKey = address('99')
    const calls = vi.mocked(h.transport.agentRequest).mock.calls.length
    await expect(awaitRegisteredVerifierAgentResult(session)).rejects.toThrow(/profile changed/)
    expect(h.transport.agentRequest).toHaveBeenCalledTimes(calls)
  })
  it('enforces the caller deadline even when a transport ignores cancellation', async () => {
    vi.useFakeTimers()
    const h = harness(), session = await openRegisteredVerifierAgentSession(h.client, input())
    vi.mocked(h.transport.agentRequest).mockImplementation(() => new Promise(() => {}))
    const assertion = expect(awaitRegisteredVerifierAgentResult(session, {timeoutMs: 50})).rejects.toMatchObject({kind: 'timeout'})
    await vi.advanceTimersByTimeAsync(50)
    await assertion
  })
  it('cancels before polling and never automatically creates a replacement session', async () => {
    const h = harness(), session = await openRegisteredVerifierAgentSession(h.client, input()), controller = new AbortController()
    controller.abort()
    await expect(awaitRegisteredVerifierAgentResult(session, {signal: controller.signal})).rejects.toMatchObject({kind: 'cancelled'})
    expect(h.transport.agentRequest).toHaveBeenCalledTimes(1)
  })
})

it('refuses substituted wallet operation, nonce, audience and disclosure endpoint', async () => {
  const h = harness(), session = await openRegisteredVerifierAgentSession(h.client, input())
  const random = new Uint8Array(32).fill(1), snapshotRoot = new Uint8Array(32).fill(2)
  const nonce = derivedNonce(session.requestHash, random, {epoch: 1, snapshotRoot, registrySize: 3, committee: 3, quorum: 2, operationExp: session.operation.exp})
  const td = {...session.operation, type: 'keykeeper-op/v1', credential_ids: ['licence']}
  const ro = {jwt: 'already-verified', header: {alg: 'EdDSA'}, signerDid: session.profile.clientId.replace('decentralized_identifier:', ''), signerKey: {kty: 'OKP', crv: 'Ed25519', x: ''}, claims: {
    iss: session.profile.clientId.replace('decentralized_identifier:', ''), client_id: session.profile.clientId,
    response_mode: 'direct_post.jwt', response_uri: session.profile.endpoint + '/v1/response?session=' + session.sessionId, nonce, state: 'state', exp: session.operation.exp,
    dcql_query: {credentials: []}, transaction_data: [Buffer.from(JSON.stringify(td)).toString('base64url')],
  }} as VerifiedRequestObject
  const status = {status: 'pending' as const, phase: 'awaiting_wallet' as const, bindingPreimage: {operation: session.operation, random: bytesToHex(random), snapshot_root: bytesToHex(snapshotRoot), epoch: 1, registry_size: 3, committee_count: 3, quorum: 2, nonce}}
  expect(() => assertRegisteredWalletRequest(session, ro, status)).not.toThrow()
  expect(() => assertRegisteredWalletRequest(session, {...ro, claims: {...ro.claims,
    response_uri: session.profile.endpoint + '/v1/response?session=' + 'ff'.repeat(32),
  }}, status)).toThrow(/outside/)
  for (const field of ['client_id', 'response_uri', 'nonce', 'transaction_data'] as const) {
    const bad = {...ro, claims: {...ro.claims, [field]: field === 'transaction_data' ? [Buffer.from(JSON.stringify({...td, description: 'Different authorization'})).toString('base64url')] : 'different'}}
    expect(() => assertRegisteredWalletRequest(session, bad, status)).toThrow()
  }
  expect(() => assertRegisteredWalletRequest(session, ro, {...status, bindingPreimage: {...status.bindingPreimage, operation: {...session.operation, action: 'decrypt'}}})).toThrow(/operation/)
})

// ⚠⚠ A JAR WITHOUT `transaction_data` IS VALID. Requiring it made the Tasra Vault the only
//    wallet that could complete a presentation on any fleet, because Hovi silently never POSTs
//    a response when the entry is present — so one QR could serve one wallet, never both.
//    These pin the exact envelope: absent is accepted, present is still checked strictly, and
//    nothing that was bound before became unbound.
it('accepts a Request Object with no transaction_data, and still binds the operation', async () => {
  const h = harness(), session = await openRegisteredVerifierAgentSession(h.client, input())
  const random = new Uint8Array(32).fill(1), snapshotRoot = new Uint8Array(32).fill(2)
  const nonce = derivedNonce(session.requestHash, random, {epoch: 1, snapshotRoot, registrySize: 3, committee: 3, quorum: 2, operationExp: session.operation.exp})
  const base = {jwt: 'already-verified', header: {alg: 'EdDSA'}, signerDid: session.profile.clientId.replace('decentralized_identifier:', ''), signerKey: {kty: 'OKP', crv: 'Ed25519', x: ''}, claims: {
    iss: session.profile.clientId.replace('decentralized_identifier:', ''), client_id: session.profile.clientId,
    response_mode: 'direct_post.jwt', response_uri: session.profile.endpoint + '/v1/response?session=' + session.sessionId, nonce, state: 'state', exp: session.operation.exp,
    dcql_query: {credentials: []},
  }} as VerifiedRequestObject
  const status = {status: 'pending' as const, phase: 'awaiting_wallet' as const, bindingPreimage: {operation: session.operation, random: bytesToHex(random), snapshot_root: bytesToHex(snapshotRoot), epoch: 1, registry_size: 3, committee_count: 3, quorum: 2, nonce}}

  // The Hovi-compatible JAR. This threw 'Wallet request has no unique transaction data'.
  expect(() => assertRegisteredWalletRequest(session, base, status)).not.toThrow()

  // ⚠ What survives the relaxation: request_hash covers chain_id, slot_id, action and
  //   payload_digest, and the nonce is derived from it — so a substituted operation is still
  //   refused with no transaction_data anywhere in the request.
  expect(() => assertRegisteredWalletRequest(session, base, {...status, bindingPreimage: {...status.bindingPreimage, operation: {...session.operation, action: 'decrypt'}}})).toThrow(/operation/)
  expect(() => assertRegisteredWalletRequest(session, {...base, claims: {...base.claims, nonce: 'different'}}, status)).toThrow(/nonce/)
})

it('still checks transaction_data strictly whenever the Request Object carries it', async () => {
  const h = harness(), session = await openRegisteredVerifierAgentSession(h.client, input())
  const random = new Uint8Array(32).fill(1), snapshotRoot = new Uint8Array(32).fill(2)
  const nonce = derivedNonce(session.requestHash, random, {epoch: 1, snapshotRoot, registrySize: 3, committee: 3, quorum: 2, operationExp: session.operation.exp})
  const td = {...session.operation, type: 'keykeeper-op/v1', credential_ids: ['licence']}
  const encode = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url')
  const withTd = (transaction_data: string[]) => ({jwt: 'already-verified', header: {alg: 'EdDSA'}, signerDid: session.profile.clientId.replace('decentralized_identifier:', ''), signerKey: {kty: 'OKP', crv: 'Ed25519', x: ''}, claims: {
    iss: session.profile.clientId.replace('decentralized_identifier:', ''), client_id: session.profile.clientId,
    response_mode: 'direct_post.jwt', response_uri: session.profile.endpoint + '/v1/response?session=' + session.sessionId, nonce, state: 'state', exp: session.operation.exp,
    dcql_query: {credentials: []}, transaction_data,
  }} as VerifiedRequestObject)
  const status = {status: 'pending' as const, phase: 'awaiting_wallet' as const, bindingPreimage: {operation: session.operation, random: bytesToHex(random), snapshot_root: bytesToHex(snapshotRoot), epoch: 1, registry_size: 3, committee_count: 3, quorum: 2, nonce}}

  expect(() => assertRegisteredWalletRequest(session, withTd([encode(td)]), status)).not.toThrow()
  // A description the creator never authorized is still refused — that is the whole point of
  // the entry, and it is the one field the nonce does NOT bind.
  expect(() => assertRegisteredWalletRequest(session, withTd([encode({...td, description: 'Different authorization'})]), status)).toThrow()
  expect(() => assertRegisteredWalletRequest(session, withTd([encode({...td, type: 'other/v1'})]), status)).toThrow()
  // Two entries are ambiguous about what was authorized, so they stay refused.
  expect(() => assertRegisteredWalletRequest(session, withTd([encode(td), encode(td)]), status)).toThrow(/unique transaction data/)
  expect(() => assertRegisteredWalletRequest(session, withTd([]), status)).toThrow(/unique transaction data/)
})
