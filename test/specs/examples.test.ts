import {afterEach, expect, test, vi} from 'vitest'
import {createExampleSlot} from '../../examples/slot-creation.ts'
import {committeeClient, required} from '../../examples/live-config.ts'
import {expectDenial} from '../live/acceptance-checks.ts'
import {createCommitteeSlotClient, type CreateSlotArgs, type TasraWriteClient, type TasraChainClient} from 'tasra-sdk/chain'
import type {CommitteeVerifier, HolderProofPerVerifier} from 'tasra-sdk/committee'
import {offlineRoundTrip} from '../../examples/offline.ts'

vi.mock('tasra-sdk/chain', async importOriginal => ({
  ...await importOriginal<typeof import('tasra-sdk/chain')>(),
  createCommitteeSlotClient: vi.fn(),
}))
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs() })

test('offline quick start is self-contained', () => expect(offlineRoundTrip()).toBe('Hello Tasra'))
test('missing live configuration fails explicitly', () => {
  expect(() => required('KK_RPC_URL', {})).toThrow('Missing KK_RPC_URL')
})
test('threshold creation follows registry requirement; export never weakens it', async () => {
  const direct = vi.fn().mockResolvedValue({slotId: 'created'})
  const commit = vi.fn().mockResolvedValue({slotId: 'committed'})
  const writer = {createSlot: direct, createSlotCommitReveal: commit} as unknown as TasraWriteClient
  const args: CreateSlotArgs = {dcqlRule: 'rule', k: 2, n: 3, mode: 'bls', exportable: false}
  await createExampleSlot(writer, false, args)
  expect(direct).toHaveBeenCalledWith(args)
  await createExampleSlot(writer, true, args)
  expect(commit).toHaveBeenCalledWith(args)
  await expect(createExampleSlot(writer, true, {...args, exportable: true})).rejects.toThrow('cannot create exportable')
  expect(commit).toHaveBeenCalledTimes(1)
  await createExampleSlot(writer, false, {...args, exportable: true})
  expect(direct).toHaveBeenLastCalledWith({...args, exportable: true})
})
test('application requests fresh holder proofs for every verifier and operation', async () => {
  vi.stubEnv('KK_VERIFIER_AUDIENCE', 'test-verifier')
  let calls = 0
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    new Response(JSON.stringify({nonce: `nonce-${++calls}`, expires_at: 9999999999})))
  const secretKey = new Uint8Array(32).fill(1)
  committeeClient({} as TasraChainClient, '0x' + 'ab'.repeat(32), {
    holder: 'did:example:test', signer: {alg: 'EdDSA', did: 'did:example:test', secretKey},
    secretKey, credentials: ['signed-credential'],
  }, 'decrypt')
  const cfg = vi.mocked(createCommitteeSlotClient).mock.calls.at(-1)![0]
  const proof = cfg.holderProof as HolderProofPerVerifier
  const first = {url: 'https://verifier-1.example'} as CommitteeVerifier
  const second = {url: 'https://verifier-2.example'} as CommitteeVerifier
  const proofs = await Promise.all([proof(first), proof(second), proof(first)])
  expect(new Set(proofs).size).toBe(3)
  expect(fetch.mock.calls.map(([url]) => url)).toEqual([
    'https://verifier-1.example/v1/nonce', 'https://verifier-2.example/v1/nonce', 'https://verifier-1.example/v1/nonce',
  ])
  const claims = JSON.parse(Buffer.from(proofs[0].split('.')[1]!, 'base64url').toString()) as {action: string; aud: string}
  expect(claims.action).toBe('decrypt')
  expect(claims.aud).toBe('test-verifier')
})
test('acceptance requires explicit refusal, never a connection failure or successful operation', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', {status: 403}))
  const deny = async () => { await globalThis.fetch('https://verifier.example/v1/committee-authorize'); throw new Error('refused') }
  await expect(expectDenial(deny)).resolves.toEqual([403])
  fetch.mockResolvedValue(new Response('', {status: 500}))
  await expect(expectDenial(deny)).rejects.toThrow('Expected explicit')
  fetch.mockRejectedValue(new Error('offline'))
  await expect(expectDenial(deny)).rejects.toThrow('Expected explicit')
  await expect(expectDenial(async () => undefined)).rejects.toThrow('Expected explicit')
})
