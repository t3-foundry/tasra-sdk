import {describe, expect, it, vi} from 'vitest'
import {
  PROVISION_RULE_ACTION,
  provisionRule,
  provisionRuleTypedData,
} from '../../src/chain/provisionRule.js'
import {ruleCommitment} from '../../src/chain/write.js'

const SLOT = `0x${'11'.repeat(32)}` as const
const SALT = `0x${'22'.repeat(32)}` as const
const RULE = 'any'
const KEY_REGISTRY = `0x${'33'.repeat(20)}` as const

/** Enough of a chain client for a call that never reads anything but the address book. */
function fakeChain() {
  return {
    client: {chain: {id: 43112}},
    addresses: {KeyRegistry: KEY_REGISTRY},
  } as never
}

function signer(calls: unknown[] = []) {
  return {
    signTypedData: async (td: unknown) => {
      calls.push(td)
      return `0x${'ab'.repeat(65)}` as const
    },
  }
}

describe('provisionRuleTypedData', () => {
  it('signs the SALTED COMMITMENT, not the rule', () => {
    // The digest is what makes the signature mean "provision the preimage of commitment X"
    // rather than "provision anything for this slot". Swapping the rule after signing must
    // therefore produce a different digest.
    const td = provisionRuleTypedData({
      chainId: 43112, keyRegistry: KEY_REGISTRY, slotId: SLOT,
      commitment: ruleCommitment(SALT, RULE), description: '', exp: 1,
    })
    expect(td.message.payloadDigest).toBe(ruleCommitment(SALT, RULE))
    expect(td.message.payloadDigest).not.toBe(ruleCommitment(SALT, 'other'))
  })

  it('uses the shared Keykeeper Presentation domain', () => {
    // ⚠ The Rust verifier checks this with the SAME `keykeeper_eth::presentation_auth` it uses
    // for ADR-0069 D5. These four values are an encoding the compiler cannot check on either
    // side, so they are pinned here: a drift is a signature nobody made.
    const td = provisionRuleTypedData({
      chainId: 43112, keyRegistry: KEY_REGISTRY, slotId: SLOT,
      commitment: ruleCommitment(SALT, RULE), description: 'd', exp: 2,
    })
    expect(td.domain.name).toBe('Keykeeper Presentation')
    expect(td.domain.version).toBe('1')
    expect(td.domain.verifyingContract).toBe(KEY_REGISTRY)
    expect(td.primaryType).toBe('PresentationOperation')
    expect(td.message.action).toBe('provision-rule')
  })
})

describe('provisionRule', () => {
  it('posts the body shape the keeper deserializes', async () => {
    // Field names are snake_case because they are matched by a Rust
    // `#[derive(Deserialize)]` struct — a rename on either side is a 400, not a type error.
    let seen: {url: string; body: Record<string, unknown>} | undefined
    const fetchImpl = vi.fn(async (url: string, init: RequestInit) => {
      seen = {url, body: JSON.parse(String(init.body))}
      return new Response(JSON.stringify({provisioned: true, pending: false}), {status: 200})
    }) as unknown as typeof fetch

    await provisionRule(fakeChain(), {
      slotId: SLOT, dcqlRule: RULE, ruleSalt: SALT, signer: signer(),
      keeperUrls: ['http://k1'], fetchImpl, nowSecs: 1000,
    })

    expect(seen?.url).toBe(`http://k1/v1/keys/${SLOT.slice(2)}/rule/by-creator`)
    expect(seen?.body.dcql_rule).toBe(RULE)
    expect(seen?.body.dcql_salt).toBe(SALT)
    const auth = seen?.body.authorization as Record<string, unknown>
    expect(auth.action).toBe(PROVISION_RULE_ACTION)
    expect(auth.slot_id).toBe(SLOT)
    expect(auth.payload_digest).toBe(ruleCommitment(SALT, RULE))
    expect(auth.chain_id).toBe(43112)
    expect(auth.exp).toBe(1600)
    expect(typeof auth.operation_sig).toBe('string')
  })

  it('sends ONE signature to every drawn keeper', async () => {
    // Deliberate: the same rule goes to the whole committee, so replay to a sibling keeper is
    // the intended behaviour. Re-signing per keeper would buy nothing and cost a wallet prompt.
    const signed: unknown[] = []
    const urls: string[] = []
    const fetchImpl = vi.fn(async (url: string) => {
      urls.push(String(url))
      return new Response('{}', {status: 200})
    }) as unknown as typeof fetch

    await provisionRule(fakeChain(), {
      slotId: SLOT, dcqlRule: RULE, ruleSalt: SALT, signer: signer(signed),
      keeperUrls: ['http://k1', 'http://k2/', 'http://k3'], fetchImpl,
    })
    expect(signed).toHaveLength(1)
    expect(urls).toHaveLength(3)
    // A trailing slash must not produce a double slash in the path.
    expect(urls[1]).toBe(`http://k2/v1/keys/${SLOT.slice(2)}/rule/by-creator`)
  })

  it('reports a PARTIAL fan-out as recoverable, naming self-heal', async () => {
    // A partial fan-out is not a lost slot: each keeper that missed it re-fetches the rule
    // from a peer and checks it against the on-chain commitment. Saying "the slot is unusable"
    // here would be false, and would send someone to recreate a slot that will fix itself.
    const fetchImpl = vi.fn(async (url: string) =>
      String(url).includes('k2') ? new Response('nope', {status: 503}) : new Response('{}', {status: 200}),
    ) as unknown as typeof fetch

    await expect(
      provisionRule(fakeChain(), {
        slotId: SLOT, dcqlRule: RULE, ruleSalt: SALT, signer: signer(),
        keeperUrls: ['http://k1', 'http://k2'], fetchImpl,
      }),
    ).rejects.toThrow(/1 of 2 keepers accepted.*self-heal/s)
  })

  it('reports a TOTAL failure as unrecoverable, because nothing can heal from nothing', async () => {
    // Peer rule-heal needs at least one keeper that already holds the rule. Zero is the one
    // case that genuinely has to be retried, and it must not read like the partial case.
    const fetchImpl = vi.fn(async () => new Response('down', {status: 502})) as unknown as typeof fetch
    await expect(
      provisionRule(fakeChain(), {
        slotId: SLOT, dcqlRule: RULE, ruleSalt: SALT, signer: signer(),
        keeperUrls: ['http://k1', 'http://k2'], fetchImpl,
      }),
    ).rejects.toThrow(/0 of 2.*nothing can self-heal/s)
  })

  it('refuses a malformed salt before signing anything', async () => {
    // Omitting or mistyping the salt could only ever produce a commitment mismatch, which the
    // keeper reports as a RULE error — the confusing failure the CLI's optional salt caused.
    const signed: unknown[] = []
    await expect(
      provisionRule(fakeChain(), {
        slotId: SLOT, dcqlRule: RULE, ruleSalt: '0xdeadbeef' as `0x${string}`,
        signer: signer(signed), keeperUrls: ['http://k1'],
      }),
    ).rejects.toThrow(/ruleSalt must be 32 bytes/)
    expect(signed).toHaveLength(0)
  })
})
