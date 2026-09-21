// Committee guards — the draw's edges, token verification's refusals, and the optional-field
// wiring the happy paths never reach.
//
// The committee flow is covered end to end elsewhere (committee.flow, committee.request,
// committee.one-call, the conformance vectors). What was left is the branch that fires when
// something is WRONG, which here is most of the security surface: the draw decides who may
// sign, and token verification decides whether what they signed counts.
//
// Three groups carry the weight:
//
//   • THE DRAW's edges. `selectVerifierCommittee` takes no caller-chosen input by design
//     (the source records that hashing a caller-picked vpHash was ground offline until the
//     draw came out favourable). Its guards are therefore about the REGISTRY: an empty one,
//     a committee larger than the set, and the rejection-sampling cap that stops an
//     unsatisfiable request looping forever.
//
//   • TOKEN VERIFICATION's refusals. Each one is a distinct attack: a token bound to another
//     rule, a committee that is not the draw for that (slot, epoch, seed), a signature from
//     someone outside the active set, a token presented before it is valid. A missing check
//     is an accepted token, not a crash.
//
//   • THE OPTIONAL FIELDS on committeeDecrypt and the extraction request. Each is a keeper
//     check the caller can silently lose: a user signature, a ciphertext epoch, verifier
//     proofs, a client binding. `client_pubkey`/`client_signature` are both-or-neither.
//
// Run: tsx test/committee.guards.ts — exits non-zero on any failure.

import {ed25519} from '@noble/curves/ed25519'
import {
  BINDING_HOLDER_KEY,
  BINDING_ISSUER_ASSERTED,
  BINDING_UNBOUND,
  assembleCompoundToken,
  bindingFromWire,
  bindingToWire,
  compoundTokenHash,
  decodeCompoundToken,
  merkleRoot,
  selectVerifierCommittee,
  verifierLeaf,
  verifyCompoundToken,
  type CompoundTokenPayload,
  type VerifierSet,
} from '../src/committee/token.ts'
import {
  committeeAuthorize,
  committeeDecrypt,
  committeeSign,
  gatherCommitteeToken,
  requestIbeExtractionPartials,
} from '../src/committee/client.ts'
import {
  buildVerifierProofs,
  committeeChainReadsFromClient,
  pinnedDraw,
  requestCommitteeToken,
  type CommitteeChainReads,
} from '../src/committee/request.ts'
import {bytesToHex} from '../src/crypto/hex.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean, detail = ''): void {
  if (cond) passed++
  else failures.push(name + (detail ? ` — ${detail}` : ''))
}
function eq(name: string, actual: unknown, expected: unknown): void {
  const json = (v: unknown): string => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? `${x}n` : x))
  const a = json(actual)
  const b = json(expected)
  ok(name, a === b, `got ${a}, want ${b}`)
}
function throwsWith(name: string, re: RegExp, run: () => unknown): void {
  try {
    run()
    ok(name, false, 'did not throw')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    ok(name, re.test(message), `message was ${JSON.stringify(message)}`)
  }
}
async function rejectsWith(name: string, re: RegExp, run: () => Promise<unknown>): Promise<void> {
  try {
    await run()
    ok(name, false, 'did not throw')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    ok(name, re.test(message), `message was ${JSON.stringify(message)}`)
  }
}
const fill = (n: number, v: number): Uint8Array => new Uint8Array(n).fill(v)
const bareHex = (b: Uint8Array): string => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')

// ─── the draw's edges ─────────────────────────────────────────────────────────
{
  const slotId = fill(32, 0xcd)
  const seed = fill(32, 0x5e)

  throwsWith('an empty registry is refused', /verifier registry is empty/, () =>
    selectVerifierCommittee(slotId, 1, seed, 0, 1),
  )
  // ⚠ A committee larger than the registry is unsatisfiable by construction — the draw picks
  // DISTINCT members. Refusing up front (naming both numbers) beats looping to the cap.
  throwsWith('a committee larger than the registry is refused, naming both', /requested 6 distinct members from a registry of only 5/, () =>
    selectVerifierCommittee(slotId, 1, seed, 5, 6),
  )
  // Zero is a legitimate request and must return empty rather than loop or throw.
  eq('a zero-member committee is an empty draw', selectVerifierCommittee(slotId, 1, seed, 5, 0), [])
  // The whole registry is the boundary case: satisfiable, but only just.
  eq('a committee equal to the registry size draws everyone', selectVerifierCommittee(slotId, 1, seed, 5, 5).slice().sort((a, b) => a - b), [0, 1, 2, 3, 4])

  // The draw is a pure function of (slotId, epoch, seed, registrySize) — no caller input, and
  // no randomness. Every verifier must reach the same answer independently.
  eq('the draw is deterministic', selectVerifierCommittee(slotId, 7, seed, 10, 3), selectVerifierCommittee(slotId, 7, seed, 10, 3))
  for (const [label, a] of [
    ['the slot', selectVerifierCommittee(fill(32, 0xce), 7, seed, 10, 3)],
    ['the epoch', selectVerifierCommittee(slotId, 8, seed, 10, 3)],
    ['the seed', selectVerifierCommittee(slotId, 7, fill(32, 0x5f), 10, 3)],
  ] as const) {
    ok(`changing ${label} changes the draw`, JSON.stringify(a) !== JSON.stringify(selectVerifierCommittee(slotId, 7, seed, 10, 3)))
  }
  eq('a bigint epoch matches the number form', selectVerifierCommittee(slotId, 7n, seed, 10, 3), selectVerifierCommittee(slotId, 7, seed, 10, 3))
  ok('every drawn index is in range', selectVerifierCommittee(slotId, 7, seed, 10, 4).every(i => i >= 0 && i < 10))
  eq('drawn indexes are distinct', new Set(selectVerifierCommittee(slotId, 7, seed, 50, 10)).size, 10)
}

// ─── merkle root + leaves ─────────────────────────────────────────────────────
{
  // An empty set has no root — `null`, not a zero hash. A zero root would compare equal to an
  // unset on-chain snapshot, which is exactly the confusion the committee flow avoids by
  // treating a zero root as "nothing anchored".
  eq('an empty leaf set has no root', merkleRoot([]), null)
  const leaf = (i: number): Uint8Array => verifierLeaf(i, fill(20, 0x10 + i), fill(32, 0x20 + i))
  ok('a single leaf is its own root', bareHex(merkleRoot([leaf(0)])!) === bareHex(leaf(0)))
  // An odd node is promoted unchanged to the next level, so an odd count still roots.
  ok('three leaves produce a root', merkleRoot([leaf(0), leaf(1), leaf(2)])!.length === 32)
  // ⚠ SORTED-PAIR hashing (the OpenZeppelin convention the on-chain verifier uses), so
  // swapping a sibling pair does NOT change the root. That is why position is bound INSIDE
  // the leaf — `verifierLeaf(index, …)` — rather than by where the leaf sits: the tree cannot
  // express order, so the index has to be part of what is hashed.
  eq(
    'swapping a sibling pair leaves the root unchanged (sorted-pair)',
    bareHex(merkleRoot([leaf(0), leaf(1)])!),
    bareHex(merkleRoot([leaf(1), leaf(0)])!),
  )
  ok('…so the index is what distinguishes a leaf', bareHex(leaf(0)) !== bareHex(verifierLeaf(1, fill(20, 0x10), fill(32, 0x20))))
  // Changing WHICH leaves are in the set does change the root.
  ok('a different leaf set roots differently', bareHex(merkleRoot([leaf(0), leaf(1)])!) !== bareHex(merkleRoot([leaf(0), leaf(2)])!))
}

// ─── token verification's refusals ────────────────────────────────────────────
{
  const registrySize = 5
  const committee = 3
  const quorum = 2
  const epoch = 9
  const seed = fill(32, 0x5e)
  const slotId = fill(32, 0xcd)
  const ruleHash = fill(32, 0x22)
  const iat = 1_000
  const exp = 2_000

  const secrets = Array.from({length: registrySize}, (_, i) => fill(32, 0x40 + i))
  const pubkeys = secrets.map(s => ed25519.getPublicKey(s))
  const set: VerifierSet = {registrySize, pubkeys: new Map(pubkeys.map((p, i) => [i, p]))}
  const drawn = selectVerifierCommittee(slotId, epoch, seed, registrySize, committee)

  const payload: CompoundTokenPayload = {
    tokenType: 'JWT', seed, epoch, slotId,
    vpHash: fill(32, 0x11), holderHash: fill(32, 0x1a), ruleHash,
    verifierIndexes: drawn, iat, exp,
  }
  const hash = compoundTokenHash(payload)
  const sign = (indexes: number[]) => indexes.map(i => ({verifierIndex: i, signature: ed25519.sign(hash, secrets[i]!)}))
  const token = decodeCompoundToken(assembleCompoundToken(payload, sign(drawn.slice(0, quorum))))
  const verifyOpts = {set, committee, quorum, now: 1_500, leeway: 60, slotRuleHash: ruleHash}

  ok('a well-formed token verifies', verifyCompoundToken({token, ...verifyOpts}).verifiedSigners.length >= quorum)

  // ⚠ The rule binding. A token minted for one slot's rule must not authorize another's —
  // this is what makes the token slot-specific rather than merely committee-signed.
  throwsWith('a token bound to another rule is refused', /rule_hash does not match the slot rule hash/, () =>
    verifyCompoundToken({token, ...verifyOpts, slotRuleHash: fill(32, 0x23)}),
  )
  // A rule hash of the WRONG LENGTH must fail the same way, not throw from an index read —
  // the comparison checks length before bytes.
  throwsWith('a short slot rule hash is refused, not a crash', /rule_hash does not match the slot rule hash/, () =>
    verifyCompoundToken({token, ...verifyOpts, slotRuleHash: fill(31, 0x22)}),
  )

  // An identity-scoped token carries `identityHash`, and it must survive verification into
  // the result: a caller enforcing the scope binding reads it from there.
  {
    const scoped: CompoundTokenPayload = {...payload, identityHash: fill(32, 0x44)}
    const scopedHash = compoundTokenHash(scoped)
    const scopedToken = decodeCompoundToken(
      assembleCompoundToken(scoped, drawn.slice(0, quorum).map(i => ({verifierIndex: i, signature: ed25519.sign(scopedHash, secrets[i]!)}))),
    )
    const out = verifyCompoundToken({token: scopedToken, ...verifyOpts})
    eq('an identity-scoped token reports its identity hash', bytesToHex(out.identityHash!), bytesToHex(fill(32, 0x44)))
    eq('an unscoped token reports none', verifyCompoundToken({token, ...verifyOpts}).identityHash, undefined)
  }
  // ⚠ The committee must BE the draw for this (slot, epoch, seed). A token listing any other
  // set — even of real verifiers — is a hand-picked committee.
  throwsWith('a committee that is not the draw is refused', /not the expected draw/, () =>
    verifyCompoundToken({token: {...token, verifierIndexes: [0, 1, 2]}, ...verifyOpts}),
  )
  throwsWith('a committee of the wrong size is refused', /not the expected draw/, () =>
    verifyCompoundToken({token: {...token, verifierIndexes: drawn.slice(0, 2)}, ...verifyOpts}),
  )
  // Expiry on both sides. `iat` in the future is the case a clock-skewed or forged token hits,
  // and it must be refused separately from expiry so the message tells the two apart.
  throwsWith('an expired token is refused', /token expired/, () => verifyCompoundToken({token, ...verifyOpts, now: 3_000}))
  throwsWith('a token not yet valid is refused', /token not yet valid/, () => verifyCompoundToken({token, ...verifyOpts, now: 500}))
  ok('a token inside the leeway at the upper edge verifies', !!verifyCompoundToken({token, ...verifyOpts, now: exp + 30}))
  ok('a token inside the leeway at the lower edge verifies', !!verifyCompoundToken({token, ...verifyOpts, now: iat - 30}))

  // A signer outside the active set cannot be checked at all, so it cannot count.
  const strangerHash = compoundTokenHash(payload)
  const stranger = {verifierIndex: 99, signature: ed25519.sign(strangerHash, fill(32, 0x99))}
  throwsWith('a signer outside the active set is named', /signer index 99 is not in the active verifier set/, () =>
    verifyCompoundToken({token: {...token, signatures: [...token.signatures, stranger]}, ...verifyOpts}),
  )
  // A real member with a bad signature is named too — the caller needs to know WHO.
  const forged = {verifierIndex: drawn[2]!, signature: ed25519.sign(fill(32, 0x77), secrets[drawn[2]!]!)}
  throwsWith('an invalid signature names the verifier index', new RegExp(`invalid signature from verifier index ${drawn[2]!}`), () =>
    verifyCompoundToken({token: {...token, signatures: [...token.signatures, forged]}, ...verifyOpts}),
  )
  // ⚠ DUPLICATES must not count toward quorum: one verifier signing twice is one signer.
  const doubled = sign([drawn[0]!, drawn[0]!])
  throwsWith('the same signer twice does not reach quorum', /quorum not met: 1 of the drawn committee signed, need 2/, () =>
    verifyCompoundToken({token: {...token, signatures: doubled}, ...verifyOpts}),
  )
  // A signature from a real, active verifier who was NOT drawn also fails quorum.
  const notDrawn = [0, 1, 2, 3, 4].find(i => !drawn.includes(i))!
  throwsWith('an undrawn member does not count toward quorum', /quorum not met/, () =>
    verifyCompoundToken({token: {...token, signatures: sign([notDrawn])}, ...verifyOpts}),
  )
  eq('a token with no signatures at all fails quorum', (() => {
    try {
      verifyCompoundToken({token: {...token, signatures: []}, ...verifyOpts})
      return 'verified'
    } catch (e) {
      return /quorum not met/.test(String(e)) ? 'refused' : String(e)
    }
  })(), 'refused')
}

// ─── the binding byte ↔ wire name mapping ─────────────────────────────────────
{
  // A round trip in both directions, so the two functions cannot drift apart. The byte goes
  // into the canonical token hash, so a name mapped to the wrong byte changes every hash.
  eq('unbound maps to no wire value', bindingToWire(BINDING_UNBOUND), undefined)
  eq('an absent binding maps to no wire value', bindingToWire(undefined), undefined)
  eq('holder_key round-trips', bindingFromWire(bindingToWire(BINDING_HOLDER_KEY)), BINDING_HOLDER_KEY)
  eq('issuer_asserted round-trips', bindingFromWire(bindingToWire(BINDING_ISSUER_ASSERTED)), BINDING_ISSUER_ASSERTED)
  eq('holder_key is the name for 0x01', bindingToWire(BINDING_HOLDER_KEY), 'holder_key')
  eq('issuer_asserted is the name for 0x02', bindingToWire(BINDING_ISSUER_ASSERTED), 'issuer_asserted')
  // An unknown byte is reported as such rather than silently becoming 'unbound', so a token
  // from a newer producer is visible instead of quietly downgraded.
  eq('an unknown byte is reported as unknown_N', bindingToWire(0x07), 'unknown_7')
  // ⚠ …but an unknown NAME decodes to unbound (0x00). That asymmetry is deliberate: a reader
  // must not invent a binding it does not understand, and unbound is the least-privilege value.
  eq('an unknown wire name decodes to unbound', bindingFromWire('something_new'), BINDING_UNBOUND)
  eq('the explicit "unbound" name decodes to unbound', bindingFromWire('unbound'), BINDING_UNBOUND)
  eq('an absent wire name decodes to unbound', bindingFromWire(undefined), BINDING_UNBOUND)
}

// ─── buildVerifierProofs: degrade rather than ship a wrong proof ──────────────
{
  const registrySize = 4
  const dir = Array.from({length: registrySize}, (_, i) => ({
    index: i,
    url: `http://verifier-${i}`,
    operator: `0x${'10'.repeat(20)}`.slice(0, 2) + (0x10 + i).toString(16).repeat(20),
    pubkey: `0x${(0x20 + i).toString(16).repeat(32)}`,
  }))
  const proofs = buildVerifierProofs(dir, registrySize, [0, 1])
  ok('a complete directory yields proofs', !!proofs && proofs.length === 2)
  // ⚠ Every degradation returns `undefined` — NEVER a wrong proof. The keeper then falls back
  // to its configured set, which is a weaker but correct path; a bad proof is a refusal.
  eq('a directory missing a member yields no proofs', buildVerifierProofs(dir.slice(0, 3), registrySize, [0, 1]), undefined)
  eq('a member with no pubkey yields no proofs', buildVerifierProofs(dir.map((v, i) => (i === 2 ? {index: v.index, url: v.url} : v)), registrySize, [0, 1]), undefined)
  eq('a root that disagrees with the anchor yields no proofs', buildVerifierProofs(dir, registrySize, [0, 1], fill(32, 0xff)), undefined)
  // registrySize 0 means no leaves, so no root, so no proofs.
  eq('an empty registry yields no proofs', buildVerifierProofs(dir, 0, [0]), undefined)
  // A signer index outside the directory cannot be proved.
  eq('a signer outside the directory yields no proofs', buildVerifierProofs(dir, registrySize, [9]), undefined)
}

// ─── pinnedDraw + requestCommitteeToken guards ────────────────────────────────
{
  const seed = fill(32, 0x5e)
  const seedAtSeed = fill(32, 0x6f)
  const withSeedAt = {
    seed: () => Promise.resolve(seed),
    seedAt: () => Promise.resolve(seedAtSeed),
  }
  eq('epochLag 0 uses the current seed', (await pinnedDraw(withSeedAt, 9, 0)).epoch, 9)
  eq('epochLag 1 pins the previous epoch', (await pinnedDraw(withSeedAt, 9, 1)).epoch, 8)
  eq('…and reads that epoch\'s seed', bareHex((await pinnedDraw(withSeedAt, 9, 1)).seed), bareHex(seedAtSeed))
  // The lag is clamped to [0, 1]: the keeper admits only {latest, latest-1}, so a larger value
  // must not silently produce a token every verifier refuses.
  eq('a lag above 1 is clamped', (await pinnedDraw(withSeedAt, 9, 5)).epoch, 8)
  eq('a negative lag is clamped to 0', (await pinnedDraw(withSeedAt, 9, -3)).epoch, 9)
  eq('epoch 0 cannot go below zero', (await pinnedDraw(withSeedAt, 0, 1)).epoch, 0)
  // ⚠ Asking for a lag without `seedAt` must name the missing read AND how to get it. The
  // alternative is a draw against the wrong seed, which fails much later as an unauthorized.
  await rejectsWith('epochLag without seedAt names the missing read and the adapter', /epochLag needs chain\.seedAt.*committeeChainReadsFromClient/s, () =>
    pinnedDraw({seed: () => Promise.resolve(seed)}, 9, 1),
  )

  const chain: CommitteeChainReads = {
    seed: () => Promise.resolve(seed),
    epoch: () => Promise.resolve(9),
    verifierPolicy: () => Promise.resolve([3, 2] as const),
  }
  const base = {
    chain, verifiers: Array.from({length: 5}, (_, i) => ({index: i, url: `http://verifier-${i}`})),
    slotId: `0x${'cd'.repeat(32)}`, holder: 'did:example:alice', credentials: ['vc-jwt'],
  }
  // ⚠ The holder proof is required by DEFAULT, and the opt-out has to be explicit — the
  // source's reason is that a client refusing what the server accepts makes a valid
  // deployment unreachable, so the decision belongs to the caller and must be stated.
  await rejectsWith('no holder proof and no opt-out is refused', /holderProof is required to prove control of the holder DID/, () =>
    requestCommitteeToken(base),
  )
  await rejectsWith('the opt-out gets past the guard', /^(?!.*holderProof is required)/s, () =>
    requestCommitteeToken({...base, allowNoHolderProof: true}),
  )
  // A slot with no verifier policy is not on the committee path at all, and the error says so.
  await rejectsWith('a slot with no verifierPolicy points at the JWT path', /has no verifierPolicy \(committee path not wired\); use the JWT path/, () =>
    requestCommitteeToken({...base, holderProof: 'p', chain: {...chain, verifierPolicy: () => Promise.resolve([0, 0] as const)}}),
  )
  // ⚠ A registry smaller than the committee cannot seat one. Caught here rather than as an
  // exhausted draw, and it names both numbers.
  await rejectsWith('a registry smaller than the committee is refused, naming both', /active verifier set \(2\) is smaller than the committee size \(3\)/, () =>
    requestCommitteeToken({...base, holderProof: 'p', verifiers: base.verifiers.slice(0, 2)}),
  )
}

// ─── keeper requests: the optional fields ─────────────────────────────────────
{
  interface Sent {
    url: string
    body: Record<string, unknown>
  }
  const sent: Sent[] = []
  const realFetch = globalThis.fetch
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    const u = String(url)
    sent.push({url: u, body: JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>})
    if (u.includes('/v1/committee/decrypt')) {
      return {ok: true, status: 200, json: async () => ({plaintext: 'AAAA'})} as unknown as Response
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({identifier: 1, extraction_share: 'AAAA', verifying_share: 'AAAA', epoch: 4}),
    } as unknown as Response
  }) as typeof globalThis.fetch

  try {
    const token = {} as never
    const ciphertext = {u: fill(96, 1), nonce: fill(12, 2), aeadCt: fill(48, 3)}
    const proofs = [{verifierIndex: 1, operator: `0x${'ab'.repeat(20)}`, pubkey: `0x${'cd'.repeat(32)}`, proof: [`0x${'11'.repeat(32)}`]}]

    // Every optional field, present.
    sent.length = 0
    await committeeDecrypt({
      nodeUrl: 'http://keeper-1', committeeToken: token, ciphertext,
      identity: new TextEncoder().encode('did:example:sender'), decryptingSet: [1, 2], blsPeers: [],
      userSignature: fill(64, 9), ciphertextEpoch: 4, targetKeykeeper: `0x${'ee'.repeat(32)}`,
      verifierProofs: proofs, clientPubkey: fill(32, 7), clientSignature: fill(64, 8),
    })
    const body = sent[0]!.body
    eq('decrypt: user_signature is bare hex', body.user_signature, bareHex(fill(64, 9)))
    eq('decrypt: ciphertext_epoch is forwarded', body.ciphertext_epoch, 4)
    eq('decrypt: target_keykeeper is stripped of 0x', body.target_keykeeper, 'ee'.repeat(32))
    // The proofs are renamed to the keeper's snake_case DTO and stripped of 0x throughout.
    eq('decrypt: verifier_proofs are converted to the wire DTO', body.verifier_proofs, [
      {verifier_index: 1, operator: 'ab'.repeat(20), pubkey: 'cd'.repeat(32), proof: ['11'.repeat(32)]},
    ])
    eq('decrypt: the client binding is sent as bare hex', [body.client_pubkey, body.client_signature], [bareHex(fill(32, 7)), bareHex(fill(64, 8))])

    // ⚠ BOTH-OR-NEITHER on the client binding: the keeper verifies the signature against the
    // pubkey, so one without the other is unverifiable and must not be sent at all.
    for (const [label, half] of [
      ['only a pubkey', {clientPubkey: fill(32, 7)}],
      ['only a signature', {clientSignature: fill(64, 8)}],
    ] as const) {
      sent.length = 0
      await committeeDecrypt({
        nodeUrl: 'http://keeper-1', committeeToken: token, ciphertext,
        identity: new Uint8Array(), decryptingSet: [1], blsPeers: [], ...half,
      })
      ok(`decrypt: ${label} sends neither half`, !('client_pubkey' in sent[0]!.body) && !('client_signature' in sent[0]!.body))
    }

    // ciphertextEpoch 0 is a VALUE, not an absence — `!== undefined` rather than truthiness.
    sent.length = 0
    await committeeDecrypt({
      nodeUrl: 'http://keeper-1', committeeToken: token, ciphertext,
      identity: new Uint8Array(), decryptingSet: [1], blsPeers: [], ciphertextEpoch: 0,
    })
    eq('decrypt: a zero ciphertext_epoch is still sent', sent[0]!.body.ciphertext_epoch, 0)

    // The same option set on the extraction request.
    sent.length = 0
    await requestIbeExtractionPartials({
      nodeUrls: ['http://keeper-1'], committeeToken: token, identity: 'did:example:alice/imaging',
      userSignature: fill(64, 9), ciphertextEpoch: 2, verifierProofs: proofs,
      clientPubkey: fill(32, 7), clientSignature: fill(64, 8),
    })
    const ex = sent[0]!.body
    eq('extract: identity is sent in the clear', ex.identity, 'did:example:alice/imaging')
    eq('extract: user_signature is bare hex', ex.user_signature, bareHex(fill(64, 9)))
    eq('extract: ciphertext_epoch is forwarded', ex.ciphertext_epoch, 2)
    ok('extract: verifier_proofs are converted', Array.isArray(ex.verifier_proofs))
    eq('extract: the client binding is sent', [ex.client_pubkey, ex.client_signature], [bareHex(fill(32, 7)), bareHex(fill(64, 8))])
    sent.length = 0
    await requestIbeExtractionPartials({
      nodeUrls: ['http://keeper-1'], committeeToken: token, identity: 'x', clientPubkey: fill(32, 7),
    })
    ok('extract: a lone client pubkey sends neither half', !('client_pubkey' in sent[0]!.body))
  } finally {
    globalThis.fetch = realFetch
  }
}

// ─── committeeAuthorize + the chain-reads adapter ─────────────────────────────
{
  const sent: Array<{url: string; body: Record<string, unknown>}> = []
  let status = 200
  let detailBody = 'the verifier said no'
  let ruleVersion: number | undefined
  const realFetch = globalThis.fetch
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    sent.push({url: String(url), body: JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>})
    if (status !== 200) {
      const s = status
      return {ok: false, status: s, text: async () => detailBody} as unknown as Response
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        verifier_index: 0,
        token_hash: bareHex(fill(32, 1)),
        vp_hash: bareHex(fill(32, 2)),
        holder_hash: bareHex(fill(32, 3)),
        rule_hash: bareHex(fill(32, 4)),
        signature: bareHex(fill(64, 5)),
        committee_indexes: [0],
        ...(ruleVersion !== undefined ? {rule_version: ruleVersion} : {}),
      }),
    } as unknown as Response
  }) as typeof globalThis.fetch

  try {
    const body = {
      holder: 'did:example:alice', credentials: ['vc'], holderProof: 'proof',
      tokenType: 'JWT' as const, seed: fill(32, 1), epoch: 1, slotId: fill(32, 2),
      registrySize: 1, committee: 1, iat: 1, exp: 2,
    }
    const reply = await committeeAuthorize('http://verifier-0', body)
    eq('a verifier reply decodes its index', reply.verifierIndex, 0)
    eq('no rule_version decodes to undefined', reply.ruleVersion, undefined)
    // ⚠ The rule version is DIAGNOSTIC, not a gate — but it has to survive the decode, or a
    // refusal under a superseded policy is indistinguishable from an unauthorized one.
    ruleVersion = 7
    eq('a numeric rule_version is carried through', (await committeeAuthorize('http://verifier-0', body)).ruleVersion, 7)
    ruleVersion = undefined

    // The binding preimage's optional description travels only when set.
    sent.length = 0
    const binding = {chainId: 43113, action: 'sign' as const, payloadDigest: fill(32, 6), random: fill(32, 7), clientId: 'app'}
    await committeeAuthorize('http://verifier-0', {...body, binding})
    ok('a binding with no description omits it', !('description' in sent[0]!.body))
    sent.length = 0
    await committeeAuthorize('http://verifier-0', {...body, binding: {...binding, description: 'Sign a document'}})
    eq('a binding description is forwarded when set', sent[0]!.body.description, 'Sign a document')

    // ⚠ `holderProof` must be a STRING, `''` included. The guard exists because the policy
    // belongs at one layer: the caller decides and states it, this function only transmits.
    await rejectsWith('an undefined holderProof is refused here, naming the opt-out', /holderProof must be a string \(pass "" only when/, () =>
      committeeAuthorize('http://verifier-0', {...body, holderProof: undefined as unknown as string}),
    )
    // An empty string is accepted and OMITTED from the wire — the server field is an Option
    // and an empty string fails its parse.
    sent.length = 0
    await committeeAuthorize('http://verifier-0', {...body, holderProof: ''})
    ok('an empty holder proof is omitted rather than sent as ""', !('holder_proof' in sent[0]!.body))

    // A refusal carries the status and, when there is one, the body detail.
    status = 403
    await rejectsWith('a refusal reports status and detail', /committee-authorize → HTTP 403: the verifier said no/, () =>
      committeeAuthorize('http://verifier-0', body),
    )
    // …and an EMPTY body must not produce a dangling colon.
    detailBody = ''
    await rejectsWith('an empty body gives a clean message', /committee-authorize → HTTP 403$/, () =>
      committeeAuthorize('http://verifier-0', body),
    )
    status = 200
    detailBody = 'the verifier said no'
  } finally {
    globalThis.fetch = realFetch
  }

  // committeeChainReadsFromClient adapts the SDK's readers, and each optional reader it may or
  // may not find changes the shape it returns.
  const readers = {
    beacon: {seed: () => Promise.resolve(`0x${'11'.repeat(32)}`), epoch: () => Promise.resolve(5n)},
    keyRegistry: {verifierPolicy: () => Promise.resolve([3, 2] as const)},
  }
  const noSeedAt = committeeChainReadsFromClient(readers)
  eq('a client with no seedAt exposes none', noSeedAt.seedAt, undefined)
  eq('a client with no verifierSet exposes no snapshot', noSeedAt.snapshot, undefined)
  const full = committeeChainReadsFromClient({
    ...readers,
    beacon: {...readers.beacon, seedAt: () => Promise.resolve(`0x${'22'.repeat(32)}`)},
    verifierSet: {snapshotAt: () => Promise.resolve({root: `0x${'33'.repeat(32)}`, size: 5})},
  })
  ok('seedAt is exposed when the client has it', typeof full.seedAt === 'function')
  eq('an anchored snapshot is reported as {root, size}', await full.snapshot!(5n), {root: `0x${'33'.repeat(32)}`, size: 5})
  // ⚠ The registry's getter may answer as a TUPLE or as a struct depending on the ABI decode,
  // and both are real. Reading only one shape silently loses the snapshot and drops the flow
  // to the configured-set path.
  const tuple = committeeChainReadsFromClient({
    ...readers,
    verifierSet: {snapshotAt: () => Promise.resolve([`0x${'44'.repeat(32)}`, 7n])},
  })
  eq('a tuple-shaped snapshot decodes too', await tuple.snapshot!(5n), {root: `0x${'44'.repeat(32)}`, size: 7})
  // A zero root or a zero size means nothing is anchored — reported as null, never as a
  // snapshot with an all-zero root that a proof would then be built against.
  const zeroRoot = committeeChainReadsFromClient({
    ...readers,
    verifierSet: {snapshotAt: () => Promise.resolve({root: `0x${'00'.repeat(32)}`, size: 5})},
  })
  eq('a zero root is no snapshot', await zeroRoot.snapshot!(5n), null)
  const zeroSize = committeeChainReadsFromClient({
    ...readers,
    verifierSet: {snapshotAt: () => Promise.resolve({root: `0x${'33'.repeat(32)}`, size: 0})},
  })
  eq('a zero size is no snapshot', await zeroSize.snapshot!(5n), null)
}

// ─── committeeSign: the reply's optional epoch, and a refusal ─────────────────
{
  const sent: Array<{url: string; body: Record<string, unknown>}> = []
  let signOk = true
  let withEpoch = true
  let rejectWithString = false
  const realFetch = globalThis.fetch
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    if (rejectWithString) {
      // A transport that rejects with something that is NOT an Error. Nothing in this package
      // does it, but a patched fetch or a bundler shim can, and the error aggregation must
      // still produce a readable reason instead of "undefined".
      // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
      return Promise.reject('socket hung up')
    }
    sent.push({url: String(url), body: JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>})
    if (!signOk) return {ok: false, status: 503, text: async () => 'slot not ready'} as unknown as Response
    return {
      ok: true,
      status: 200,
      json: async () => ({
        key_slot_id: `0x${'cd'.repeat(32)}`,
        group_public_key: `0x${'ab'.repeat(32)}`,
        signature_r: `0x${'01'.repeat(32)}`,
        signature_z: `0x${'02'.repeat(32)}`,
        message_sha256: `0x${'03'.repeat(32)}`,
        ...(withEpoch ? {epoch: 4} : {}),
      }),
    } as unknown as Response
  }) as typeof globalThis.fetch

  try {
    const base = {nodeUrl: 'http://keeper-1', committeeToken: {} as never, message: new Uint8Array([1])}
    eq('a sign reply carries its epoch', (await committeeSign(base)).epoch, 4)
    // An older keeper omits `epoch`; it defaults to 0 rather than becoming NaN, which would
    // propagate into a rotation comparison and read as "always stale".
    withEpoch = false
    eq('a reply with no epoch defaults to 0, not NaN', (await committeeSign(base)).epoch, 0)
    withEpoch = true

    // ⚠ `target_keykeeper` is stripped of `0x` on the wire — and a caller who already passes
    // it bare must get the same bytes, not a string with two characters removed.
    sent.length = 0
    await committeeSign({...base, targetKeykeeper: 'ee'.repeat(32)})
    eq('a bare target_keykeeper is forwarded unchanged', sent[0]!.body.target_keykeeper, 'ee'.repeat(32))
    sent.length = 0
    await committeeSign({...base, targetKeykeeper: `0x${'ee'.repeat(32)}`})
    eq('a 0x-prefixed one is stripped to the same value', sent[0]!.body.target_keykeeper, 'ee'.repeat(32))

    signOk = false
    await rejectsWith('a keeper refusal on sign names the endpoint and status', /committee\/sign.*503/s, () => committeeSign(base))
    signOk = true

    // A non-Error rejection must still surface a reason in the gather's aggregated message.
    rejectWithString = true
    await rejectsWith(
      'a non-Error transport rejection still yields a readable reason',
      /no verifier authorized the request.*socket hung up/s,
      () =>
        gatherCommitteeToken({
          verifiers: [{index: 0, url: 'http://verifier-0'}],
          authorize: {
            holder: 'did:example:alice', credentials: ['vc'], holderProof: '',
            tokenType: 'JWT', seed: fill(32, 1), epoch: 1, slotId: fill(32, 2),
            registrySize: 1, committee: 1, iat: 1, exp: 2,
          },
          quorum: 1,
        }),
    )
    await rejectsWith(
      'the same holds for the extraction fan-out',
      /no node served an extraction.*socket hung up/s,
      () => requestIbeExtractionPartials({nodeUrls: ['http://keeper-1'], committeeToken: {} as never, identity: 'x'}),
    )
    rejectWithString = false
  } finally {
    globalThis.fetch = realFetch
  }
}

// ─── hex round trip on the token wire ─────────────────────────────────────────
{
  // `decodeCompoundToken` is the inverse of `assembleCompoundToken`, including the optional
  // hashes. A field dropped on either side is a token that verifies here and not at the keeper.
  const payload: CompoundTokenPayload = {
    tokenType: 'refresh', seed: fill(32, 1), epoch: 3, slotId: fill(32, 2),
    vpHash: fill(32, 3), holderHash: fill(32, 4), ruleHash: fill(32, 5),
    identityHash: fill(32, 6), requestHash: fill(32, 7), binding: BINDING_HOLDER_KEY,
    verifierIndexes: [1, 2], iat: 10, exp: 20,
  }
  const wire = assembleCompoundToken(payload, [{verifierIndex: 1, signature: fill(64, 8)}])
  const back = decodeCompoundToken(wire)
  eq('the token type survives', back.tokenType, 'refresh')
  eq('the identity hash survives', bytesToHex(back.identityHash!), bytesToHex(payload.identityHash!))
  eq('the request hash survives', bytesToHex(back.requestHash!), bytesToHex(payload.requestHash!))
  eq('the binding survives', back.binding, BINDING_HOLDER_KEY)
  eq('the canonical hash is unchanged by the round trip', bytesToHex(compoundTokenHash(back)), bytesToHex(compoundTokenHash(payload)))
  // Without the optional hashes, the wire must OMIT them rather than send nulls — they are in
  // the canonical hash, so a present-but-empty field would change it.
  const bare = assembleCompoundToken({...payload, identityHash: undefined, requestHash: undefined, binding: BINDING_UNBOUND}, [])
  ok('an absent identity hash is omitted from the wire', !('identity_hash' in bare))
  ok('an absent request hash is omitted', !('request_hash' in bare))
  ok('an unbound binding is omitted', bare.binding === undefined)
  eq('decoding the bare wire gives no identity hash', decodeCompoundToken(bare).identityHash, undefined)
}

if (failures.length > 0) {
  console.error(`✗ committee.guards: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ committee.guards: ${passed} checks passed`)
