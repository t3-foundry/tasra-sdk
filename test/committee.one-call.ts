// The one-call committee helpers, end to end against a mocked verifier fleet + keepers.
//
// `requestCommitteeToken` and `gatherCommitteeToken` were covered (test/committee.*.ts);
// the four helpers built on top of them were not, and neither were the keeper requests
// they issue. Those wrappers are pure wiring, which is exactly why they need tests: a
// dropped field is invisible at the call site and surfaces as a keeper refusal that looks
// like an authorization problem.
//
// So the assertions here are mostly about what ARRIVES at the keeper:
//
//   • the verifier proofs, client pubkey and client signature resolved during the token
//     step must reach the keeper request. Losing any of them downgrades or breaks the
//     keeper's checks while the token itself still looks valid.
//   • an identity-scoped extraction must send `scopedIdentity == identity`, because the
//     keeper enforces `identity_hash == keccak256(identity)` and a mismatch is refused.
//   • `identity` on a decrypt is the KEM's SENDER identity — a DIFFERENT concept from the
//     scoped identity, and the source warns they must never be conflated. Both are pinned.
//
// The IBE path runs real crypto: a 2-of-3 BLS slot is built here, the mock keepers return
// genuine extraction partials, and the combine + decrypt has to actually work. A mocked
// combine would pass against partials the pairing check rejects.
//
// Run: tsx test/committee.one-call.ts — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {ed25519} from '@noble/curves/ed25519'
import {
  committeeDecryptRequest,
  committeeSignRequest,
  ed25519ClientSigner,
  holderProofPerVerifier,
  ibeDecryptRequest,
  ibeExtractRequest,
  type CommitteeChainReads,
  type CommitteeVerifier,
} from '../src/committee/request.ts'
import {
  committeeDecrypt,
  gatherCommitteeToken,
  requestIbeExtractionPartials,
} from '../src/committee/client.ts'
import {compoundTokenHash, selectVerifierCommittee, type CompoundTokenPayload} from '../src/committee/token.ts'
import {dpopHtu, normalizeOrigin, platformAudience} from '../src/committee/oauth.ts'
import {ibeEncrypt} from '../src/crypto/ibe.ts'
import {base64Encode} from '../src/crypto/envelope.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean, detail = ''): void {
  if (cond) passed++
  else failures.push(name + (detail ? ` — ${detail}` : ''))
}
function eq(name: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual)
  const b = JSON.stringify(expected)
  ok(name, a === b, `got ${a}, want ${b}`)
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
const bareHex = (b: Uint8Array): string => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')
const fill = (n: number, v: number): Uint8Array => new Uint8Array(n).fill(v)

// ─── the deployment ───────────────────────────────────────────────────────────
const registrySize = 5
const committee = 3
const quorum = 2
const epoch = 9
const seed = fill(32, 0x5e)
const slotIdBytes = fill(32, 0xcd)
const slotId = `0x${bareHex(slotIdBytes)}`
const nowSecs = 1_000
const ttlSecs = 300
// requestCommitteeToken back-dates iat by 5s and takes exp from the TTL. The mock fleet has
// to derive the same two values or every canonical hash disagrees.
const iat = nowSecs - 5
const exp = nowSecs + ttlSecs

const secrets = Array.from({length: registrySize}, (_, i) => fill(32, 0x40 + i))
const drawn = selectVerifierCommittee(slotIdBytes, epoch, seed, registrySize, committee)
const verifiers: CommitteeVerifier[] = Array.from({length: registrySize}, (_, i) => ({
  index: i,
  url: `http://verifier-${i}`,
}))

const chainReads: CommitteeChainReads = {
  seed: () => Promise.resolve(seed),
  epoch: () => Promise.resolve(epoch),
  verifierPolicy: () => Promise.resolve([committee, quorum] as const),
}

// ─── a 2-of-3 BLS slot, for the IBE path ──────────────────────────────────────
const {Fr} = bls12_381.fields
const G1 = bls12_381.G1.ProjectivePoint
const G2 = bls12_381.G2.ProjectivePoint
const a0 = Fr.create(BigInt('0x1f2e3d4c5b6a79880000000000000000000000000000000000000000000000ab'))
const a1 = Fr.create(BigInt('0x0a0b0c0d0e0f10111213141516171819202122232425262728292a2b2c2d2e2f'))
const share = (i: number): bigint => Fr.add(a0, Fr.mul(a1, BigInt(i)))
const mpk = G2.BASE.multiply(a0).toRawBytes(true)
/** The dual-group verifying share the extract endpoint returns: 96B G2 ‖ 48B G1. */
const verifyingShareWire = (i: number): string =>
  base64Encode(
    new Uint8Array([
      ...G2.BASE.multiply(share(i)).toRawBytes(true),
      ...G1.BASE.multiply(share(i)).toRawBytes(true),
    ]),
  )
const extractionShare = (i: number, identity: string): string => {
  const qId = G1.fromAffine(
    bls12_381.G1.hashToCurve(new TextEncoder().encode(identity), {
      DST: 'keykeeper/BLS12381-BF-IBE-HashToG1-v1',
    }).toAffine(),
  )
  return base64Encode(qId.multiply(share(i)).toRawBytes(true))
}

// ─── the mock fleet ───────────────────────────────────────────────────────────
interface Sent {
  url: string
  body: Record<string, unknown>
}
const sent: Sent[] = []
/** Node index → how it should behave on an extraction request. */
const keeperBehaviour = new Map<number, 'serve' | 'refuse'>()
const nodeUrls = [1, 2, 3].map(i => `http://keeper-${i}`)

const realFetch = globalThis.fetch
/** The reply a verifier gives, so a test can bend one field at a time. */
let bendReply: (r: Record<string, unknown>, idx: number) => Record<string, unknown> = r => r

function tokenHashFor(extra: Partial<CompoundTokenPayload> = {}): Uint8Array {
  const payload: CompoundTokenPayload = {
    tokenType: 'JWT',
    seed,
    epoch,
    slotId: slotIdBytes,
    vpHash: fill(32, 0x11),
    holderHash: fill(32, 0x1a),
    ruleHash: fill(32, 0x22),
    verifierIndexes: drawn,
    iat,
    exp,
    ...extra,
  }
  return compoundTokenHash(payload)
}

globalThis.fetch = (async (url: string, init?: RequestInit) => {
  const u = String(url)
  const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>
  sent.push({url: u, body})

  // ── a holder-proof nonce ──
  // ⚠ Must be matched BEFORE the verifier branch: a nonce URL is
  // `http://verifier-2/v1/nonce`, so the verifier pattern also matches it. Getting this
  // order wrong makes every nonce come back undefined, which shows up as holder proofs
  // that are byte-identical rather than as an error.
  if (u.includes('/v1/nonce')) {
    return {ok: true, status: 200, json: async () => ({nonce: `nonce-for-${u}`})} as unknown as Response
  }

  // ── a verifier ──
  const vm = /verifier-(\d+)/.exec(u)
  if (vm) {
    const idx = Number(vm[1])
    if (!drawn.includes(idx)) {
      return {ok: false, status: 403, text: async () => 'not drawn'} as unknown as Response
    }
    const scoped = body.identity as string | undefined
    const identityHash = scoped === undefined ? undefined : fill(32, 0x33)
    const hash = tokenHashFor(identityHash ? {identityHash} : {})
    const reply: Record<string, unknown> = {
      verifier_index: idx,
      token_hash: bareHex(hash),
      vp_hash: bareHex(fill(32, 0x11)),
      holder_hash: bareHex(fill(32, 0x1a)),
      rule_hash: bareHex(fill(32, 0x22)),
      signature: bareHex(ed25519.sign(hash, secrets[idx]!)),
      committee_indexes: drawn,
      ...(identityHash ? {identity_hash: bareHex(identityHash)} : {}),
    }
    return {ok: true, status: 200, json: async () => bendReply(reply, idx)} as unknown as Response
  }

  // ── a keeper ──
  const km = /keeper-(\d+)/.exec(u)
  if (km) {
    const i = Number(km[1])
    if (u.includes('/v1/shards/ibe/extract')) {
      if (keeperBehaviour.get(i) === 'refuse') {
        return {ok: false, status: 503, text: async () => `keeper ${i} unavailable`} as unknown as Response
      }
      const identity = String(body.identity)
      return {
        ok: true,
        status: 200,
        json: async () => ({
          identifier: i,
          extraction_share: extractionShare(i, identity),
          verifying_share: verifyingShareWire(i),
          epoch,
        }),
      } as unknown as Response
    }
    if (u.includes('/v1/committee/sign')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          key_slot_id: slotId,
          group_public_key: `0x${'ab'.repeat(32)}`,
          signature_r: `0x${'01'.repeat(32)}`,
          signature_z: `0x${'02'.repeat(32)}`,
          message_sha256: `0x${'03'.repeat(32)}`,
          epoch,
        }),
      } as unknown as Response
    }
    if (u.includes('/v1/committee/decrypt')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({plaintext: base64Encode(new TextEncoder().encode('the plaintext'))}),
      } as unknown as Response
    }
  }
  return {ok: false, status: 404, text: async () => `no route: ${u}`} as unknown as Response
}) as typeof globalThis.fetch

const bodiesTo = (fragment: string): Array<Record<string, unknown>> =>
  sent.filter(s => s.url.includes(fragment)).map(s => s.body)

const tokenOpts = {
  chain: chainReads,
  verifiers,
  slotId,
  holder: 'did:example:alice',
  credentials: ['vc-jwt'],
  holderProof: 'holder-proof-jws',
  nowSecs,
  ttlSecs,
}

try {
  // ─── committeeSignRequest: the token's side-channel results must reach the keeper ──
  {
    sent.length = 0
    const clientSecret = fill(32, 0x77)
    const res = await committeeSignRequest({
      ...tokenOpts,
      nodeUrl: nodeUrls[0]!,
      message: new TextEncoder().encode('sign me'),
      signingSet: [1, 2],
      targetKeykeeper: `0x${'ee'.repeat(32)}`,
      userSignature: fill(64, 0x9),
      clientSigner: ed25519ClientSigner(clientSecret),
    })
    ok('sign: returns the keeper result', res.keySlotId === slotId && res.epoch === epoch)
    ok('sign: signature halves are decoded', res.signature.r.length === 32 && res.signature.z.length === 32)

    const body = bodiesTo('/v1/committee/sign')[0]
    ok('sign: the committee token is in the body', !!body?.committee_token)
    eq('sign: the message goes as bare hex', body?.message_hex, bareHex(new TextEncoder().encode('sign me')))
    eq('sign: signing_set is forwarded', body?.signing_set, [1, 2])
    // target_keykeeper is stripped of 0x on the wire — a keeper comparing the raw string
    // would refuse the 0x-prefixed form.
    eq('sign: target_keykeeper is forwarded without 0x', body?.target_keykeeper, 'ee'.repeat(32))
    eq('sign: user_signature is forwarded as bare hex', body?.user_signature, bareHex(fill(64, 0x9)))
    // The three fields resolved during the token step. Each is a separate keeper check.
    eq('sign: the client pubkey reaches the keeper', body?.client_pubkey, bareHex(ed25519.getPublicKey(clientSecret)))
    ok('sign: the client signature reaches the keeper', typeof body?.client_signature === 'string' && String(body.client_signature).length === 128)
  }
  {
    // No clientSigner → the keeper must receive NEITHER half. Sending one alone is what
    // the "both or neither" contract on the option exists to prevent.
    sent.length = 0
    await committeeSignRequest({...tokenOpts, nodeUrl: nodeUrls[0]!, message: new Uint8Array([1])})
    const body = bodiesTo('/v1/committee/sign')[0]
    ok('sign: no clientSigner sends neither client half', body?.client_pubkey === undefined && body?.client_signature === undefined)
    ok('sign: optional fields are omitted, not sent as undefined', !('signing_set' in (body ?? {})) && !('user_signature' in (body ?? {})))
  }

  // ─── committeeDecryptRequest ────────────────────────────────────────────────
  {
    sent.length = 0
    const ciphertext = {u: fill(96, 0x1), nonce: fill(12, 0x2), aeadCt: fill(48, 0x3)}
    const senderIdentity = new TextEncoder().encode('did:example:sender')
    const out = await committeeDecryptRequest({
      ...tokenOpts,
      nodeUrl: nodeUrls[0]!,
      ciphertext,
      identity: senderIdentity,
      decryptingSet: [1, 2],
      blsPeers: [
        {id: 1, peerId: 'peer-one'},
        {id: 2, peerId: 'peer-two'},
      ],
      ciphertextEpoch: 4,
    })
    eq('decrypt: returns the keeper plaintext', new TextDecoder().decode(out), 'the plaintext')

    const body = bodiesTo('/v1/committee/decrypt')[0]
    const ct = body?.ciphertext as {u: string; nonce: string; aead_ct: string}
    ok('decrypt: ciphertext goes as base64 u/nonce/aead_ct', !!ct.u && !!ct.nonce && !!ct.aead_ct)
    eq('decrypt: u is base64, not hex', ct.u, base64Encode(fill(96, 0x1)))
    // ⚠ This `identity` is the KEM SENDER identity (AEAD associated data), sent as TEXT —
    // not the scoped identity of the WHICH-gate. Conflating them is called out in the source.
    eq('decrypt: identity is the sender identity, as text', body?.identity, 'did:example:sender')
    eq('decrypt: decrypting_set is forwarded', body?.decrypting_set, [1, 2])
    eq('decrypt: bls peers are renamed to peer_id', body?.bls_peers, [
      {id: 1, peer_id: 'peer-one'},
      {id: 2, peer_id: 'peer-two'},
    ])
    eq('decrypt: ciphertext_epoch is forwarded', body?.ciphertext_epoch, 4)
  }
  {
    // A keeper refusal must surface as an error naming the operation, not as empty output.
    sent.length = 0
    await rejectsWith('decrypt: a keeper refusal names the endpoint', /committee\/decrypt/, () =>
      committeeDecrypt({
        nodeUrl: 'http://no-such-node',
        committeeToken: {} as never,
        ciphertext: {u: fill(96, 1), nonce: fill(12, 2), aeadCt: fill(48, 3)},
        identity: new Uint8Array(),
        decryptingSet: [],
        blsPeers: [],
      }),
    )
  }
  {
    // A trailing slash on the node URL must not produce a double slash in the path.
    sent.length = 0
    await committeeDecryptRequest({
      ...tokenOpts,
      nodeUrl: `${nodeUrls[0]!}/`,
      ciphertext: {u: fill(96, 1), nonce: fill(12, 2), aeadCt: fill(48, 3)},
      identity: new Uint8Array(),
      decryptingSet: [1],
      blsPeers: [],
    })
    ok(
      'a trailing slash on the node url is normalised away',
      sent.some(s => s.url === 'http://keeper-1/v1/committee/decrypt'),
    )
  }

  // ─── identity-scoped extraction: real crypto end to end ────────────────────
  const scopedIdentity = 'did:example:alice/imaging/2026-09'
  {
    sent.length = 0
    keeperBehaviour.clear()
    const skId = await ibeExtractRequest({...tokenOpts, nodeUrls, identity: scopedIdentity})
    eq('extract: returns a 48-byte compressed G1 identity key', skId.length, 48)

    // The binding that makes the whole scheme work: the token must carry THIS identity,
    // because the keeper refuses the extraction otherwise.
    const authorized = bodiesTo('/v1/committee-authorize')
    ok('extract: every verifier was asked to scope the token to the identity', authorized.length > 0 && authorized.every(b => b.identity === scopedIdentity))
    const extracts = bodiesTo('/v1/shards/ibe/extract')
    eq('extract: every keeper was asked for the same identity', new Set(extracts.map(b => b.identity)).size, 1)
    eq('extract: one request per node', extracts.length, nodeUrls.length)
    ok('extract: the identity is sent in the clear, as given', extracts.every(b => b.identity === scopedIdentity))

    // The key must actually decrypt something encrypted to that identity — the assertion
    // a mocked combine could not make.
    const ct = ibeEncrypt(mpk, new TextEncoder().encode(scopedIdentity), new TextEncoder().encode('secret'))
    const viaHelper = await ibeDecryptRequest({...tokenOpts, nodeUrls, identity: scopedIdentity, ciphertext: ct})
    eq('ibeDecryptRequest round-trips a real IBE ciphertext', new TextDecoder().decode(viaHelper), 'secret')
  }
  {
    // k of n is enough: with one keeper down the remaining two still combine. A fan-out
    // that needed all n would make the threshold meaningless.
    sent.length = 0
    keeperBehaviour.set(3, 'refuse')
    const partials = await requestIbeExtractionPartials({
      nodeUrls,
      committeeToken: {} as never,
      identity: scopedIdentity,
    })
    eq('extract: a refusing node is skipped, not fatal', partials.length, 2)
    eq('extract: partials carry the serving node for identifiable abort', partials.map(p => p.nodeUrl), ['http://keeper-1', 'http://keeper-2'])
    eq('extract: the verifying share is the 96-byte G2 half of the dual encoding', partials[0]?.verifyingShareG2.length, 96)
    eq('extract: the partial value is the 48-byte G1 share', partials[0]?.value.length, 48)
    eq('extract: identifier and epoch are numbers', [typeof partials[0]?.identifier, typeof partials[0]?.epoch], ['number', 'number'])
    keeperBehaviour.clear()
  }
  {
    // Every node down: the error has to name each node AND its reason, because "no node
    // served" with the reasons discarded is the least actionable failure here.
    keeperBehaviour.set(1, 'refuse')
    keeperBehaviour.set(2, 'refuse')
    keeperBehaviour.set(3, 'refuse')
    await rejectsWith(
      'extract: an all-down fan-out names every node and its reason',
      /no node served an extraction.*keeper-1.*keeper-2.*keeper-3/s,
      () => requestIbeExtractionPartials({nodeUrls, committeeToken: {} as never, identity: scopedIdentity}),
    )
    await rejectsWith(
      'extract: an all-down fan-out reports the HTTP status',
      /503/,
      () => requestIbeExtractionPartials({nodeUrls, committeeToken: {} as never, identity: scopedIdentity}),
    )
    keeperBehaviour.clear()
  }
  await rejectsWith('extract: an empty node list is refused up front', /no node URLs/, () =>
    requestIbeExtractionPartials({nodeUrls: [], committeeToken: {} as never, identity: 'x'}),
  )

  // ─── holderProofPerVerifier ────────────────────────────────────────────────
  {
    // One proof per verifier, each bound to THAT verifier's nonce — a single shared proof
    // is spent by whoever consumes its nonce first and the rest would refuse.
    sent.length = 0
    const perVerifier = holderProofPerVerifier({
      signer: {alg: 'EdDSA', did: 'did:example:alice', secretKey: ed25519.utils.randomPrivateKey()},
      audience: 'verifier-iss',
      credentials: ['vc-jwt'],
      slotId,
    })
    // The callback may return a string or a promise, so normalise before aggregating.
    const proofs = await Promise.all(drawn.map(i => Promise.resolve(perVerifier({index: i, url: `http://verifier-${i}`}))))
    eq('holderProofPerVerifier: one proof per verifier', proofs.length, drawn.length)
    eq('holderProofPerVerifier: no two proofs are equal', new Set(proofs).size, proofs.length)
    ok('holderProofPerVerifier: each is a compact JWS', proofs.every(p => p.split('.').length === 3))
    // Each fetched its own nonce from its own verifier.
    const nonceUrls = sent.filter(s => s.url.includes('/v1/nonce')).map(s => s.url)
    eq('holderProofPerVerifier: a nonce is fetched per verifier', new Set(nonceUrls).size, drawn.length)
    // ⚠ Counting nonce requests is NOT enough: a proof that never received the nonce is
    // still one request per verifier. Decode the claim that has to differ.
    const claims = proofs.map(p => JSON.parse(Buffer.from(p.split('.')[1]!, 'base64url').toString()) as {nonce?: string; slot_id?: string})
    ok('holderProofPerVerifier: each proof CARRIES its verifier\'s nonce', claims.every(c => typeof c.nonce === 'string' && c.nonce.length > 0))
    eq('holderProofPerVerifier: the carried nonces are distinct', new Set(claims.map(c => c.nonce)).size, drawn.length)
    ok('holderProofPerVerifier: the slot binding is echoed', claims.every(c => c.slot_id === slotId))
  }

  // ─── gatherCommitteeToken failure reporting ────────────────────────────────
  {
    // Nothing authorized: the message must carry each verifier's own reason. Every cause
    // here has a different fix, so a generic failure is unactionable.
    await rejectsWith(
      'gather: a total refusal reports the reason per verifier',
      /no verifier authorized the request.*verifier-\d.*HTTP 403/s,
      () =>
        gatherCommitteeToken({
          verifiers: verifiers.filter(v => !drawn.includes(v.index)),
          authorize: {
            holder: 'did:example:alice',
            credentials: ['vc-jwt'],
            holderProof: '',
            tokenType: 'JWT',
            seed,
            epoch,
            slotId: slotIdBytes,
            registrySize,
            committee,
            iat,
            exp,
          },
          quorum,
        }),
    )
  }
  {
    // A verifier that answers but is not in the drawn committee cannot count toward
    // quorum. The typed error must say how many of how many were collected.
    bendReply = r => ({...r, committee_indexes: [98, 99]})
    await rejectsWith(
      'gather: replies from outside the draw do not count toward quorum',
      /quorum not met \(0\/2 from the drawn committee\)/,
      () =>
        gatherCommitteeToken({
          verifiers,
          authorize: {
            holder: 'did:example:alice',
            credentials: ['vc-jwt'],
            holderProof: '',
            tokenType: 'JWT',
            seed,
            epoch,
            slotId: slotIdBytes,
            registrySize,
            committee,
            iat,
            exp,
          },
          quorum,
        }),
    )
    bendReply = r => r
  }
  {
    // The built-in encoding cross-check: if our canonical hash disagrees with the hash the
    // verifiers signed, the token is unusable and must fail HERE rather than at the keeper.
    bendReply = r => ({...r, rule_hash: bareHex(fill(32, 0x99))})
    await rejectsWith(
      'gather: a hash disagreement is caught locally as an encoding mismatch',
      /canonical token hash disagrees with the verifier \(encoding mismatch\)/,
      () =>
        gatherCommitteeToken({
          verifiers,
          authorize: {
            holder: 'did:example:alice',
            credentials: ['vc-jwt'],
            holderProof: '',
            tokenType: 'JWT',
            seed,
            epoch,
            slotId: slotIdBytes,
            registrySize,
            committee,
            iat,
            exp,
          },
          quorum,
        }),
    )
    bendReply = r => r
  }
} finally {
  globalThis.fetch = realFetch
}

// ─── OAuth derivations (no network) ───────────────────────────────────────────
// Three independent parties derive these strings and only one has a config file we
// control, so the normalisation has to be exact.
{
  eq('normalizeOrigin: trailing slashes dropped', normalizeOrigin('https://agent.example/'), 'https://agent.example')
  eq('normalizeOrigin: several trailing slashes dropped', normalizeOrigin('https://agent.example///'), 'https://agent.example')
  eq('normalizeOrigin: surrounding whitespace trimmed', normalizeOrigin('  https://agent.example  '), 'https://agent.example')
  eq('normalizeOrigin: scheme and authority lower-cased', normalizeOrigin('HTTPS://Agent.EXAMPLE'), 'https://agent.example')
  // ⚠ The path keeps its case deliberately: a path is case-sensitive, and lower-casing it
  // would silently rewrite an agent deployed under /API.
  eq('normalizeOrigin: the PATH keeps its case', normalizeOrigin('HTTPS://Agent.EXAMPLE/API/v1'), 'https://agent.example/API/v1')
  eq('normalizeOrigin: port is preserved', normalizeOrigin('https://agent.example:8443/x'), 'https://agent.example:8443/x')
  // No scheme: returned trimmed rather than mangled into one.
  eq('normalizeOrigin: a value with no scheme is left as written', normalizeOrigin('agent.example/x/'), 'agent.example/x')

  eq('platformAudience: origin + /authz/ + chain id', platformAudience('https://agent.example/', 43113), 'https://agent.example/authz/43113')
  eq('platformAudience: accepts a bigint chain id', platformAudience('https://agent.example', 43114n), 'https://agent.example/authz/43114')
  // The chain id is in the audience so a testnet token cannot authorize on mainnet.
  ok(
    'platformAudience: a different chain yields a different audience',
    platformAudience('https://agent.example', 43113) !== platformAudience('https://agent.example', 43114),
  )
  eq('dpopHtu: origin + the response path', dpopHtu('https://agent.example/'), 'https://agent.example/v1/sessions/oauth-response')
  // Session-independent by design: RFC 9449 defines htu without query or fragment.
  ok('dpopHtu: carries no session id or query', !dpopHtu('https://agent.example').includes('?'))
}

if (failures.length > 0) {
  console.error(`✗ committee.one-call: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ committee.one-call: ${passed} checks passed`)
