// Slot-driven committee client — offline test of the chain-wired surface:
// resolveSlotKeeperUrls / resolveVerifierDirectory discover the keeper + verifier set
// from a mocked registry, and createCommitteeSlotClient().{sign,encrypt} runs the full
// flow against a mocked verifier fleet + keeper. Proves a bare slot id is enough — no
// hardcoded node/verifier URLs.
//
// Run: tsx test/committee.slot.ts — exits non-zero on any failure.

import {bls12_381} from '@noble/curves/bls12-381'
import {ed25519} from '@noble/curves/ed25519'
import {
  selectVerifierCommittee,
  compoundTokenHash,
  verifierLeaf,
  merkleRoot,
  type CompoundTokenPayload,
} from '../src/committee/token.ts'
import {hexToBytes, bytesToHex} from '../src/crypto/hex.ts'
import {fromBytes, decryptEnvelope} from '../src/crypto/envelope.ts'
import {VERIFIER_TAG, resolveVerifierDirectory, resolveSlotKeeperUrls} from '../src/chain/discovery.ts'
import {createCommitteeSlotClient} from '../src/chain/committeeClient.ts'
import type {TasraChainClient} from '../src/chain/client.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean) {
  if (cond) passed++
  else failures.push(name)
}
const bareHex = (b: Uint8Array): string => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
const fill = (n: number, v: number): Uint8Array => new Uint8Array(n).fill(v)
const addr = (i: number): `0x${string}` => ('0x' + i.toString(16).padStart(40, '0')) as `0x${string}`

// ─── scenario ───────────────────────────────────────────────────────────────
const registrySize = 5
const committee = 3
const quorum = 2
const seed = fill(32, 0xab)
const slotId = ('0x' + bareHex(fill(32, 0xcd))) as `0x${string}`
const vpHash = fill(32, 0x11) // the verifier's (mocked) presentation hash
const holderHash = fill(32, 0x1a) // the verifier-authenticated holder (stable across presentations)
const ruleHash = fill(32, 0x22)
const epoch = 7

// verifier operators (sorted-ascending addresses → same order the SDK indexes by)
const secrets = Array.from({length: registrySize}, (_, i) => fill(32, 0x40 + i))
const vPubkeys = secrets.map(s => ed25519.getPublicKey(s))
const vOperators = Array.from({length: registrySize}, (_, i) => addr(i + 1))
const vUrls = Array.from({length: registrySize}, (_, i) => `http://verifier-${i}`)
const leaves = vOperators.map((op, i) => verifierLeaf(i, hexToBytes(op), vPubkeys[i]!))
const snapshotRoot = merkleRoot(leaves)!

// keeper node the slot is assigned to
const keeperOp = addr(0x100)
const keeperUrl = 'http://keeper-0'

// a BLS slot group keypair (for the encrypt round-trip)
const mskScalar = 0x123456789abcdefn
const scalarToLe = (s: bigint): Uint8Array => {
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++, s >>= 8n) out[i] = Number(s & 0xffn)
  return out
}
const msk = scalarToLe(mskScalar)
const mpk = bls12_381.G2.ProjectivePoint.BASE.multiply(mskScalar).toRawBytes(true)

// ─── mock chain client ────────────────────────────────────────────────────────
const nodeInfo = new Map<string, {url: string; pubkey: `0x${string}`}>()
vOperators.forEach((op, i) => nodeInfo.set(op.toLowerCase(), {url: vUrls[i]!, pubkey: ('0x' + bareHex(vPubkeys[i]!)) as `0x${string}`}))
nodeInfo.set(keeperOp.toLowerCase(), {url: keeperUrl, pubkey: '0x' as `0x${string}`})

const ZERO_ROOT = ('0x' + '00'.repeat(32)) as `0x${string}`
// 'anchored' = a real snapshot; 'zero' = deployed but un-anchored (zero root);
// 'missing' = VerifierSetRegistry absent from the address book (requireAddress throws,
// the way the real chain client does) — must still surface the clear no-snapshot error.
type SnapMode = 'anchored' | 'zero' | 'missing'
function makeChain(snap: SnapMode): TasraChainClient {
  return {
    // Discovery reads the per-operator values through `readMany` so they batch through
    // Multicall3 where it exists. The fake resolves them from the same tables as the
    // single-item readers below, and honours `allowFailure: false` — an unreadable
    // operator must fail the call rather than renumber an ordered directory.
    readMany: (
      contract: string,
      functionName: string,
      argsList: readonly unknown[][],
      opts?: {allowFailure?: boolean},
    ) => {
      const results = argsList.map(args => {
        const op = String(args[0]).toLowerCase()
        if (contract === 'NodeRegistry' && functionName === 'hasTag') {
          return args[1] === VERIFIER_TAG && vOperators.some(v => v.toLowerCase() === op)
        }
        if (contract === 'NodeRegistry' && functionName === 'nodeOf') {
          const info = nodeInfo.get(op)
          return info
            ? {operator: args[0], dns: '', url: info.url, p2pAddr: '', pubkey: info.pubkey, active: true}
            : null
        }
        throw new Error(`fake readMany: unexpected ${contract}.${functionName}`)
      })
      if (opts?.allowFailure === false && results.some(r => r === null)) {
        return Promise.reject(new Error(`fake readMany: ${contract}.${functionName} had an unreadable item`))
      }
      return Promise.resolve(results)
    },
    multicallAddress: () => Promise.resolve(null),
    readers: {
      nodeRegistry: {
        activeOperators: async () => [...vOperators, keeperOp],
        hasTag: async (op: `0x${string}`, tag: `0x${string}`) =>
          tag === VERIFIER_TAG && vOperators.some(v => v.toLowerCase() === op.toLowerCase()),
        nodeOf: async (op: `0x${string}`) => {
          const info = nodeInfo.get(op.toLowerCase())!
          return {operator: op, dns: '', url: info.url, p2pAddr: '', pubkey: info.pubkey, active: true}
        },
      },
      keyRegistry: {
        assignedNodes: async () => [keeperOp],
        verifierPolicy: async () => [committee, quorum] as const,
        getKeySlot: async () => ({publicKey: ('0x' + bareHex(mpk)) as `0x${string}`, epoch, mode: 1}),
      },
      beacon: {
        seed: async () => ('0x' + bareHex(seed)) as `0x${string}`,
        epoch: async () => BigInt(epoch),
      },
      verifierSet: {
        snapshotAt: async () => {
          if (snap === 'missing') {
            throw new Error('AddressBook is missing VerifierSetRegistry. Known: NodeRegistry, KeyRegistry')
          }
          return snap === 'anchored'
            ? {root: ('0x' + bareHex(snapshotRoot)) as `0x${string}`, size: registrySize}
            : {root: ZERO_ROOT, size: 0}
        },
      },
    },
  } as unknown as TasraChainClient
}
const chain = makeChain('anchored')

// ─── mock verifier fleet + keeper ───────────────────────────────────────────────
const realFetch = globalThis.fetch
function installFleet() {
  globalThis.fetch = (async (url: string, init?: {body?: string}) => {
    const u = String(url)

    // keeper: /v1/committee/sign → canned FROST result
    if (u.includes('/v1/committee/sign')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          key_slot_id: slotId,
          group_public_key: bareHex(fill(32, 0x99)),
          signature_r: bareHex(fill(32, 0x01)),
          signature_z: bareHex(fill(32, 0x02)),
          message_sha256: bareHex(fill(32, 0x03)),
          epoch,
        }),
      } as unknown as Response
    }

    // verifier: /v1/committee-authorize → sign the canonical token hash if drawn
    const m = /verifier-(\d+)/.exec(u)
    if (m && u.includes('/v1/committee-authorize')) {
      const idx = Number(m[1])
      const body = JSON.parse(init?.body ?? '{}') as {
        seed: string; epoch: number; slot_id: string; iat: number; exp: number; token_type: string
      }
      const drawn = selectVerifierCommittee(hexToBytes(body.slot_id), body.epoch, hexToBytes(body.seed), registrySize, committee)
      if (!drawn.includes(idx)) {
        return {ok: false, status: 403, text: async () => 'not selected'} as unknown as Response
      }
      const payload: CompoundTokenPayload = {
        tokenType: body.token_type as CompoundTokenPayload['tokenType'],
        seed: hexToBytes(body.seed),
        epoch: body.epoch,
        slotId: hexToBytes(body.slot_id),
        vpHash,
        holderHash,
        ruleHash,
        verifierIndexes: drawn,
        iat: body.iat,
        exp: body.exp,
      }
      const tokenHash = compoundTokenHash(payload)
      const signature = ed25519.sign(tokenHash, secrets[idx]!)
      return {
        ok: true,
        status: 200,
        json: async () => ({
          verifier_index: idx,
          token_hash: bareHex(tokenHash),
          vp_hash: bareHex(vpHash),
          holder_hash: bareHex(holderHash),
          rule_hash: bareHex(ruleHash),
          signature: bareHex(signature),
          committee_indexes: drawn,
        }),
      } as unknown as Response
    }
    return {ok: false, status: 404, text: async () => 'unexpected ' + u} as unknown as Response
  }) as typeof globalThis.fetch
}

try {
  // ── discovery ─────────────────────────────────────────────────────────────
  {
    const dir = await resolveVerifierDirectory(chain)
    ok('verifier directory has every tagged operator', dir.length === registrySize)
    ok('directory drops non-verifier (keeper) operators', !dir.some(v => v.url === keeperUrl))
    ok('directory indexes are contiguous 0..n', dir.every((v, i) => v.index === i))
    ok('directory resolves urls + operator + pubkey from chain', dir.every(v => !!v.url && !!v.operator && !!v.pubkey))

    const urls = await resolveSlotKeeperUrls(chain, slotId)
    ok('slot keeper url resolved from assignedNodes → nodeOf().url', urls.length === 1 && urls[0] === keeperUrl)
  }

  // ── sign: full slot-id-only committee flow ──────────────────────────────────
  {
    installFleet()
    const kk = createCommitteeSlotClient({
      chain,
      holder: 'did:example:alice',
      credentials: ['vc-jwt'],
      holderProof: 'holder-proof-jws',
    })
    const sig = await kk.sign(slotId, new TextEncoder().encode('authorize me'))
    ok('sign resolved keeper + verifiers from the slot id alone', sig.keySlotId === slotId)
    ok('sign returned a FROST signature', sig.signature.r.length === 32 && sig.signature.z.length === 32)

    const dir = await kk.verifierDirectory()
    ok('client caches the discovered verifier directory', dir.length === registrySize)
  }

  // ── a committee needs one proof per verifier, so the client must take the function ──
  {
    installFleet()
    const seen: string[] = []
    const kk = createCommitteeSlotClient({
      chain,
      holder: 'did:example:alice',
      credentials: ['vc-jwt'],
      // One string names one audience and burns one verifier's nonce; a drawn committee refuses the
      // rest with "aud does not include this verifier". This is the shape a real deployment needs.
      holderProof: v => {
        seen.push(v.url)
        return `holder-proof-for-${v.url}`
      },
    })
    const sig = await kk.sign(slotId, new TextEncoder().encode('authorize me'))
    ok('sign works with a per-verifier holder proof', sig.keySlotId === slotId)
    ok(`a proof was minted for each verifier (${seen.length}/${registrySize})`, seen.length === registrySize)
    ok('each proof names its own verifier', new Set(seen).size === seen.length)
  }

  // ── no-fallback: an un-anchored verifier snapshot must FAIL, never degrade ────
  for (const [mode, label] of [
    ['zero', 'un-anchored snapshot (zero root)'],
    ['missing', 'VerifierSetRegistry absent from the address book'],
  ] as const) {
    installFleet()
    const kk = createCommitteeSlotClient({
      chain: makeChain(mode),
      holder: 'did:example:alice',
      credentials: ['vc-jwt'],
      holderProof: 'holder-proof-jws',
    })
    let msg = ''
    try {
      await kk.sign(slotId, new TextEncoder().encode('authorize me'))
    } catch (e) {
      msg = e instanceof Error ? e.message : String(e)
    }
    ok(`sign refuses to fall back to a configured set — ${label}`, /trustless|snapshot|configured set/.test(msg))
  }

  // ── encrypt: local, key read from chain (no verifier/JWT/node) ───────────────
  {
    const kk = createCommitteeSlotClient({
      chain,
      holder: 'did:example:alice',
      credentials: ['vc-jwt'],
      holderProof: 'holder-proof-jws',
    })
    const plaintext = new TextEncoder().encode('only slot members can read this 🔐')
    const wire = await kk.encrypt(slotId, plaintext)
    const back = decryptEnvelope(fromBytes(wire), msk)
    ok('encrypt→decrypt round-trips with the chain-read group key', bytesToHex(back) === bytesToHex(plaintext))
  }

  // ── encrypt needs NO credentials: `{chain}` alone is a valid encrypt-only handle ──
  // The credential fields authorize the verifier committee, which only sign/decrypt
  // consult. Checking them in the constructor made an offline encrypt impossible.
  {
    const kk = createCommitteeSlotClient({chain})
    const plaintext = new TextEncoder().encode('encrypt without credentials')
    const wire = await kk.encrypt(slotId, plaintext)
    const back = decryptEnvelope(fromBytes(wire), msk)
    ok('encrypt works from a chain client alone (no credentials)', bytesToHex(back) === bytesToHex(plaintext))

    // …but sign/decrypt must still refuse, naming every missing field.
    let msg = ''
    try {
      await kk.sign(slotId, new Uint8Array([1, 2, 3]))
    } catch (e) {
      msg = e instanceof Error ? e.message : String(e)
    }
    ok(
      'sign without credentials throws, naming each missing field',
      ['holder', 'credentials', 'holderProof'].every(f => msg.includes(f)),
    )
    // The rule is NOT a required input and must not be demanded. The
    // verifier fetches it from a keeper; requiring it here refused to authorize
    // unless the caller supplied a value that was then ignored.
    ok(
      'and does NOT demand dcqlRule, which the verifier no longer accepts',
      !msg.includes('dcqlRule'),
    )
    ok('…and points at sign() as the operation', msg.includes('sign()'))

    // A partially-configured client names only what is actually absent.
    let partial = ''
    try {
      await createCommitteeSlotClient({chain, holder: 'did:example:alice', credentials: ['vc-jwt']}).sign(
        slotId,
        new Uint8Array([1]),
      )
    } catch (e) {
      partial = e instanceof Error ? e.message : String(e)
    }
    ok(
      'partial config: reports only the missing fields',
      partial.includes('holderProof') &&
        !partial.includes('dcqlRule') &&
        !partial.includes('holder,') &&
        !partial.includes('credentials'),
    )
  }
} finally {
  globalThis.fetch = realFetch
}

if (failures.length > 0) {
  console.error(`✗ committee.slot: ${failures.length} failed:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ committee.slot: ${passed} checks passed`)
