// LIVE committee authorization against a running fleet.
//
// Why this file exists: `requestCommitteeToken` has been complete for a while and
// `test/committee.request.ts` covers it thoroughly — OFFLINE, against mocks. So
// the whole path (verifier draw → per-verifier authorization → compound
// token) had never been run against a real verifier. A mock cannot catch a wire
// mismatch, because the mock is written from the same understanding as the client.
//
// It also closes the loop end to end: `ruleVersion` has to travel
// contract → `sol!` decode → the verifier's `fetch_rule_versioned` → the
// committee reply → this SDK, on bytes the deployed contract produced.
//
// Run against the demo fleet:
//
//   KK_RPC=http://127.0.0.1:8545 \
//   KK_KEY_REGISTRY=0x… KK_NODE_REGISTRY=0x… KK_BEACON=0x… KK_VERIFIER_SET=0x… \
//   KK_SLOT=0x… KK_VERIFIERS=http://127.0.0.1:8181,… \
//   KK_HOLDER=did:demo:alice KK_VC=<compact-jws> TASRA_JWT_AUD=<your-node-aud> \
//   KK_HOLDER_KEY=0x… \
//     npx tsx test/live/committeeAuthorize.ts

import {createTasraChainClient} from '../../src/chain/index.js'
import {requestCommitteeToken} from '../../src/committee/index.js'
import {createHolderProof} from '../../src/auth/holderProof.js'

const env = (k: string): string => {
  const v = process.env[k]
  if (!v) throw new Error(`missing ${k}`)
  return v
}
/** `snapshotAt` decodes as a named tuple or an object depending on the ABI; take both. */
function normaliseSnapshot(raw: unknown): {root: `0x${string}`; size: number} | null {
  if (raw && typeof raw === 'object' && 'size' in (raw as Record<string, unknown>)) {
    const o = raw as {root: `0x${string}`; size: number | bigint}
    return {root: o.root, size: Number(o.size)}
  }
  if (Array.isArray(raw) && raw.length >= 2) {
    return {root: raw[0] as `0x${string}`, size: Number(raw[1])}
  }
  return null
}

const ok = (name: string, cond: boolean, detail = ''): void => {
  console.log(`${cond ? '  ok  ' : '  FAIL'} ${name}${detail ? ` — ${detail}` : ''}`)
  if (!cond) process.exitCode = 1
}

async function main(): Promise<void> {
  const chain = createTasraChainClient({
    rpcUrl: env('KK_RPC'),
    addresses: {
      KeyRegistry: env('KK_KEY_REGISTRY') as `0x${string}`,
      NodeRegistry: env('KK_NODE_REGISTRY') as `0x${string}`,
      ThresholdRandomBeacon: env('KK_BEACON') as `0x${string}`,
      VerifierSetRegistry: env('KK_VERIFIER_SET') as `0x${string}`,
    },
  })
  const slotId = env('KK_SLOT') as `0x${string}`
  const urls = env('KK_VERIFIERS').split(',').map(s => s.trim()).filter(Boolean)
  // Index is the verifier's position in the anchored snapshot; the demo fleet
  // registers them in order, which is what the draw indexes against.
  const verifiers = urls.map((url, index) => ({index, url}))

  console.log('== chain reads (the values the verifier independently re-derives)')
  const [committee, quorum] = await chain.readers.keyRegistry.verifierPolicy(slotId)
  const epoch = await chain.readers.beacon.epoch()
  const snap = await chain.readers.verifierSet.snapshotAt(BigInt(epoch as bigint))
  console.log(`   verifierPolicy = committee ${committee}, quorum ${quorum}`)
  console.log(`   beacon epoch   = ${epoch}`)
  console.log(`   snapshot       = ${JSON.stringify(snap)}`)
  ok('slot has a verifier policy', Number(committee) > 0, `committee=${committee}`)

  // ⚠ The demo fleet issues VCs with NO `cnf` claim and holds no holder keypair,
  // which is why its verifiers run `require_holder_binding = false`. So this run
  // exercises the no-proof path by design; set KK_HOLDER_KEY to exercise the
  // bound path on a fleet that has one.
  let holderProof: string | undefined
  if (process.env.KK_HOLDER_KEY) {
    console.log('== holder proof (nonce issued by the verifier, so it cannot be pre-minted)')
    holderProof = await createHolderProof(urls[0]!, {
      signer: {
        alg: 'EdDSA',
        did: env('KK_HOLDER'),
        secretKey: Buffer.from(env('KK_HOLDER_KEY').replace(/^0x/, ''), 'hex'),
      },
      audience: env('KK_AUDIENCE'),
      credentials: [env('KK_VC')],
      slotId,
    })
    ok('holder proof built', holderProof.split('.').length === 3)
  } else {
    console.log('== no holder key configured; running the require_holder_binding=false path')
  }

  console.log('== POST /v1/committee-authorize to each verifier, gather a quorum')
  const res = await requestCommitteeToken({
    chain: {
      seed: () => chain.readers.beacon.seed() as Promise<`0x${string}`>,
      epoch: () => chain.readers.beacon.epoch() as Promise<bigint>,
      verifierPolicy: (id: `0x${string}`) => chain.readers.keyRegistry.verifierPolicy(id),
      // viem returns a named tuple for this struct; normalise to the shape the
      // SDK expects rather than binding to one spelling of the ABI.
      snapshot: async (e: bigint) => {
        const raw = (await chain.readers.verifierSet.snapshotAt(e)) as unknown
        return normaliseSnapshot(raw)
      },
    },
    verifiers,
    slotId,
    holder: env('KK_HOLDER'),
    credentials: [env('KK_VC')],
    holderProof,
    allowNoHolderProof: !holderProof,
  })

  console.log(`   signatures gathered: ${res.token.signatures.length} (quorum ${res.quorum})`)
  console.log(`   registrySize=${res.registrySize} committee=${res.committee} epoch=${res.epoch}`)
  console.log(`   ruleVersion=${String(res.ruleVersion)}`)

  ok('a quorum of drawn verifiers authorized', res.token.signatures.length >= res.quorum)
  ok(
    'registry size came from the anchored snapshot',
    res.registrySize === normaliseSnapshot(snap)!.size,
  )
  // The loop: contract → sol! decode → fetch_rule_versioned → reply → here.
  ok('verifiers reported a ruleVersion', typeof res.ruleVersion === 'number', String(res.ruleVersion))
  if (process.env.KK_EXPECT_RULE_VERSION !== undefined) {
    ok(
      `ruleVersion is ${process.env.KK_EXPECT_RULE_VERSION}`,
      res.ruleVersion === Number(process.env.KK_EXPECT_RULE_VERSION),
      String(res.ruleVersion),
    )
  }
}

main().catch(e => {
  console.error('LIVE RUN FAILED:', e instanceof Error ? e.message : e)
  process.exitCode = 1
})
