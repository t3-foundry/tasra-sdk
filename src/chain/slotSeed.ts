// ADR-0075: the per-commitment draw seed.
//
// Under ADR-0030 a slot is committed, then revealed once the beacon has advanced past the
// commit's target epoch. The wait is what makes the committee draw ungrindable — the seed must
// post-date the commitment — and it costs ONE BEACON EPOCH, which at the production cadence is up
// to an hour.
//
// ADR-0075 keeps the property and drops the wait: the accountant set threshold-signs
// `KeyRegistry.commitSeedDigest(commitment)` on demand, and the reveal derives the draw seed from
// that signature. It post-dates the commitment because it is OVER the commitment.
//
// This module is the client half. It is deliberately best-effort: when no accountant answers, the
// caller falls back to the epoch wait, which still works and is what every existing deployment
// does. A seed that cannot be fetched is slower, never wrong.

import type {Hex} from 'viem'
import type {TasraChainClient} from './client.js'
import {keyRegistryAbi} from './abis/index.js'
import {resolveAccountantUrls} from './discovery.js'

/** What an accountant returns from `POST /v1/slot-seed`. */
export interface SlotSeed {
  commitment: Hex
  /** `KeyRegistry.commitSeedDigest(commitment)` — what the signature is over. */
  digest: Hex
  /** The 64-byte BN254 G1 threshold signature; pass as `seedSig` to `revealKeySlotWithSeed`. */
  signature: Hex
}

/** A 64-byte BN254 G1 point, hex-encoded: the wire size of a threshold signature. */
const SIG_HEX_LEN = 2 + 64 * 2

function parseSeed(body: unknown, commitment: Hex): SlotSeed | null {
  if (!body || typeof body !== 'object') return null
  const {digest, signature} = body as Record<string, unknown>
  if (typeof digest !== 'string' || typeof signature !== 'string') return null
  if (!/^0x[0-9a-fA-F]{64}$/.test(digest)) return null
  // ⚠ Pin the LENGTH, not just the alphabet. An accountant that answered with a short or
  // over-long signature would otherwise be discovered by a reverting reveal, which costs gas and
  // names `BadSeedSignature` — a message that points at the signature's validity, not its shape.
  if (signature.length !== SIG_HEX_LEN || !/^0x[0-9a-fA-F]+$/.test(signature)) return null
  // An all-zero signature is the point at infinity. The contract rejects it (it would otherwise
  // verify against an all-zero key from anyone), but rejecting it here means a misbehaving
  // accountant cannot make a caller pay for the discovery.
  if (/^0x0+$/.test(signature)) return null
  return {commitment, digest: digest.toLowerCase() as Hex, signature: signature.toLowerCase() as Hex}
}

async function askOne(url: string, commitment: Hex, timeoutMs: number): Promise<SlotSeed | null> {
  const base = url.replace(/\/+$/, '')
  const res = await fetch(`${base}/v1/slot-seed`, {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({commitment}),
    signal: AbortSignal.timeout(timeoutMs),
  })
  // 503 is the expected answer from an accountant whose threshold set is not up, and 404 from one
  // whose chain view has not yet seen the commit. Both mean "ask someone else / try again",
  // neither is an error worth surfacing — the caller's fallback is the epoch wait.
  if (!res.ok) return null
  return parseSeed(await res.json(), commitment)
}

export interface SlotSeedOptions {
  /** Accountant base URLs. Resolved from `NodeRegistry` when omitted. */
  urls?: string[]
  /** Per-accountant HTTP timeout. The round itself is bounded server-side. */
  timeoutMs?: number
}

/**
 * Ask the accountant set for `commitment`'s draw seed, verifying the answer before returning it.
 *
 * Returns `null` when no accountant could serve one — an unwired endpoint, a set that is down, or
 * a commitment the chain has not yet caught up to. The caller then falls back to ADR-0030's epoch
 * wait.
 *
 * ⚠⚠ THE DIGEST IS CHECKED AGAINST THE REGISTRY, not recomputed here. `commitSeedDigest` binds the
 *    chain id and the registry's own address, and re-deriving it in this SDK would create a second
 *    copy of that formula that can drift from the contract silently — the exact shape that has
 *    already cost this codebase a beacon outage. One `eth_call` against the contract the reveal is
 *    about to be sent to cannot disagree with it.
 *
 * ⚠ The SIGNATURE is not verified here. Verifying a BN254 pairing in TypeScript would mean
 *   shipping a pairing implementation to do, less reliably, what the reveal does on chain for the
 *   gas the caller is already spending. What IS checked is everything cheap: shape, length,
 *   non-infinity, and that the digest is the right one for this commitment.
 */
export async function requestSlotSeed(
  chain: TasraChainClient,
  keyRegistry: `0x${string}`,
  commitment: Hex,
  opts: SlotSeedOptions = {},
): Promise<SlotSeed | null> {
  const timeoutMs = opts.timeoutMs ?? 20_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
    throw new Error('Invalid slot-seed timeout')
  }
  const urls = opts.urls ?? (await resolveAccountantUrls(chain).catch(() => []))
  if (!urls.length) return null

  const expected = (await chain.client.readContract({
    address: keyRegistry,
    abi: keyRegistryAbi,
    functionName: 'commitSeedDigest',
    args: [commitment],
  })) as Hex

  for (const url of urls) {
    let seed: SlotSeed | null
    try {
      seed = await askOne(url, commitment, timeoutMs)
    } catch {
      // One unreachable accountant is not a failure of the set. Move on.
      continue
    }
    if (!seed) continue
    // A digest that is not the registry's own means this accountant is bound to a DIFFERENT
    // registry or chain — its signature could never satisfy the reveal. Skip it rather than
    // spending gas to be told so.
    if (seed.digest !== expected.toLowerCase()) continue
    return seed
  }
  return null
}
