// The request-binding derivations — `request_hash`, `vp_nonce` and the decrypt payload
// digest — shared with the keepers and the Verifier Agent. These must stay
// byte-identical, or the wallet signs a nonce every verifier refuses. test/dpop.ts and
// the committee conformance suite pin them against known-answer vectors.

import {keccak_256} from '@noble/hashes/sha3'
import {sha256} from '@noble/hashes/sha256'
import {b64url, utf8} from './jose.js'

export const REQUEST_BINDING_DOMAIN = 'keykeeper-committee/request-binding/v1'
export const VP_NONCE_DOMAIN = 'keykeeper/vp-nonce/v1'
export const DECRYPT_DIGEST_DOMAIN = 'keykeeper/decrypt-audit-ciphertext/v1'

export type CommitteeAction = 'sign' | 'decrypt' | 'ibe-extract' | 'dual-approve'
export const COMMITTEE_ACTIONS: readonly CommitteeAction[] = ['sign', 'decrypt', 'ibe-extract', 'dual-approve']

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}
const be32 = (n: number) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255])
function be64(n: number | bigint): Uint8Array {
  let v = BigInt(n)
  const out = new Uint8Array(8)
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/**
 * `keccak256(DOMAIN ‖ chain_id u64 BE ‖ slot_id ‖ len(action) u32 BE ‖ action ‖ payload_digest)` —
 * the ONE binding hash the verifier-agent, the JAR signer, every drawn verifier, the keeper, the
 * accountant audit and this SDK compute. The wallet's request body is deliberately NOT in it.
 */
export function requestHash(chainId: number | bigint, slotId: Uint8Array, action: CommitteeAction, payloadDigest: Uint8Array): Uint8Array {
  if (slotId.length !== 32) throw new Error('requestHash: slotId must be 32 bytes')
  if (payloadDigest.length !== 32) throw new Error('requestHash: payloadDigest must be 32 bytes')
  return keccak_256(concat(utf8(REQUEST_BINDING_DOMAIN), be64(chainId), slotId, be32(action.length), utf8(action), payloadDigest))
}

/**
 * The authenticated context a wallet nonce binds beyond the request hash and the session
 * random (the reference nonce context): the beacon epoch, the anchored verifier-set
 * snapshot root and size, the slot's effective policy and the creator-signed operation's
 * expiry. The verifier-agent, the JAR signer and every fan-out verifier rebuild it from their own reads;
 * changing any field needs a new wallet proof. `snapshotRoot` is all-zero only where no
 * verifier-set registry is configured (dev).
 */
export interface NonceContext {
  epoch: number | bigint
  snapshotRoot: Uint8Array
  registrySize: number
  committee: number
  quorum: number
  operationExp: number | bigint
}

/**
 * `base64url(keccak256(NONCE_DOMAIN ‖ request_hash ‖ random ‖ epoch u64 BE ‖ snapshot_root ‖
 * registry_size u32 BE ‖ committee u32 BE ‖ quorum u32 BE ‖ operation_exp i64 BE))` — the
 * nonce a KB-JWT must carry (the reference vp-nonce derivation, domain v2).
 */
export function derivedNonce(reqHash: Uint8Array, random: Uint8Array, ctx: NonceContext): string {
  if (reqHash.length !== 32) throw new Error('derivedNonce: reqHash must be 32 bytes')
  if (random.length !== 32) throw new Error('derivedNonce: random must be 32 bytes')
  if (ctx.snapshotRoot.length !== 32) throw new Error('derivedNonce: snapshotRoot must be 32 bytes')
  return b64url(
    keccak_256(
      concat(
        utf8(VP_NONCE_DOMAIN),
        reqHash,
        random,
        be64(ctx.epoch),
        ctx.snapshotRoot,
        be32(ctx.registrySize),
        be32(ctx.committee),
        be32(ctx.quorum),
        be64(BigInt.asUintN(64, BigInt(ctx.operationExp))),
      ),
    ),
  )
}

/**
 * The per-action `payload_digest` the keeper recomputes at `enforce_request_binding`:
 * `sign` = sha256(message), `ibe-extract` = sha256(identity), `decrypt` = the ciphertext
 * digest ({@link decryptPayloadDigest}), `dual-approve` = the digest the caller already
 * holds. Pass exactly one of the inputs the action needs.
 */
export function payloadDigestFor(
  action: CommitteeAction,
  args: {message?: Uint8Array; identity?: string; payloadDigest?: Uint8Array},
): Uint8Array {
  switch (action) {
    case 'sign':
      if (args.message) return sha256(args.message)
      break
    case 'ibe-extract':
      if (args.identity !== undefined) return sha256(utf8(args.identity))
      break
    case 'decrypt':
    case 'dual-approve':
      break
  }
  if (args.payloadDigest) {
    if (args.payloadDigest.length !== 32) throw new Error('payloadDigest must be 32 bytes')
    return args.payloadDigest
  }
  throw new Error(`payloadDigestFor(${action}): missing the input that action digests`)
}

/**
 * The `decrypt` action's digest, mirroring the reference decrypt digest:
 * `sha256(DOMAIN ‖ len(u) u64 LE ‖ u ‖ len(aead_ct) u64 LE ‖ aead_ct)` — the AEAD nonce is
 * deliberately excluded (it is not authorised content).
 */
export function decryptPayloadDigest(u: Uint8Array, aeadCt: Uint8Array): Uint8Array {
  const le64 = (n: number) => {
    const out = new Uint8Array(8)
    let v = BigInt(n)
    for (let i = 0; i < 8; i++) {
      out[i] = Number(v & 0xffn)
      v >>= 8n
    }
    return out
  }
  return sha256(concat(utf8(DECRYPT_DIGEST_DOMAIN), le64(u.length), u, le64(aeadCt.length), aeadCt))
}
