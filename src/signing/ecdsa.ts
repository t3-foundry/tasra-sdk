// Threshold ECDSA (secp256k1) signing for EVM EOAs — POST /v1/sign/eoa-digest.
// The node coordinates the signing ceremony internally; the client makes one
// round-trip with a 32-byte prehash digest and gets back Ethereum (r, s, v).
// The slot must be a `tecdsa`-mode slot.
//
// Bodies use BARE hex (no 0x): the node hex-decodes key_slot_id and digest
// directly.

import {hexToBytes} from '../crypto/hex.js'
import {bytesToHex as toHex} from '@noble/hashes/utils'
import {secp256k1} from '@noble/curves/secp256k1'
import {keccak_256} from '@noble/hashes/sha3'
import {httpError} from '../errors.js'

const strip0x = (s: string): string => (s.startsWith('0x') ? s.slice(2) : s)
const base = (u: string): string => u.replace(/\/$/, '')

export interface EoaSignOpts {
  nodeUrl: string
  jwt: string
  /** 0x-prefixed (or bare) bytes32 slot id (must be a tecdsa-mode slot). */
  slotId: string
  /** The 32-byte prehash to sign (e.g. the EIP-1559 signing hash). */
  digest: Uint8Array
  /** 20-byte operator address to pin (anti-Sybil). */
  targetKeykeeper?: string
}

export interface EoaSignature {
  /** 33-byte compressed secp256k1 group public key (the EOA's pubkey). */
  groupPublicKey: Uint8Array
  /** 32-byte big-endian r. */
  r: Uint8Array
  /** 32-byte big-endian s (low-s normalized per EIP-2). */
  s: Uint8Array
  /** Raw recovery id, 0 or 1. Use ethSignatureV() to get the EVM `v`. */
  yParity: 0 | 1
}

/**
 * Threshold-sign a 32-byte digest with a tecdsa slot's key. Returns the raw
 * Ethereum signature components; assemble into a transaction with ethSignatureV().
 */
export async function signEoaDigest(opts: EoaSignOpts): Promise<EoaSignature> {
  if (opts.digest.length !== 32) {
    throw new Error(`signEoaDigest: digest must be 32 bytes, got ${opts.digest.length}`)
  }
  const body: Record<string, unknown> = {
    key_slot_id: strip0x(opts.slotId),
    digest: toHex(opts.digest),
  }
  if (opts.targetKeykeeper) body.target_keykeeper = strip0x(opts.targetKeykeeper)

  const url = `${base(opts.nodeUrl)}/v1/sign/eoa-digest`
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json', Authorization: `Bearer ${opts.jwt}`},
    body: JSON.stringify(body),
  })
  if (!res.ok) throw await httpError(res, url, 'sign/eoa-digest')
  const d = (await res.json()) as {
    group_public_key: string
    signature_r: string
    signature_s: string
    signature_v: number | string
  }
  return {
    groupPublicKey: hexToBytes(d.group_public_key),
    r: hexToBytes(d.signature_r),
    s: hexToBytes(d.signature_s),
    yParity: Number(d.signature_v) === 1 ? 1 : 0,
  }
}

/** Map the raw recovery id (0/1) to an Ethereum `v`: legacy 27/28, or EIP-155
 *  (`35 + 2·chainId + yParity`) when a chainId is given. */
export function ethSignatureV(yParity: number, chainId?: number): number {
  return chainId === undefined ? 27 + yParity : 35 + 2 * chainId + yParity
}

// EIP-55 checksum: uppercase each hex nibble whose matching keccak nibble is ≥ 8.
function toChecksumAddress(addrLowerNoPrefix: string): string {
  const hash = toHex(keccak_256(addrLowerNoPrefix)) // keccak of the lowercase ASCII hex
  let out = ''
  for (let i = 0; i < addrLowerNoPrefix.length; i++) {
    out += parseInt(hash[i]!, 16) >= 8 ? addrLowerNoPrefix[i]!.toUpperCase() : addrLowerNoPrefix[i]!
  }
  return out
}

/**
 * Derive the EIP-55 checksummed `0x` Ethereum address of a threshold EOA from its
 * secp256k1 group public key — pass `EoaSignature.groupPublicKey` (33-byte
 * compressed) or a 65-byte uncompressed key. Pure `@noble` (no ethers/web3): the
 * key is decompressed, keccak-256'd over X‖Y, and the low 20 bytes are checksummed.
 * This is what an ethers `Signer.getAddress()` returns for a Tasra EOA slot.
 */
export function addressFromEoaPubkey(pubkey: Uint8Array): `0x${string}` {
  const uncompressed = secp256k1.ProjectivePoint.fromHex(pubkey).toRawBytes(false)
  const addr = toHex(keccak_256(uncompressed.subarray(1)).subarray(12)) // keccak(X‖Y) → last 20B
  return `0x${toChecksumAddress(addr)}`
}
