// Sign Ethereum transactions with a Tasra threshold-ECDSA (tECDSA) slot,
// via an ethers v6 Signer — drop it into ethers or Hardhat like any other signer.
//
//   npx tsx examples/ethers-signer.ts      # runs the offline self-test below
//
// This example imports the published 'tasra-sdk' entry point. The private key never exists anywhere: each
// signature is produced by the k-of-n keykeeper-node fleet via signEoaDigest();
// this Signer just turns ethers' transaction/message/typed-data hashes into that
// 32-byte digest call and re-assembles the {r,s,v} result.
//
// NOTE: the node's /v1/sign/eoa-digest path may be feature-gated in your
// deployment. The offline self-test at the bottom substitutes a LOCAL secp256k1
// key for the fleet to prove the assembly end-to-end without a live backend.
//
// ── Usage (ethers) ────────────────────────────────────────────────────────────
//   import {redeemRenewalToken} from 'tasra-sdk'
//   const signer = new TasraSigner({
//     nodes: ['https://node-1', 'https://node-2', 'https://node-3'],
//     slotId: '0x…',                                  // a tECDSA signing slot
//     getJwt: async () => (await redeemRenewalToken(verifier, renewalToken)).token,
//   }).connect(provider)
//   await signer.getAddress()
//   await signer.sendTransaction({to, value})         // signs + broadcasts via provider
//
// ── Usage (Hardhat) ───────────────────────────────────────────────────────────
//   const signer = new TasraSigner({nodes, slotId, getJwt}).connect(ethers.provider)
//   const erc20  = await ethers.getContractAt('IERC20', tokenAddr, signer)
//   await erc20.transfer(to, amount)                  // signed by the threshold fleet

import {
  AbstractSigner,
  Transaction,
  Signature,
  getBytes,
  hexlify,
  hashMessage,
  TypedDataEncoder,
  verifyMessage,
  verifyTypedData,
  type Provider,
  type TransactionRequest,
  type TransactionLike,
  type TypedDataDomain,
  type TypedDataField,
} from 'ethers'
import {secp256k1} from '@noble/curves/secp256k1'
import {signEoaDigest, addressFromEoaPubkey, fetchMpk} from 'tasra-sdk'

/** Raw Ethereum ECDSA components as returned by the threshold network. */
export interface RawEcdsaSig {
  r: Uint8Array // 32-byte big-endian
  s: Uint8Array // 32-byte big-endian (low-s)
  yParity: number // 0 | 1
}

export interface TasraSignerConfig {
  /** k-of-n keykeeper-node base URLs. */
  nodes: string[]
  /** 0x-prefixed bytes32 tECDSA slot id. */
  slotId: string
  /** Supply a fresh DCQL-gated JWT (e.g. via redeemRenewalToken / redeemCredential). */
  getJwt: () => Promise<string>
  /** ethers provider — needed to populate nonce/gas/chainId and to broadcast. */
  provider?: Provider | null
  /** The EOA address, if already known — skips the getAddress() key fetch. */
  address?: string
  /** Override the digest signer (used by the offline self-test); defaults to signEoaDigest. */
  signDigest?: (digest: Uint8Array) => Promise<RawEcdsaSig>
}

export class TasraSigner extends AbstractSigner {
  readonly cfg: TasraSignerConfig
  #address?: string
  readonly #signDigest: (digest: Uint8Array) => Promise<RawEcdsaSig>

  constructor(cfg: TasraSignerConfig) {
    super(cfg.provider ?? null)
    this.cfg = cfg
    this.#address = cfg.address
    this.#signDigest =
      cfg.signDigest ??
      (async digest => {
        const sig = await signEoaDigest({
          nodeUrl: cfg.nodes[0]!,
          jwt: await cfg.getJwt(),
          slotId: cfg.slotId,
          digest,
        })
        return {r: sig.r, s: sig.s, yParity: sig.yParity}
      })
  }

  /** The threshold EOA address — derived from the slot's secp256k1 group key, or the configured one. */
  async getAddress(): Promise<string> {
    if (this.#address) return this.#address
    // Assumes /v1/keys/{slot}/public serves the secp256k1 key for a tECDSA slot;
    // pass `address` in the config to skip this.
    const {mpkBytes} = await fetchMpk(this.cfg.nodes[0]!, this.cfg.slotId)
    return (this.#address = addressFromEoaPubkey(mpkBytes))
  }

  connect(provider: Provider | null): TasraSigner {
    return new TasraSigner({...this.cfg, provider})
  }

  /** Sign an arbitrary 32-byte digest via the threshold network → an ethers Signature. */
  async ethSignature(digest: Uint8Array): Promise<Signature> {
    const {r, s, yParity} = await this.#signDigest(digest)
    return Signature.from({r: hexlify(r), s: hexlify(s), yParity: (yParity ? 1 : 0) as 0 | 1})
  }

  async signTransaction(tx: TransactionRequest): Promise<string> {
    const pop = await this.populateTransaction(tx)
    delete (pop as {from?: unknown}).from // a Transaction has no `from` (it's recovered)
    const t = Transaction.from(pop as unknown as TransactionLike<string>)
    t.signature = await this.ethSignature(getBytes(t.unsignedHash))
    return t.serialized
  }

  async signMessage(message: string | Uint8Array): Promise<string> {
    return (await this.ethSignature(getBytes(hashMessage(message)))).serialized
  }

  async signTypedData(
    domain: TypedDataDomain,
    types: Record<string, Array<TypedDataField>>,
    value: Record<string, unknown>,
  ): Promise<string> {
    return (await this.ethSignature(getBytes(TypedDataEncoder.hash(domain, types, value)))).serialized
  }
}

// ── Offline self-test: a LOCAL secp256k1 key stands in for the threshold fleet ──
// Proves the adapter assembles signatures that ethers recovers back to the right
// address — for messages, EIP-712 typed data, and an EIP-1559 transaction —
// without any running node (the live tECDSA path is the default in production).

async function selfTest(): Promise<void> {
  const priv = getBytes('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d')
  const pub = secp256k1.getPublicKey(priv, true)
  const addr = addressFromEoaPubkey(pub)

  const localSignDigest = async (digest: Uint8Array): Promise<RawEcdsaSig> => {
    const sig = secp256k1.sign(digest, priv) // low-s by default; carries .recovery
    const compact = sig.toCompactRawBytes() // r‖s, 64 bytes
    return {r: compact.slice(0, 32), s: compact.slice(32, 64), yParity: sig.recovery!}
  }

  const signer = new TasraSigner({
    nodes: ['http://node'],
    slotId: '0x' + 'cd'.repeat(32),
    getJwt: async () => 'unused-offline',
    address: addr,
    signDigest: localSignDigest,
  })

  let pass = 0
  const fails: string[] = []
  const ok = (name: string, cond: boolean): void => {
    if (cond) {
      pass++
      console.log(`  ✓ ${name}`)
    } else fails.push(name)
  }

  ok('getAddress() returns the threshold EOA address', (await signer.getAddress()) === addr)

  const msg = 'hello from a Tasra threshold EOA'
  ok('signMessage → verifyMessage recovers the address', verifyMessage(msg, await signer.signMessage(msg)) === addr)

  const domain: TypedDataDomain = {name: 'Demo', version: '1', chainId: 1, verifyingContract: '0x' + '11'.repeat(20)}
  const types = {Mail: [{name: 'note', type: 'string'}]}
  const value = {note: 'gm'}
  ok(
    'signTypedData → verifyTypedData recovers the address',
    verifyTypedData(domain, types, value, await signer.signTypedData(domain, types, value)) === addr,
  )

  const t = Transaction.from({
    to: '0x' + '22'.repeat(20),
    value: 10n ** 18n,
    nonce: 7,
    gasLimit: 21000,
    maxFeePerGas: 10n ** 9n,
    maxPriorityFeePerGas: 10n ** 9n,
    chainId: 1,
    type: 2,
  })
  t.signature = await signer.ethSignature(getBytes(t.unsignedHash))
  ok('signed EIP-1559 tx recovers the sender', Transaction.from(t.serialized).from === addr)

  if (fails.length > 0) {
    console.error(`\n✗ ethers-signer self-test: ${fails.length} failed:`)
    for (const f of fails) console.error('   - ' + f)
    process.exit(1)
  }
  console.log(`\n✓ ethers-signer self-test: ${pass} checks passed (offline, local-key stand-in)`)
}

// Surface a failure as a non-zero exit rather than an unhandled rejection.
selfTest().catch((error: unknown) => {
  console.error(error)
  process.exitCode = 1
})
