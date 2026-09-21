// Sign Ethereum transactions with a Tasra threshold-ECDSA (tECDSA) slot,
// via a viem Account — drop it into a viem Wallet Client (and thus wagmi, or an
// ERC-4337 stack that accepts a viem account) like any other account.
//
//   npx tsx examples/viem-account.ts      # runs the offline self-test below
//
// Install the optional peer with npm install tasra-sdk viem for this adapter. In YOUR project import the SDK bits from
// 'tasra-sdk' (this in-repo example imports from 'tasra-sdk'). The private key
// never exists anywhere: each signature is produced by the k-of-n keykeeper-node
// fleet via signEoaDigest(); this account just turns viem's message/typed-data/
// transaction hashes into that 32-byte digest call and serializes the result.
//
// NOTE: the node's /v1/sign/eoa-digest path may be feature-gated in your
// deployment. The offline self-test substitutes a LOCAL secp256k1 key for the
// fleet to prove the assembly end-to-end without a live backend.
//
// ── Usage (viem) ──────────────────────────────────────────────────────────────
//   import {createWalletClient, http} from 'viem'
//   import {redeemRenewalToken} from 'tasra-sdk'
//   const account = await createTasraAccount({
//     nodes, slotId,                                  // a tECDSA signing slot
//     getJwt: async () => (await redeemRenewalToken(verifier, renewalToken)).token,
//   })
//   const wallet = createWalletClient({account, chain, transport: http(rpcUrl)})
//   await wallet.sendTransaction({to, value})         // signed by the fleet
//   // wagmi: pass `account` to a custom connector. ERC-4337: use it as the owner.

import {
  hashMessage,
  hashTypedData,
  keccak256,
  serializeTransaction,
  serializeSignature,
  hexToBytes,
  toHex,
  type Hex,
  type SignableMessage,
  type TypedDataDefinition,
  type TransactionSerializable,
  type LocalAccount,
} from 'viem'
import {toAccount} from 'viem/accounts'
import {secp256k1} from '@noble/curves/secp256k1'
import {signEoaDigest, addressFromEoaPubkey, fetchMpk} from 'tasra-sdk'

/** Raw Ethereum ECDSA components as returned by the threshold network. */
export interface RawEcdsaSig {
  r: Uint8Array // 32-byte big-endian
  s: Uint8Array // 32-byte big-endian (low-s)
  yParity: number // 0 | 1
}

export interface TasraAccountConfig {
  /** k-of-n keykeeper-node base URLs. */
  nodes: string[]
  /** 0x-prefixed bytes32 tECDSA slot id. */
  slotId: string
  /** Supply a fresh DCQL-gated JWT (e.g. via redeemRenewalToken / redeemCredential). */
  getJwt: () => Promise<string>
  /** The EOA address, if already known — skips the group-key fetch. */
  address?: Hex
  /** Override the digest signer (used by the offline self-test); defaults to signEoaDigest. */
  signDigest?: (digest: Uint8Array) => Promise<RawEcdsaSig>
}

/**
 * Build a viem `LocalAccount` whose signing is delegated to a Tasra tECDSA
 * slot. Async because the address is derived from the slot's secp256k1 group key
 * (unless you pass `address`), and viem needs the address up front.
 */
export async function createTasraAccount(cfg: TasraAccountConfig): Promise<LocalAccount> {
  const signDigest =
    cfg.signDigest ??
    (async (digest: Uint8Array): Promise<RawEcdsaSig> => {
      const sig = await signEoaDigest({
        nodeUrl: cfg.nodes[0]!,
        jwt: await cfg.getJwt(),
        slotId: cfg.slotId,
        digest,
      })
      return {r: sig.r, s: sig.s, yParity: sig.yParity}
    })

  // Assumes /v1/keys/{slot}/public serves the secp256k1 key for a tECDSA slot;
  // pass `address` in the config to skip this.
  const address =
    cfg.address ?? (addressFromEoaPubkey((await fetchMpk(cfg.nodes[0]!, cfg.slotId)).mpkBytes) as Hex)

  // hash (Hex) → threshold sign → 65-byte serialized signature (Hex)
  const signHash = async (hash: Hex): Promise<Hex> => {
    const {r, s, yParity} = await signDigest(hexToBytes(hash))
    return serializeSignature({r: toHex(r), s: toHex(s), yParity})
  }

  // The method parameters below are deliberately left un-annotated: viem's
  // `CustomSource` types `signTypedData`/`signTransaction` as generics, and
  // contextual typing from `toAccount` matches them exactly. Annotating them
  // with the concrete types instead makes the object structurally incompatible,
  // and `toAccount` then resolves to its JsonRpcAccount overload.
  return toAccount({
    address,
    async sign({hash}: {hash: Hex}) {
      return signHash(hash)
    },
    async signMessage({message}: {message: SignableMessage}) {
      return signHash(hashMessage(message))
    },
    async signTypedData(typedData) {
      return signHash(hashTypedData(typedData as TypedDataDefinition))
    },
    async signTransaction(transaction, options) {
      // One cast at the boundary: viem's generic serializer is declared to return
      // MaybePromise<Hex>, but every concrete serializer (including viem's own
      // `serializeTransaction`) is synchronous.
      const serialize = (options?.serializer ?? serializeTransaction) as (
        tx: TransactionSerializable,
        sig?: {r: Hex; s: Hex; yParity: number},
      ) => Hex
      const tx = transaction as TransactionSerializable
      const unsigned = serialize(tx)
      const {r, s, yParity} = await signDigest(hexToBytes(keccak256(unsigned)))
      return serialize(tx, {r: toHex(r), s: toHex(s), yParity})
    },
  })
}

// ── Offline self-test: a LOCAL secp256k1 key stands in for the threshold fleet ──
// Proves the account assembles signatures that viem recovers back to the right
// address — for messages, EIP-712 typed data, and an EIP-1559 transaction.

async function selfTest(): Promise<void> {
  const {recoverMessageAddress, recoverTypedDataAddress, recoverTransactionAddress} = await import('viem')

  const priv = hexToBytes('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d')
  const pub = secp256k1.getPublicKey(priv, true)
  const addr = addressFromEoaPubkey(pub) as Hex

  const localSignDigest = async (digest: Uint8Array): Promise<RawEcdsaSig> => {
    const sig = secp256k1.sign(digest, priv) // low-s by default; carries .recovery
    const compact = sig.toCompactRawBytes() // r‖s, 64 bytes
    return {r: compact.slice(0, 32), s: compact.slice(32, 64), yParity: sig.recovery!}
  }

  const account = await createTasraAccount({
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
  const eq = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase()

  ok('account.address is the threshold EOA address', eq(account.address, addr))

  const message = 'hello from a Tasra viem account'
  const msgSig = await account.signMessage!({message})
  ok('signMessage → recoverMessageAddress', eq(await recoverMessageAddress({message, signature: msgSig}), addr))

  const typedData = {
    domain: {name: 'Demo', version: '1', chainId: 1, verifyingContract: ('0x' + '11'.repeat(20)) as Hex},
    types: {Mail: [{name: 'note', type: 'string'}]},
    primaryType: 'Mail' as const,
    message: {note: 'gm'},
  }
  const tdSig = await account.signTypedData!(typedData)
  ok('signTypedData → recoverTypedDataAddress', eq(await recoverTypedDataAddress({...typedData, signature: tdSig}), addr))

  const tx: TransactionSerializable = {
    to: ('0x' + '22'.repeat(20)) as Hex,
    value: 10n ** 18n,
    nonce: 7,
    gas: 21000n,
    maxFeePerGas: 10n ** 9n,
    maxPriorityFeePerGas: 10n ** 9n,
    chainId: 1,
    type: 'eip1559',
  }
  // `type: 'eip1559'` above pins the envelope, so the serialized form is 0x02-prefixed.
  const serialized = (await account.signTransaction!(tx)) as `0x02${string}`
  ok('signed EIP-1559 tx → recoverTransactionAddress', eq(await recoverTransactionAddress({serializedTransaction: serialized}), addr))

  if (fails.length > 0) {
    console.error(`\n✗ viem-account self-test: ${fails.length} failed:`)
    for (const f of fails) console.error('   - ' + f)
    process.exit(1)
  }
  console.log(`\n✓ viem-account self-test: ${pass} checks passed (offline, local-key stand-in)`)
}

// Surface a failure as a non-zero exit rather than an unhandled rejection.
selfTest().catch((error: unknown) => {
  console.error(error)
  process.exitCode = 1
})
