# Sign Ethereum transactions (ethers / viem / Hardhat)

> Threshold ECDSA for EVM accounts, wired into ethers, viem and Hardhat.

For an EVM project, a **threshold-ECDSA (tECDSA) slot** *is* an Ethereum account
whose key is split across the fleet — every signature needs k-of-n nodes and no
machine ever holds the whole key. `signEoaDigest` signs a 32-byte prehash and
returns Ethereum `{r, s, yParity}`; `addressFromEoaPubkey` derives the EOA's
EIP-55 address from its secp256k1 group key (using only `@noble`):

```ts
import {signEoaDigest, ethSignatureV, addressFromEoaPubkey} from 'tasra-sdk'

const {groupPublicKey, r, s, yParity} = await signEoaDigest({nodeUrl, jwt, slotId, digest})
const from = addressFromEoaPubkey(groupPublicKey)   // 0x… checksummed address
const v    = ethSignatureV(yParity, chainId)        // EIP-155 v
```

Wrap that in an **ethers v6 `Signer`** and it drops into ethers or Hardhat like any
key-backed account. `examples/ethers-signer.ts` (shipped with the package) is a complete, copy-paste
`TasraSigner extends AbstractSigner` (getAddress + signTransaction / signMessage /
signTypedData), with the JWT supplied by your `getJwt` callback:

```ts
import {redeemRenewalToken} from 'tasra-sdk'
import {TasraSigner} from './tasra-signer'   // copied from the package's examples/ethers-signer.ts

const signer = new TasraSigner({
  nodes, slotId,                                     // a tECDSA signing slot
  getJwt: async () => (await redeemRenewalToken(verifier, renewalToken)).token,
}).connect(provider)

await signer.getAddress()
await signer.sendTransaction({to, value})            // signed by the fleet, broadcast via the provider

// Hardhat: const c = await ethers.getContractAt(abi, addr, signer.connect(ethers.provider))
//          await c.transfer(to, amount)
```

Prefer **viem** (and thus wagmi, or an ERC-4337 stack)? `examples/viem-account.ts`
(shipped with the package) is the same adapter as a viem `LocalAccount` via `toAccount`. viem is
an optional peer of tasra-sdk, so install it alongside:

```ts
import {createWalletClient, http} from 'viem'
import {redeemRenewalToken} from 'tasra-sdk'
import {createTasraAccount} from './tasra-account'   // copied from the package's examples/viem-account.ts

const account = await createTasraAccount({
  nodes, slotId,                                     // a tECDSA signing slot
  getJwt: async () => (await redeemRenewalToken(verifier, renewalToken)).token,
})
const wallet = createWalletClient({account, chain, transport: http(rpcUrl)})
await wallet.sendTransaction({to, value})            // signed by the fleet
```

Both are just adapters — the SDK's shipped surface stays signer-lib-agnostic (the
address helper uses only `@noble`; `ethers` is a dev-only dependency for that example,
while viem is already a dependency). **Note:** the node's `/v1/sign/eoa-digest` path
may be feature-gated in your deployment; each example's offline self-test
(`npm run example:ethers` / `npm run example:viem`) proves the signature assembly
end-to-end with a local stand-in key.

---

[← Back to the README](../README.md) · [Documentation index](README.md)
