// Write-client signer shapes + the rule commitment.
//
// Offline: `createTasraWriteClient` performs no RPC at construction time, so
// every check here runs without a chain.
//
// Two things are being protected:
//   1. `ruleCommitment` is a CROSS-LANGUAGE contract with the reference implementation's
//      the reference rule-commitment function. If it drifts, every keeper rejects
//      every rule and slots fail closed — with no signal from this package. The
//      KAT below is the same vector carried in the function's doc comment.
//   2. The BYO-signer (`wallet`) path is what makes browser wallets possible.
//      It must resolve the account from the supplied client and must NOT
//      monkey-patch that client, because it belongs to the caller.
//
// Run: tsx test/chain.write-signer.ts — exits non-zero on any failure.

import {concat, createWalletClient, defineChain, http, keccak256, toHex} from 'viem'
import {privateKeyToAccount} from 'viem/accounts'
import type {Hex} from 'viem'
import {createTasraWriteClient, ruleCommitment, verifyRuleCommitment} from '../src/chain/write.ts'
import * as barrel from '../src/chain/index.ts'
import {addressBookFromObject} from '../src/chain/deployments.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean) {
  if (cond) passed++
  else failures.push(name)
}
function throws(name: string, fn: () => unknown, match: RegExp) {
  try {
    fn()
    failures.push(`${name} (expected a throw, got none)`)
  } catch (e) {
    const msg = String((e as {message?: string})?.message ?? e)
    ok(name, match.test(msg))
    if (!match.test(msg)) failures[failures.length - 1] = `${name} (wrong message: ${msg})`
  }
}

// ---------------------------------------------------------------- KAT

{
  const salt = `0x${'11'.repeat(32)}` as Hex
  const rule = JSON.stringify({credentials:[{id:'c1',format:'jwt_vc_json',claims:[{path:['iss'],values:['did:web:hr.acmecorp']},{path:['dept'],values:['Engineering']}]}]})
  const want = '0x91f1bb4fb0352c35247431eb122da9b1b91ca8e85e36eb11f5139864e9ac01af'
  ok('ruleCommitment matches the cross-language the reference implementation KAT', ruleCommitment(salt, rule) === want)

  const otherSalt = `0x${'22'.repeat(32)}` as Hex
  ok('commitment is salt-sensitive', ruleCommitment(otherSalt, rule) !== ruleCommitment(salt, rule))

  // Key-order change must NOT move the commitment (JCS canonicalises).
  const reordered = JSON.stringify({credentials:[{id:'c1',claims:[{path:['iss'],values:['did:web:hr.acmecorp']},{path:['dept'],values:['Engineering']}],format:'jwt_vc_json'}]})
  ok('commitment is key-order-insensitive (JCS)', ruleCommitment(salt, reordered) === ruleCommitment(salt, rule))
  ok('commitment is 32 bytes', ruleCommitment(salt, rule).length === 66)

  ok('ruleCommitment is exported from the chain barrel', barrel.ruleCommitment === ruleCommitment)

  // The keeper's dispatch (the reference implementation `rule_commitment`): ONLY an OID4VP-DCQL rule commits to its
  // canonical bytes. The bearer-JWT kk-DCQL grammar and "any" commit to their RAW bytes, so
  // for them key order DOES move the commitment — exactly as it does on the keeper.
  const raw = (r: string) => keccak256(concat([toHex('keykeeper/rule-commitment/v1'), salt, toHex(r)]))
  const kk = JSON.stringify({credentials:[{id:'c0',format:'jwt',claims:[{path:['sub'],values:['did:jwk:abc']}]}]})
  const kkReordered = JSON.stringify({credentials:[{claims:[{path:['sub'],values:['did:jwk:abc']}],format:'jwt',id:'c0'}]})
  ok('a kk-DCQL (bearer-JWT) rule commits to its raw bytes', ruleCommitment(salt, kk) === raw(kk))
  ok('a kk-DCQL rule is key-order-sensitive (no canonicalisation off the OID4VP path)',
    ruleCommitment(salt, kkReordered) === raw(kkReordered) && ruleCommitment(salt, kkReordered) !== ruleCommitment(salt, kk))
  ok('the universal grant "any" commits to its raw bytes', ruleCommitment(salt, 'any') === raw('any'))
}

// ─────────────────────────────────────────────────── verifyRuleCommitment
{
  const salt = `0x${'11'.repeat(32)}` as Hex
  const rule = JSON.stringify({credentials:[{id:'c1',format:'jwt_vc_json',claims:[{path:['iss'],values:['did:web:hr.acmecorp']},{path:['dept'],values:['Engineering']}]}]})
  const hash = ruleCommitment(salt, rule)
  ok('verifyRuleCommitment: matching rule+salt verifies', verifyRuleCommitment(rule, salt, hash))
  ok('verifyRuleCommitment: wrong salt rejects', !verifyRuleCommitment(rule, `0x${'22'.repeat(32)}` as Hex, hash))
  ok('verifyRuleCommitment: wrong rule rejects', !verifyRuleCommitment('{"credentials":[{"id":"x","format":"jwt_vc_json","claims":[{"path":["iss"]}]}]}', salt, hash))
  ok('verifyRuleCommitment: invalid JSON returns false', !verifyRuleCommitment('not json', salt, hash))
  // ⚠ It must RETURN false, never throw — the whole point is that a caller can check a
  // rule a verifier handed it without wrapping the call. A malformed salt is the input
  // that actually throws inside, so it is the one that proves the guarantee.
  ok('verifyRuleCommitment: a malformed salt returns false rather than throwing',
    !verifyRuleCommitment(rule, 'not-a-hex-salt' as Hex, hash))
  ok('verifyRuleCommitment is exported from chain barrel', barrel.verifyRuleCommitment === verifyRuleCommitment)
}

// ------------------------------------------------------------ signer selection

const addresses = addressBookFromObject({KeyRegistry: '0x0000000000000000000000000000000000000001'})
const rpcUrl = 'http://127.0.0.1:8545'
const pk = `0x${'42'.repeat(32)}` as Hex
const account = privateKeyToAccount(pk)
const chain = defineChain({
  id: 1337,
  name: 'test',
  nativeCurrency: {name: 'Ether', symbol: 'ETH', decimals: 18},
  rpcUrls: {default: {http: [rpcUrl]}},
})

{
  // Local-key path: unchanged behaviour.
  const c = createTasraWriteClient({rpcUrl, addresses, privateKey: pk, chainId: 1337})
  ok('privateKey path derives the account address', c.address === account.address)
}

{
  // BYO-signer path: the account comes from the supplied client.
  const wallet = createWalletClient({account, chain, transport: http(rpcUrl)})
  const originalWrite = wallet.writeContract
  const originalSend = wallet.sendTransaction

  const c = createTasraWriteClient({rpcUrl, addresses, wallet})
  ok('wallet path adopts the supplied account address', c.address === account.address)

  // The nonce-retry wrapper must not be installed on a client we do not own: a
  // silent retry in a browser is a SECOND signature prompt for one user action.
  ok('supplied wallet.writeContract is not monkey-patched', wallet.writeContract === originalWrite)
  ok('supplied wallet.sendTransaction is not monkey-patched', wallet.sendTransaction === originalSend)
}

{
  // A wallet with no bound account cannot sign; fail loudly at construction rather
  // than at the first write, which in a UI would be several screens later.
  const unbound = createWalletClient({chain, transport: http(rpcUrl)})
  throws(
    'unbound wallet is rejected with a directive message',
    () => createTasraWriteClient({rpcUrl, addresses, wallet: unbound as never}),
    /no account bound/i,
  )
  throws(
    'neither privateKey nor wallet is rejected',
    () => createTasraWriteClient({rpcUrl, addresses} as never),
    /either `privateKey` or `wallet`/i,
  )
}

{
  // The chain id is in every signature. The demo default (1337) is only ever
  // right for a fleet on this machine, so it is only assumed for a loopback RPC;
  // anywhere else the caller must say which chain they are writing to.
  const remoteRpc = 'https://api.avax-test.network/ext/bc/C/rpc'
  throws(
    'non-loopback RPC without chainId is refused with a directive message',
    () => createTasraWriteClient({rpcUrl: remoteRpc, addresses, privateKey: pk}),
    /chainId is required/,
  )
  const remote = createTasraWriteClient({rpcUrl: remoteRpc, addresses, privateKey: pk, chainId: 43113})
  ok('non-loopback RPC with an explicit chainId is accepted', remote.address === account.address)

  for (const url of ['http://localhost:8545', 'http://127.0.0.1:8545', 'http://[::1]:8545', 'http://besu.localhost:8545']) {
    let built = false
    try {
      createTasraWriteClient({rpcUrl: url, addresses, privateKey: pk})
      built = true
    } catch {
      /* counted below */
    }
    ok(`loopback RPC ${url} keeps the demo default`, built)
  }

  // A chain-bound wallet already knows its chain; that is enough.
  const bound = createWalletClient({account, chain, transport: http(remoteRpc)})
  let viaWallet = false
  try {
    createTasraWriteClient({rpcUrl: remoteRpc, addresses, wallet: bound})
    viaWallet = true
  } catch {
    /* counted below */
  }
  ok('a chain-bound wallet supplies the chain id for a non-loopback RPC', viaWallet)
}

if (failures.length) {
  console.error(`chain.write-signer: ${failures.length} FAILED`)
  for (const f of failures) console.error(`  ✗ ${f}`)
  process.exit(1)
}
console.log(`chain.write-signer: ${passed} checks passed`)
