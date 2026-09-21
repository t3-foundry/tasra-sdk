// Real production wallet authorization shared by the live suites.
import assert from 'node:assert/strict'
import {randomBytes} from 'node:crypto'
import {privateKeyToAccount} from 'viem/accounts'
import {parseEther, type Hex} from 'viem'
import {createTasraWriteClient, generateClientKey} from '../../src/chain/write.ts'
import {
  awaitVerifierAgentResult, buildResponse, ed25519HolderKey, fetchRequestObject,
  issueSdJwtVc, openVerifierAgentSession, parseSdJwt, planPresentation,
  sdJwtCredentialView, submitResponse, type OperationInput,
} from '../../src/oid4vp/index.ts'
import {discoverCommittee, mintLocalJwt, provisionRule, type FleetConfig} from './_fleet.ts'

export const WALLET_RULE = JSON.stringify({credentials:[{claims:[{path:['iss'],values:['did:web:hr.acmecorp.example']},{path:['dept'],values:['Engineering']}],format:'dc+sd-jwt',id:'employee',meta:{vct_values:['EmployeeOf']}}]})

export function issueWallet(cfg: FleetConfig, opts: {dept?: string; issuer?: string; ttlSecs?: number; issuerKey?: string; vct?: string; claims?: Record<string, unknown>} = {}) {
  const holder = ed25519HolderKey(randomBytes(32))
  const sdJwt = issueSdJwtVc({
    issuer:{did:opts.issuer ?? cfg.issuerDid, signer:{alg:'EdDSA',privateKey:Buffer.from(opts.issuerKey ?? cfg.issuerKey,'base64url')}},
    vct:opts.vct ?? 'EmployeeOf', claims:opts.claims ?? {dept:opts.dept ?? 'Engineering'}, cnf:{jwk:holder.publicJwk},
    sub:holder.did, ttlSecs:opts.ttlSecs ?? 3600,
  })
  return {holder, sdJwt}
}

export async function authorizeWallet(cfg: FleetConfig, slot: Hex, creatorKey: Hex,
  input: Pick<OperationInput,'action'|'message'|'payloadDigest'|'identity'|'ttlSecs'>,
  wallet = issueWallet(cfg), forcePresentation = false) {
  const url = process.env.KK_VERIFIER_AGENT_URL ?? process.env.KK_VERIFIER_AGENT_EXTERNAL_URL
  assert(url, 'KK_VERIFIER_AGENT_URL must name the deployed HTTPS verifier-agent')
  assert(cfg.book.KeyRegistry)
  const deadline = Date.now()+45000
  let session
  for (;;) {
    try {
      session = await openVerifierAgentSession({
        ...input, verifierAgentUrl:url, signer:privateKeyToAccount(creatorKey), chainId:cfg.chainId,
        keyRegistry:cfg.book.KeyRegistry, slotId:slot, description:'Local test operation',
      })
      break
    } catch(error) {
      if (!String(error).includes('no anchored verifier snapshot') || Date.now() >= deadline) throw error
      await new Promise(resolve => setTimeout(resolve,3000))
    }
  }
  const ro = await fetchRequestObject(session.requestUri)
  assert.equal(new URL(ro.claims.response_uri).origin, new URL(url).origin, 'response must stay on the approved agent origin')
  const plan = planPresentation(ro,[{sdJwt:wallet.sdJwt}])
  const parsed = parseSdJwt(wallet.sdJwt)
  const candidate = forcePresentation ? {held:{sdJwt:wallet.sdJwt},parsed,view:sdJwtCredentialView(parsed),queryId:ro.claims.dcql_query.credentials[0]!.id} : plan.chosen
  assert(candidate, 'held credential does not answer the wallet request')
  const built = buildResponse({ro,candidate,holder:wallet.holder,disclose:'all'})
  assert(built.form.response, 'presentation must use encrypted direct_post.jwt')
  await submitResponse(ro,built)
  const result = await awaitVerifierAgentResult(session,{intervalMs:1000,timeoutMs:120000})
  assert.equal(result.token.binding,'holder_key')
  assert(result.verifierProofs?.length)
  return {compound_token:result.token,verifierProofs:result.verifierProofs,verifier_proofs:result.verifierProofs.map(p => ({verifier_index:p.verifierIndex,operator:p.operator,pubkey:p.pubkey,proof:p.proof}))}
}

export async function createWalletSlot(cfg: FleetConfig, mode: 'frost'|'bls' = 'frost', k = 2, n = 3, rule = WALLET_RULE) {
  const creatorKey = generateClientKey()
  const writer = createTasraWriteClient({rpcUrl:cfg.rpcUrl,addresses:cfg.book,privateKey:creatorKey,chainId:cfg.chainId})
  const funder = createTasraWriteClient({rpcUrl:cfg.rpcUrl,addresses:cfg.book,privateKey:cfg.deployPk as Hex,chainId:cfg.chainId})
  await funder.sendEth(writer.address,parseEther('1'))
  const {slotId,ruleSalt} = await writer.createSlotCommitReveal({dcqlRule:rule,k,n,mode,tags:['keykeeper'],maxWaitMs:180000})
  const deadline = Date.now()+240000
  for (;;) {
    const committee = await discoverCommittee(cfg,slotId)
    if (committee.length === n) {
      const response = await fetch(`${committee[0]}/v1/keys/${slotId}/public`)
      assert.equal(response.status,200)
      const pub = await response.json() as {group_public_key?:string}
      if (pub.group_public_key) {
        const provisioned = await provisionRule(committee,slotId,rule,ruleSalt,mintLocalJwt(cfg))
        assert(provisioned.ok,provisioned.errors.join('; '))
        return {slotId,ruleSalt,committee,publicKey:pub.group_public_key,creatorKey,writer}
      }
    }
    assert(Date.now()<deadline,'slot DKG did not complete')
    await new Promise(resolve=>setTimeout(resolve,2000))
  }
}
