// Renewal issuance is retired. Exercise expiration, fresh presentation, and
// closed renewal/raw-export surfaces on the production wallet runtime.
import assert from 'node:assert/strict'
import {randomBytes} from 'node:crypto'
import {Suite} from '../fleet/_assert.ts'
import {gate,loadFleetConfig,mintLocalJwt} from '../fleet/_fleet.ts'
import {authorizeWallet,createWalletSlot,issueWallet} from '../fleet/_wallet.ts'
import {VerifierAgentSessionError} from '../../src/oid4vp/index.ts'
import {committeeSign} from '../../src/committee/client.ts'

const cfg=loadFleetConfig(),s=new Suite('e2e: expired credential lockout and fresh wallet presentation')
if (!(await gate(s,cfg))) { s.done(); process.exit(1) }
const slot=await createWalletSlot(cfg),message=randomBytes(32)
await assert.rejects(()=>authorizeWallet(cfg,slot.slotId,slot.creatorKey,{action:'sign',message},issueWallet(cfg,{ttlSecs:-120}),true),
  error=>error instanceof VerifierAgentSessionError && error.kind==='refused')
s.ok('expired issuer-signed credential rejected by the verifiers',true)
const grant=await authorizeWallet(cfg,slot.slotId,slot.creatorKey,{action:'sign',message})
await committeeSign({nodeUrl:slot.committee[0]!,committeeToken:grant.compound_token,verifierProofs:grant.verifierProofs,message})
s.ok('fresh credential presentation restores the operation',true)
for (const path of ['renewals','renewals/redeem','renewals/revoke']) {
  const response=await fetch(`${cfg.verifierUrls[0]}/v1/${path}`,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
  s.eq(`retired ${path} route remains absent`,response.status,404)
}
const exported=await fetch(`${slot.committee[0]}/v1/shards/key`,{method:'POST',headers:{'Content-Type':'application/json',Authorization:`Bearer ${mintLocalJwt(cfg)}`},body:JSON.stringify({key_slot_id:slot.slotId})})
s.eq('administrative JWT cannot export user key material',exported.status,403)
s.done()
