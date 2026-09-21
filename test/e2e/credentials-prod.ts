// Live SD-JWT issuer/claim enforcement through the production wallet protocol.
import assert from 'node:assert/strict'
import {randomBytes} from 'node:crypto'
import {Suite} from '../fleet/_assert.ts'
import {gate,loadFleetConfig} from '../fleet/_fleet.ts'
import {authorizeWallet,createWalletSlot,issueWallet} from '../fleet/_wallet.ts'
import {VerifierAgentSessionError} from '../../src/oid4vp/index.ts'
import {committeeSign} from '../../src/committee/client.ts'
import {frostVerify} from '../fleet/_crypto.ts'

const cfg=loadFleetConfig(), s=new Suite('e2e: production wallet credentials')
if (!(await gate(s,cfg))) { s.done(); process.exit(1) }
const slot=await createWalletSlot(cfg)
const message=randomBytes(32)
const grant=await authorizeWallet(cfg,slot.slotId,slot.creatorKey,{action:'sign',message})
s.eq('wallet earned holder-key-bound authorization',grant.compound_token.binding,'holder_key')
const signed=await committeeSign({nodeUrl:slot.committee[0]!,committeeToken:grant.compound_token,verifierProofs:grant.verifierProofs,message})
s.ok('credential-earned grant produced an independently verified signature',frostVerify(signed.signature.r,signed.signature.z,signed.groupPublicKey,message))
for (const [label,wallet] of [
  ['wrong department',issueWallet(cfg,{dept:'Sales'})],
  ['untrusted issuer',issueWallet(cfg,{issuer:'did:web:evil.example'})],
] as const) {
  // Force the negative presentation onto the wire; local wallet selection is
  // advisory and cannot serve as evidence that the verifiers enforce the rule.
  await assert.rejects(()=>authorizeWallet(cfg,slot.slotId,slot.creatorKey,{action:'sign',message},wallet,true),
    error=>error instanceof VerifierAgentSessionError && error.kind==='refused')
  s.ok(`verifier committee rejected ${label}`,true)
}
s.done()
