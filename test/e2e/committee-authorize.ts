// Real wallet quorum grants with anchored membership proofs; live decrypt and
// rejection of a token with fewer signatures than the required quorum.
import {Suite,bytesEq} from '../fleet/_assert.ts'
import {gate,loadFleetConfig} from '../fleet/_fleet.ts'
import {authorizeWallet,createWalletSlot} from '../fleet/_wallet.ts'
import {decryptPayloadDigest} from '../../src/oid4vp/index.ts'
import {encryptEnvelope} from '../../src/crypto/envelope.ts'
import {hexToBytes} from '../../src/crypto/hex.ts'

const cfg=loadFleetConfig(),s=new Suite('e2e: wallet committee quorum authorization')
if (!(await gate(s,cfg))) { s.done(); process.exit(1) }
const slot=await createWalletSlot(cfg,'bls')
const identity='committee-wallet-cert',plaintext=new TextEncoder().encode('quorum-authorized ciphertext')
const env=encryptEnvelope(hexToBytes(slot.slotId),hexToBytes(slot.publicKey),new TextEncoder().encode(identity),plaintext,0n)
const grant=await authorizeWallet(cfg,slot.slotId,slot.creatorKey,{action:'decrypt',payloadDigest:decryptPayloadDigest(env.ciphertext.u,env.ciphertext.aeadCt)})
s.ok('grant includes a verifier quorum and anchored membership proofs',grant.compound_token.signatures.length>=2 && grant.verifier_proofs.length>=2)
const peers=[]
for (const url of slot.committee) {
  const response=await fetch(`${url}/v1/info`)
  const info=await response.json() as {node_identifier:number;peer_id:string}
  peers.push({id:info.node_identifier,peer_id:info.peer_id})
}
const b64=(value:Uint8Array)=>Buffer.from(value).toString('base64')
const body={committee_token:grant.compound_token,verifier_proofs:grant.verifier_proofs,
  ciphertext:{u:b64(env.ciphertext.u),nonce:b64(env.ciphertext.nonce),aead_ct:b64(env.ciphertext.aeadCt)},identity,
  decrypting_set:peers.map(p=>p.id).sort((a,b)=>a-b),bls_peers:peers}
const post=(value:unknown)=>fetch(`${slot.committee[0]}/v1/committee/decrypt`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(value),signal:AbortSignal.timeout(30000)})
const denied=await post({...body,committee_token:{...grant.compound_token,signatures:grant.compound_token.signatures.slice(0,1)}})
const reason=await denied.text()
s.ok('sub-quorum token denied for its missing quorum',denied.status===403 && /quorum|signature/i.test(reason),reason)
const response=await post(body)
const result=await response.json() as {plaintext?:string;plaintext_b64?:string}
s.eq('full quorum accepted by the keeper',response.status,200)
s.ok('threshold decrypt recovered the exact plaintext',bytesEq(Buffer.from(result.plaintext ?? result.plaintext_b64 ?? '','base64'),plaintext))
s.done()
