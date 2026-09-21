import {afterEach, expect, test, vi} from 'vitest'
import {assertCompoundTokenWire, pollOid4vpSession} from '../../src/verifier-agent/index.js'
import {decodeCompoundToken, type CompoundTokenWire} from '../../src/committee/token.js'
const hash='0x'+'12'.repeat(32)
const token=()=>({token_type:'JWT',seed:hash,slot_id:hash,vp_hash:hash,holder_hash:hash,rule_hash:hash,epoch:1,iat:100,exp:200,identity_hash:null,request_hash:hash,binding:'holder_key',verifier_indexes:[0],signatures:[{verifier_index:0,signature:'0x'+'34'.repeat(64)}]})
afterEach(()=>vi.unstubAllGlobals())
test('verifier-agent signing response with null identity binding survives polling and token decoding',async()=>{
 vi.stubGlobal('fetch',vi.fn().mockResolvedValue(Response.json({status:'done',phase:'done',compound_token:token(),error:null})))
 const response=await pollOid4vpSession('http://127.0.0.1:8390','session','secret')
 expect(response.compoundToken).not.toHaveProperty('identity_hash')
 const decoded=decodeCompoundToken(response.compoundToken as unknown as CompoundTokenWire)
 expect(decoded.identityHash).toBeUndefined();expect(decoded.requestHash).toHaveLength(32)
})
test('normalization preserves IBE binding and rejects malformed optional hashes',()=>{
 expect(assertCompoundTokenWire({...token(),identity_hash:hash},'session').identity_hash).toBe(hash)
 for(const key of ['identity_hash','request_hash'])expect(()=>assertCompoundTokenWire({...token(),[key]:'invalid'},'session')).toThrow('32-byte hex string')
 const normalized=assertCompoundTokenWire({...token(),request_hash:null},'session')
 expect(normalized).not.toHaveProperty('request_hash')
})
