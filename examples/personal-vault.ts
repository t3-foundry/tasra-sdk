// Only for a BLS slot created with exportable: true. Export is permanent:
// revoking authorization cannot revoke a master key already held by a client.
import {createTasraSlotClient} from 'tasra-sdk/chain'
import {loadHolder, loadNetwork, required, slotId} from './live-config.ts'

const network = await loadNetwork()
const identity = loadHolder()
const client = createTasraSlotClient({chain: network.chain, identity: identity.holder})
try {
  const session = await client.openSession(slotId(), {vpJwt: {
    dcqlRule: required('KK_DCQL_RULE'), credentials: identity.credentials,
    holderProof: {signer: identity.signer, audience: required('KK_VERIFIER_AUDIENCE')},
  }})
  const result = await session.decrypt(session.encrypt(new TextEncoder().encode('Personal vault demo')))
  if (new TextDecoder().decode(result) !== 'Personal vault demo') throw new Error('Vault round trip failed')
  console.log('Exportable vault round trip succeeded.')
} finally {
  await client.closeAll()
  identity.secretKey.fill(0)
}
