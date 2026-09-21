// Signing uses a separate, provisioned FROST slot, not the BLS encryption slot.
import {verifyFrostSignature} from 'tasra-sdk'
import {committeeClient, loadHolder, loadNetwork, slotId} from './live-config.ts'

const network = await loadNetwork()
const slot = slotId('KK_SIGN_SLOT_ID')
const identity = loadHolder()
try {
  const client = committeeClient(network.chain, slot, identity, 'sign')
  const message = new TextEncoder().encode('Hello Tasra')
  const result = await client.sign(slot, message)
  if (!verifyFrostSignature(result.groupPublicKey, message, result.signature)) throw new Error('Invalid FROST signature')
  console.log('Threshold signature verified.')
} finally {
  identity.secretKey.fill(0)
}
