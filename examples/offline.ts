import {encryptEnvelope, decryptWithMasterKey, hexToBytes} from 'tasra-sdk'

/** Public, fixed DEMO keys. Never encrypt a real secret with these. */
export function offlineRoundTrip(): string {
  const msk = new Uint8Array(32)
  msk[0] = 1
  const mpk = hexToBytes('93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8')
  const identity = new TextEncoder().encode('demo')
  try {
    const envelope = encryptEnvelope(new Uint8Array(32), mpk, identity,
      new TextEncoder().encode('Hello Tasra'), 0n)
    return new TextDecoder().decode(decryptWithMasterKey(msk, envelope.ciphertext, identity))
  } finally {
    msk.fill(0)
  }
}
