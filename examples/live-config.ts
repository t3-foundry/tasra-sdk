// Node example utilities, not part of the SDK's public API.
import {readFileSync} from 'node:fs'
import {ed25519DidKey, hexToBytes, type HolderSigner} from 'tasra-sdk'
import {
  addressBookFromManifest, createTasraChainClient, parsePinnedNetworkManifest,
  observeNetworkManifest, resolveSlotKeeperUrls, nodeApi,
  createCommitteeSlotClient, type TasraChainClient,
} from 'tasra-sdk/chain'
import {ed25519ClientSigner, holderProofPerVerifier} from 'tasra-sdk/committee'

export function required(name: string, env: NodeJS.ProcessEnv = process.env): string {
  const value = env[name]?.trim()
  if (!value) throw new Error(`Missing ${name}. See docs/prerequisites.md and https://github.com/t3-foundry/tasra-releases for Fuji deployment records.`)
  return value
}

export function slotId(name = 'KK_SLOT_ID'): `0x${string}` {
  const value = required(name)
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${name} must be a 0x-prefixed bytes32`)
  return value as `0x${string}`
}

export async function loadNetwork() {
  const digest = required('KK_MANIFEST_SHA256')
  const manifest = parsePinnedNetworkManifest(readFileSync(required('KK_MANIFEST_FILE'), 'utf8'), digest)
  const addresses = addressBookFromManifest(manifest)
  const rpcUrl = required('KK_RPC_URL')
  const observation = await observeNetworkManifest(manifest, rpcUrl)
  if (!observation.matches) throw new Error('Deployment code does not match the pinned manifest')
  return {manifest, digest, rpcUrl, addresses,
    chain: createTasraChainClient({rpcUrl, addresses, chainId: manifest.chainId})}
}

export function loadHolder(prefix = 'KK') {
  const secretKey = hexToBytes(readFileSync(required(`${prefix}_HOLDER_KEY_FILE`), 'utf8').trim())
  try {
    if (secretKey.length !== 32) throw new Error('Holder key must contain exactly 32 bytes of hex')
    const credentials: unknown = JSON.parse(readFileSync(required(`${prefix}_CREDENTIALS_FILE`), 'utf8'))
    if (!Array.isArray(credentials) || !credentials.length || !credentials.every(v => typeof v === 'string' && v.length > 0)) {
      throw new Error('Credentials file must be a nonempty JSON array of compact-JWS credentials')
    }
    const holder = ed25519DidKey(ed25519ClientSigner(secretKey).publicKey)
    const signer: HolderSigner = {alg: 'EdDSA', did: holder, secretKey}
    return {holder, signer, secretKey, credentials: credentials as string[]}
  } catch (error) {
    secretKey.fill(0)
    throw error
  }
}

export function committeeClient(chain: TasraChainClient, slot: string, identity: ReturnType<typeof loadHolder>, action: 'sign' | 'decrypt') {
  return createCommitteeSlotClient({chain, holder: identity.holder, credentials: identity.credentials,
    clientSigner: ed25519ClientSigner(identity.secretKey),
    holderProof: holderProofPerVerifier({signer: identity.signer, credentials: identity.credentials,
      audience: required('KK_VERIFIER_AUDIENCE'), slotId: slot, action}),
  })
}

export async function decryptPeers(chain: TasraChainClient, slot: `0x${string}`) {
  const urls = await resolveSlotKeeperUrls(chain, slot)
  if (!urls.length) throw new Error('Slot has no assigned keeper endpoints')
  const peers = await Promise.all(urls.map(async url => {
    const info = await nodeApi.info(url)
    if (!Number.isSafeInteger(info.node_identifier) || Number(info.node_identifier) <= 0 || !info.peer_id) {
      throw new Error('Keeper did not publish its BLS identifier and peer ID')
    }
    return {id: info.node_identifier!, peerId: info.peer_id}
  }))
  if (new Set(peers.map(p => p.id)).size !== peers.length) throw new Error('Duplicate BLS identifiers')
  return peers.sort((a, b) => a.id - b.id)
}
