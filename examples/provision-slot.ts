// Operator-only setup, separate from the application quick start.
import {randomBytes} from 'node:crypto'
import {readFileSync, writeFileSync} from 'node:fs'
import {fetchMpk} from 'tasra-sdk'
import {createTasraWriteClient, resolveSlotKeeperUrls, type CreateSlotArgs} from 'tasra-sdk/chain'
import {loadNetwork, required} from './live-config.ts'
import {createExampleSlot} from './slot-creation.ts'

const network = await loadNetwork()
const dcqlRule = readFileSync(required('KK_RULE_FILE'), 'utf8').trim()
const output = required('KK_SLOT_OUTPUT')
const adminJwt = required('KK_ADMIN_JWT')
const k = Number(required('KK_K'))
const n = Number(required('KK_N'))
if (!Number.isSafeInteger(k) || !Number.isSafeInteger(n) || k < 1 || n < k || n > 65535) {
  throw new Error('Require integer 1 <= KK_K <= KK_N <= 65535')
}
const mode = required('KK_SLOT_MODE')
if (mode !== 'bls' && mode !== 'frost') throw new Error('KK_SLOT_MODE must be bls or frost')
const custody = required('KK_CUSTODY')
if (custody !== 'threshold' && custody !== 'exportable') throw new Error('KK_CUSTODY must be threshold or exportable')
if (custody === 'exportable' && mode !== 'bls') throw new Error('Exportable example requires a BLS slot')
const requiresCommitReveal = Boolean(await network.chain.readers.keyRegistry.requiresCommitReveal())
if (requiresCommitReveal && custody === 'exportable') throw new Error('Exportable slots are unavailable on this deployment')
const privateKey = readFileSync(required('KK_CREATOR_KEY_FILE'), 'utf8').trim()
if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) throw new Error('Creator key must be 0x-prefixed bytes32')
const writer = createTasraWriteClient({rpcUrl: network.rpcUrl, addresses: network.addresses,
  chainId: network.manifest.chainId, privateKey: privateKey as `0x${string}`})
const random32 = (): `0x${string}` => `0x${randomBytes(32).toString('hex')}`
const args: CreateSlotArgs = {slotId: random32(), salt: random32(), ruleSalt: random32(), dcqlRule,
  k, n, mode, exportable: custody === 'exportable'}
// Persist BEFORE submitting a transaction; never overwrite an existing recovery record.
writeFileSync(output, JSON.stringify({deploymentId: network.manifest.deploymentId, ...args}, null, 2), {flag: 'wx', mode: 0o600})
const created = await createExampleSlot(writer, requiresCommitReveal, args)
console.log(`Created ${mode} slot ${created.slotId}; recovery record: ${output}`)
const deadline = Date.now() + 180_000
let nodes: string[] = []
let ready = false
while (Date.now() < deadline) {
  nodes = await resolveSlotKeeperUrls(network.chain, created.slotId)
  const keys = await Promise.all(nodes.map(url => fetchMpk(url, created.slotId).catch(() => null)))
  if (nodes.length >= k && keys.every(key => key && key.mpkBytes.length > 0)) { ready = true; break }
  await new Promise(resolve => setTimeout(resolve, 2000))
}
if (!ready) throw new Error(`DKG not ready within 180s; preserve ${output} and diagnose before creating another slot`)
await Promise.all(nodes.map(async url => {
  const response = await fetch(`${url.replace(/\/$/, '')}/v1/keys/${created.slotId}/rule`, {
    method: 'POST', headers: {'Content-Type': 'application/json', Authorization: `Bearer ${adminJwt}`},
    body: JSON.stringify({dcql_rule: dcqlRule, dcql_salt: created.ruleSalt}), signal: AbortSignal.timeout(15_000),
  })
  if (!response.ok) throw new Error(`Rule provisioning failed: HTTP ${response.status}; preserve the recovery record`)
}))
console.log('Rule provisioned. Fund metering and enroll the holder using the deployment instructions before application use.')
