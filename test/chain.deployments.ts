// Deployment address-book conformance: parse a real Foundry broadcast run,
// parse an env-format address blob, and check requireAddress.
//
// Run: tsx test/chain.deployments.ts — exits non-zero on any failure.

import {readFileSync} from 'node:fs'
import {basename, dirname, join, resolve} from 'node:path'
import {fileURLToPath} from 'node:url'
import {
  addressBookFromBroadcast,
  addressBookFromEnv,
  addressBookFromObject,
  requireAddress,
  requireVaultAddress,
  VAULT_TRANCHES,
} from '../src/chain/deployments.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean) {
  if (cond) passed++
  else failures.push(name)
}

const here = dirname(fileURLToPath(import.meta.url))

// 1. Parse real Foundry broadcast runs, committed as fixtures.
{
  // Two real deploys with DIFFERENT contract sets. Both mix contracts created
  // directly (`contractAddress` on a CREATE) with contracts created by a factory
  // (named under `additionalContracts` of a CALL), and covering only one deploy
  // once hid a bug where a run resolved almost nothing.
  const fixtures = resolve(here, 'fixtures', 'broadcast')
  const runFiles = ['43112-run.json', '43113-run.json'].map(f => join(fixtures, f))

  // Contracts deployed behind an ERC1967Proxy. Their book entry must be the
  // PROXY: an implementation address is a live address that reads as
  // uninitialized storage, so a format check cannot catch the mix-up.
  const PROXIED = [
    'NodeRegistry',
    'KeyRegistry',
    'Settlement',
    'AccountantSlashing',
    'LivenessRegistry',
    'VerifierSetRegistry',
    'KeeperShareRegistry',
    'AccountantSetRegistry',
  ] as const

  for (const runFile of runFiles) {
    const chain = basename(runFile).replace('-run.json', '')
    const raw = JSON.parse(readFileSync(runFile, 'utf8')) as {
      transactions?: Array<{
        transactionType?: string
        contractName?: string
        contractAddress?: string
        additionalContracts?: Array<{contractName?: string; address?: string}>
      }>
    }
    const book = addressBookFromBroadcast(raw)

    // Ground truth straight out of the run: every ERC1967Proxy it created.
    const proxies = new Set<string>()
    for (const t of raw.transactions ?? []) {
      if (t.contractName === 'ERC1967Proxy' && t.contractAddress)
        proxies.add(t.contractAddress.toLowerCase())
      for (const a of t.additionalContracts ?? [])
        if (a.contractName === 'ERC1967Proxy' && a.address)
          proxies.add(a.address.toLowerCase())
    }

    for (const name of ['NodeRegistry', 'KeyRegistry', 'Settlement'] as const) {
      ok(
        `broadcast[${chain}]: ${name} resolved`,
        /^0x[0-9a-f]{40}$/.test(book[name] ?? ''),
      )
    }
    // The slot-driven committee flow needs VerifierSetRegistry from the book.
    ok(
      `broadcast[${chain}]: VerifierSetRegistry resolved`,
      /^0x[0-9a-f]{40}$/.test(book.VerifierSetRegistry ?? ''),
    )
    if (proxies.size) {
      for (const name of PROXIED) {
        const addr = book[name]
        ok(
          `broadcast[${chain}]: ${name} is the proxy, not the implementation`,
          !!addr && proxies.has(addr),
        )
      }
    }

    // The deploy creates one vesting vault per tranche, all labelled
    // TasraVestingVault in the run. They must come back as three distinct
    // addresses, and the bare name must not resolve (it would be whichever
    // vault happened to be deployed last).
    const vaultCount = [
      ...(raw.transactions ?? []).flatMap(t => [
        ...(t.contractName === 'TasraVestingVault' ? [1] : []),
        ...(t.additionalContracts ?? []).filter(
          a => a.contractName === 'TasraVestingVault',
        ),
      ]),
    ].length
    if (vaultCount > 1) {
      const addrs = VAULT_TRANCHES.map(t => requireVaultAddress(book, t))
      ok(
        `broadcast[${chain}]: ${VAULT_TRANCHES.length} vault tranches resolve distinctly`,
        new Set(addrs).size === VAULT_TRANCHES.length,
      )
      ok(
        `broadcast[${chain}]: ambiguous bare TasraVestingVault key dropped`,
        book.TasraVestingVault === undefined,
      )
    }
  }
}

// 2. Parse an env-format address blob with aliases + raw keys.
{
  const env = [
    '# fleet chain credentials',
    'NODE_REGISTRY=0x0165878A594ca255338adfa4d48449f69242Eb8F',
    'KEY_REGISTRY="0x2279b7a0a67db372996a5fab50d91eaa73d2ebe6"',
    'KEYK_TOKEN=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512',
    'export RANDOM_BEACON=0xa513e6e4b8f2a923d98304ec87f64353c4d5c853',
    'VERIFIER_SET_REGISTRY=0xbf921f94fd9ef1738be25d8cecfdfe2c822c81b0',
    'KEEPER_SHARE_REGISTRY=0x9A9f2CCfdE556A7E9Ff0848998Aa4a0CFD8863AE',
    'GARBAGE=not-an-address',
  ].join('\n')
  const book = addressBookFromEnv(env)
  ok('env: NODE_REGISTRY → NodeRegistry', book.NodeRegistry === '0x0165878a594ca255338adfa4d48449f69242eb8f')
  ok('env: KEYK_TOKEN alias → TasraToken', book.TasraToken === '0xe7f1725e7734ce288f8367e1bb143e90bb3f0512')
  ok('env: export prefix stripped', book.ThresholdRandomBeacon === '0xa513e6e4b8f2a923d98304ec87f64353c4d5c853')
  // Aliases added for the slot-driven committee flow (trustless snapshot).
  ok('env: VERIFIER_SET_REGISTRY → VerifierSetRegistry', book.VerifierSetRegistry === '0xbf921f94fd9ef1738be25d8cecfdfe2c822c81b0')
  ok('env: KEEPER_SHARE_REGISTRY → KeeperShareRegistry', book.KeeperShareRegistry === '0x9a9f2ccfde556a7e9ff0848998aa4a0cfd8863ae')
  ok('env: raw key kept too', book.NODE_REGISTRY === book.NodeRegistry)
  ok('env: non-address skipped', book.GARBAGE === undefined)
}

// 2b. The same aliasing from an env OBJECT (process.env / import.meta.env).
// This is the form the README's chain quick start uses, so it has to work: a
// whole process.env is mostly non-addresses, and those must be dropped rather
// than throw.
{
  const book = addressBookFromEnv({
    NODE_REGISTRY: '0x0165878A594ca255338adfa4d48449f69242Eb8F',
    KEYK_TOKEN: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512',
    PATH: '/usr/bin:/bin',
    SHELL: '/bin/zsh',
    EMPTY: '',
    ABSENT: undefined,
  })
  ok('obj: NODE_REGISTRY → NodeRegistry', book.NodeRegistry === '0x0165878a594ca255338adfa4d48449f69242eb8f')
  ok('obj: KEYK_TOKEN alias → TasraToken', book.TasraToken === '0xe7f1725e7734ce288f8367e1bb143e90bb3f0512')
  ok('obj: raw key kept too', book.NODE_REGISTRY === book.NodeRegistry)
  ok('obj: non-address env vars skipped', book.PATH === undefined && book.SHELL === undefined)
  ok('obj: empty + undefined values skipped', book.EMPTY === undefined && book.ABSENT === undefined)
  // Parity with the blob form — same input, same book.
  const fromBlob = addressBookFromEnv('NODE_REGISTRY=0x0165878A594ca255338adfa4d48449f69242Eb8F')
  ok('obj: matches the KEY=VALUE blob form', fromBlob.NodeRegistry === book.NodeRegistry)
}

// 3. requireAddress throws on a missing contract.
{
  let threw = false
  try {
    requireAddress({}, 'NodeRegistry')
  } catch {
    threw = true
  }
  ok('requireAddress: throws when missing', threw)
}

// 4. Vesting-tranche resolution.
{
  const book = addressBookFromEnv(
    [
      'TASRA_VAULT_INVESTOR=0x0165878A594ca255338adfa4d48449f69242Eb8F',
      'VAULT_TEAM=0x2279b7a0a67db372996a5fab50d91eaa73d2ebe6',
    ].join('\n'),
  )
  ok(
    'env: TASRA_VAULT_INVESTOR → investor tranche',
    requireVaultAddress(book, 'investor') ===
      '0x0165878a594ca255338adfa4d48449f69242eb8f',
  )
  ok(
    'env: VAULT_TEAM → team tranche',
    requireVaultAddress(book, 'team') ===
      '0x2279b7a0a67db372996a5fab50d91eaa73d2ebe6',
  )

  // A single-vault deployment carries only the bare name; the fallback is safe
  // there precisely because a multi-vault book drops that key.
  const single = addressBookFromObject({
    TasraVestingVault: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512',
  })
  ok(
    'requireVaultAddress: falls back to the bare name when unambiguous',
    requireVaultAddress(single, 'community') ===
      '0xe7f1725e7734ce288f8367e1bb143e90bb3f0512',
  )

  let threw = false
  try {
    requireVaultAddress({}, 'investor')
  } catch {
    threw = true
  }
  ok('requireVaultAddress: throws when missing', threw)
}

if (failures.length) {
  console.error(`chain.deployments FAILED (${failures.length}):`)
  for (const f of failures) console.error('  ✗', f)
  process.exit(1)
}
console.log(`chain.deployments: ${passed} checks passed`)
