// Display formatters for on-chain values — pure, no chain, no network.
//
// These had no tests at all, which for money formatting is the wrong place to have
// none: every defect here is silent. A dropped thousands separator, a fraction
// truncated instead of rounded, or a sign lost on a negative balance all produce a
// plausible-looking wrong number that no type checks and no caller notices.
//
// So the assertions pin exact strings, including the cases a naive implementation
// gets wrong: sub-unit amounts (leading fractional zeros must survive), trailing
// zeros (stripped), 0 decimals, and non-18-decimal tokens.
//
// Run: tsx test/chain.format.ts — exits non-zero on any failure.

import {formatBps, formatUnits, formatWad, truncateHex} from '../src/chain/format.ts'

let passed = 0
const failures: string[] = []
function ok(name: string, cond: boolean, detail = ''): void {
  if (cond) passed++
  else failures.push(name + (detail ? ` — ${detail}` : ''))
}
/** Assert an exact string, and report what came back when it differs. */
function eq(name: string, actual: string, expected: string): void {
  ok(name, actual === expected, `got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`)
}

const addr = '0x1234567890abcdef1234567890abcdef12345678'

// ─── truncateHex ──────────────────────────────────────────────────────────────
eq('truncateHex: default 6/4 window', truncateHex(addr), '0x123456…5678')
eq('truncateHex: custom window', truncateHex(addr, 4, 6), '0x1234…345678')
eq('truncateHex: empty in, empty out', truncateHex(''), '')
// A bare hash without 0x gets one, so the output is uniform whatever the caller holds.
eq('truncateHex: adds a missing 0x', truncateHex('abcdefabcdefabcdef'), '0xabcdef…cdef')
// Short enough to show whole: returned intact, NOT padded with an ellipsis.
eq('truncateHex: short value is returned whole', truncateHex('0xdeadbeef'), '0xdeadbeef')
eq('truncateHex: exactly at the boundary is whole', truncateHex('0x1234567890'), '0x1234567890')
ok('truncateHex: one over the boundary truncates', truncateHex('0x12345678901').includes('…'))

// ─── formatUnits ──────────────────────────────────────────────────────────────
const wei = (whole: string, frac = ''): bigint => BigInt(whole + frac.padEnd(18, '0'))

eq('formatUnits: zero', formatUnits(0n), '0')
eq('formatUnits: one whole token', formatUnits(wei('1')), '1')
eq('formatUnits: thousands separated', formatUnits(wei('1234567')), '1,234,567')
// Exactly three digits must NOT gain a separator, and four must.
eq('formatUnits: 999 has no separator', formatUnits(wei('999')), '999')
eq('formatUnits: 1000 has one', formatUnits(wei('1000')), '1,000')
eq('formatUnits: fraction kept to 4 digits', formatUnits(wei('1', '5')), '1.5')
eq('formatUnits: trailing zeros stripped', formatUnits(wei('2', '50')), '2.5')
// The fraction is TRUNCATED, not rounded — pin it, because the two differ here and a
// caller reading "1.2346" would be seeing a number the chain does not hold.
eq('formatUnits: fraction truncates rather than rounds', formatUnits(wei('1', '23456789')), '1.2345')
eq('formatUnits: maxFractionDigits honoured', formatUnits(wei('1', '23456789'), 18, 2), '1.23')
eq('formatUnits: maxFractionDigits 0 drops the fraction', formatUnits(wei('1', '9'), 18, 0), '1')
// Sub-unit amounts: the leading zeros inside the fraction are significant. Losing them
// reports 1 wei of a 6-decimal token as "0.1" — five orders of magnitude out.
eq('formatUnits: sub-unit keeps leading fractional zeros', formatUnits(1000n, 6, 6), '0.001')
eq('formatUnits: 1 wei at 18 decimals rounds away to 0', formatUnits(1n), '0')
eq('formatUnits: 1 unit of a 6-decimal token', formatUnits(1_000_000n, 6), '1')
eq('formatUnits: 6-decimal token with a fraction', formatUnits(1_250_000n, 6), '1.25')
eq('formatUnits: 0 decimals is a plain integer', formatUnits(42n, 0), '42')
// Negative: the sign must survive both the separator and the fraction paths.
eq('formatUnits: negative whole', formatUnits(-wei('1234')), '-1,234')
eq('formatUnits: negative with a fraction', formatUnits(-wei('1', '5')), '-1.5')
eq('formatUnits: negative sub-unit', formatUnits(-1n), '-0')

// ─── formatBps ────────────────────────────────────────────────────────────────
// The protocol's own diversion rate is 1000 bps; an off-by-100 here misreports 10% as
// 0.1% or 1000%, which is exactly the number an operator would act on.
eq('formatBps: 1000 bps is 10%', formatBps(1000), '10%')
eq('formatBps: 10000 bps is 100%', formatBps(10000), '100%')
eq('formatBps: 0', formatBps(0), '0%')
eq('formatBps: integer percent has no decimals', formatBps(500), '5%')
eq('formatBps: non-integer percent gets 2 decimals', formatBps(1234), '12.34%')
eq('formatBps: 1 bp', formatBps(1), '0.01%')
eq('formatBps: accepts a bigint', formatBps(1000n), '10%')

// ─── formatWad ────────────────────────────────────────────────────────────────
// A WAD is 18-decimal fixed point with a wider default fraction than a token amount —
// a price needs the extra digits.
eq('formatWad: 1e18 is 1', formatWad(10n ** 18n), '1')
eq('formatWad: keeps 6 fractional digits by default', formatWad(1_500_000_000_000_000_000n), '1.5')
eq('formatWad: default fraction is wider than formatUnits', formatWad(BigInt('1123456789012345678')), '1.123456')
ok(
  'formatWad: default fraction width differs from formatUnits',
  formatWad(BigInt('1123456789012345678')) !== formatUnits(BigInt('1123456789012345678')),
)
eq('formatWad: explicit width', formatWad(BigInt('1123456789012345678'), 2), '1.12')

if (failures.length > 0) {
  console.error(`✗ chain.format: ${failures.length} failed of ${passed + failures.length}:`)
  for (const f of failures) console.error('   - ' + f)
  process.exit(1)
}
console.log(`✓ chain.format: ${passed} checks passed`)
