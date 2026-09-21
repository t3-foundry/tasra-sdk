// Display/format helpers for on-chain values. Pure, dependency-free.

/** "0x1234…cdef" — middle-truncate an address/hash for compact display. */
export function truncateHex(hex: string, lead = 6, tail = 4): string {
  if (!hex) return ''
  const h = hex.startsWith('0x') ? hex : `0x${hex}`
  if (h.length <= 2 + lead + tail) return h
  return `${h.slice(0, 2 + lead)}…${h.slice(-tail)}`
}

/**
 * Format an 18-decimal token amount (wei) to a human string with up to
 * `maxFractionDigits` significant fractional digits, thousands-separated.
 * Generic over decimals.
 */
export function formatUnits(
  value: bigint,
  decimals = 18,
  maxFractionDigits = 4,
): string {
  const neg = value < 0n
  const v = neg ? -value : value
  const base = 10n ** BigInt(decimals)
  const whole = v / base
  const frac = v % base
  const wholeStr = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')
  if (maxFractionDigits === 0 || frac === 0n) {
    return `${neg ? '-' : ''}${wholeStr}`
  }
  let fracStr = frac.toString().padStart(decimals, '0').slice(0, maxFractionDigits)
  fracStr = fracStr.replace(/0+$/, '')
  return `${neg ? '-' : ''}${wholeStr}${fracStr ? `.${fracStr}` : ''}`
}

/** Format a basis-points integer (e.g. 1000) as a percentage string ("10%"). */
export function formatBps(bps: number | bigint): string {
  const n = Number(bps) / 100
  return `${Number.isInteger(n) ? n : n.toFixed(2)}%`
}

/** WAD (1e18 fixed-point) value to a decimal string, e.g. a price. */
export function formatWad(wad: bigint, maxFractionDigits = 6): string {
  return formatUnits(wad, 18, maxFractionDigits)
}
