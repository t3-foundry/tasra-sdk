// Shared assertion + reporting harness for the live-fleet test suites.
//
// The repo's test idiom is "each file is a standalone tsx script that exits
// non-zero on failure" (see test/crypto.roundtrip.ts). These suites talk to a
// REAL running fleet, so they layer three things on top:
//   - named checks with a got/want diff on failure,
//   - a SKIP outcome — a suite that can't run because the fleet is down must
//     not be a hard failure unless KK_FLEET_REQUIRED=1 (mirrors how the chain
//     tests skip when the contracts repo is absent), and
//   - a one-line summary + non-zero exit when anything failed.

const RED = '\x1b[0;31m'
const GRN = '\x1b[0;32m'
const YEL = '\x1b[0;33m'
const CYN = '\x1b[1;36m'
const DIM = '\x1b[2m'
const RST = '\x1b[0m'

export class Suite {
  private passed = 0
  private readonly failures: string[] = []
  private readonly skips: string[] = []

  constructor(private readonly name: string) {
    console.log(`\n${CYN}▶ ${name}${RST}`)
  }

  /** Record a boolean check. Returns the condition so callers can branch. */
  ok(label: string, cond: boolean, detail?: string): boolean {
    if (cond) {
      this.passed++
      console.log(`  ${GRN}✓${RST} ${label}`)
    } else {
      this.failures.push(label)
      console.error(
        `  ${RED}✗ ${label}${RST}` +
          (detail ? `\n      ${DIM}${detail}${RST}` : ''),
      )
    }
    return cond
  }

  /** Equality check with a got/want diff printed on mismatch. */
  eq<T>(label: string, got: T, want: T): boolean {
    const g = fmt(got)
    const w = fmt(want)
    return this.ok(label, g === w, g === w ? undefined : `got ${g}  want ${w}`)
  }

  /** Numeric closeness check (for indexer lag, balances with rounding, etc.). */
  near(label: string, got: number, want: number, tol: number): boolean {
    const d = Math.abs(got - want)
    return this.ok(
      label,
      d <= tol,
      d <= tol ? undefined : `|${got} - ${want}| = ${d} > tol ${tol}`,
    )
  }

  skip(label: string, reason?: string): void {
    if (process.env.TASRA_CHECKS_REQUIRED === '1') {
      this.ok(label,false,reason ?? 'A required check was skipped')
      return
    }
    this.skips.push(label)
    const why = reason ? ` ${DIM}(skip: ${reason})${RST}` : ''
    console.log(`  ${YEL}- ${label}${RST}${why}`)
  }

  info(msg: string): void {
    console.log(`    ${DIM}${msg}${RST}`)
  }

  /** Print the summary; exit non-zero if any check failed. */
  done(): void {
    const parts = [`${this.passed} passed`]
    if (this.failures.length) parts.push(`${this.failures.length} failed`)
    if (this.skips.length) parts.push(`${this.skips.length} skipped`)
    const mark = this.failures.length ? `${RED}✗` : `${GRN}✓`
    console.log(`${mark} ${this.name}: ${parts.join(', ')}${RST}`)
    if (this.failures.length) process.exit(1)
  }
}

function fmt(v: unknown): string {
  if (typeof v === 'bigint') return v.toString()
  if (v instanceof Uint8Array) return '0x' + Buffer.from(v).toString('hex')
  if (typeof v === 'string') return v
  if (typeof v === 'object' && v !== null) return JSON.stringify(v)
  return String(v)
}

/** Byte-equality helper shared by crypto-touching suites. */
export function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i])
}

/**
 * Emit a machine-parseable performance metric. Prints a human line AND a
 * `::metric:: {json}` line that the verify orchestrator (test/verify/run.ts)
 * greps out of child stdout so numbers land in the consolidated report. Safe to
 * call from any standalone suite — when run directly it just prints both lines.
 */
export function metric(
  name: string,
  value: number,
  unit = '',
  extra: Record<string, string | number> = {},
): void {
  const payload = {name, value, unit, ...extra}
  console.log(`${DIM}    ◆ ${name} = ${value}${unit ? ` ${unit}` : ''}${RST}`)
  console.log(`::metric:: ${JSON.stringify(payload)}`)
}
