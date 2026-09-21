// Shim that lets Vitest run the hand-rolled suites in `test/*.ts` as-is.
//
// Those suites predate any test runner: each is a self-executing module that
// tallies its own checks, prints them, and calls `process.exit(1)` if any failed.
// Between them they carry ~300 assertions with carefully written names.
//
// Rewriting all of that into `describe`/`it`/`expect` would mean re-deriving every
// assertion by hand — a lot of churn with a real chance of silently dropping
// coverage. So instead each suite keeps its logic verbatim and gets a three-line
// Vitest spec (in `test/specs/`) that runs it through this shim.
//
// One spec file per suite is deliberate: Vitest isolates the module registry per
// FILE, so this reproduces the one-process-per-suite isolation the old
// `tsx a.ts && tsx b.ts` chain had. Several suites patch `globalThis.fetch` or
// rely on module-level state (e.g. the proxy setting keys/node-client.ts reads
// once); sharing one registry between them would couple suites that are independent
// today. It also means the suites run in parallel across workers.

/** Thrown in place of a suite's `process.exit(code)` so the stack unwinds instead. */
class SuiteExit extends Error {
  constructor(readonly code: number) {
    super(`suite called process.exit(${code})`)
    this.name = 'SuiteExit'
  }
}

/**
 * Import a suite module with `process.exit` stubbed, and report its outcome.
 *
 * The suites signal failure by exiting non-zero after printing which checks
 * failed, so a non-zero code becomes a thrown error here and Vitest reports the
 * suite as failed with the printed detail in its captured output.
 *
 * @param load a thunk that dynamically imports the suite, e.g. `() => import('../crypto.roundtrip.ts')`
 */
export async function runSuite(load: () => Promise<unknown>): Promise<void> {
  const realExit = process.exit
  let exitCode: number | undefined

  // `process.exit` is typed as returning `never`; this stub throws instead, which
  // satisfies that contract but not the overload signature, hence the cast.
  process.exit = ((code?: number): never => {
    exitCode = code ?? 0
    throw new SuiteExit(exitCode)
  }) as typeof process.exit

  try {
    await load()
  } catch (e) {
    // A SuiteExit is the suite's own exit call — inspect the code below. Anything
    // else is a genuine throw (an assertion helper, or a bug) and should surface.
    if (!(e instanceof SuiteExit)) throw e
  } finally {
    process.exit = realExit
  }

  if (exitCode !== undefined && exitCode !== 0) {
    throw new Error(
      `suite failed (exit ${exitCode}) — see the captured output above for the failing checks`,
    )
  }
}
