// Vitest config for the HERMETIC suites only.
//
// `test/specs/*.test.ts` are thin wrappers around the self-contained suites in
// `test/*.ts` (see test/_runSuite.ts). Everything under test/e2e, test/fleet,
// test/reconcile, test/slashing, test/stress, test/verify, and test/economics
// needs a live fleet + chain and stays as standalone `tsx` CLIs — those are run
// via `npm run test:e2e`, `test:fleet`, `stress:*`, `verify:*`.
//
// test/pack-smoke.ts is also excluded: it runs `npm pack` and lays out a scratch
// consumer, which is packaging verification (`npm run verify:pkg`), not a unit test.
import {defineConfig} from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/specs/**/*.test.ts'],
    // One worker per spec file, so each suite gets its own module registry —
    // several patch globalThis.fetch or depend on module-level state.
    isolate: true,
    // The suites print their own per-check lines; keep them visible on failure.
    silent: false,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // Generated ABI constants carry no logic worth measuring.
      exclude: ['src/chain/abis/**'],
      reporter: ['text', 'html'],
      reportsDirectory: 'coverage',

      // A floor, not a target. Set just under the numbers at the time of writing, so
      // ordinary churn does not fail the build but a REGRESSION does — without this,
      // coverage only ever drifts down and nobody notices which commit did it.
      //
      // Raise these when you raise coverage. They are deliberately global rather than
      // per-directory: a per-glob threshold removes those files from the global
      // calculation, which makes the headline number mean less, not more.
      thresholds: {
        statements: 94,
        branches: 90,
        functions: 95,
        lines: 96,
      },

      // ⚠ What the headline number does and does not say. This measures the HERMETIC
      // suites only, so two kinds of low directory are mixed together and they are not
      // the same thing:
      //
      //   STRUCTURAL — `src/decryption` (~6%) and `src/slots` (0%) are HTTP orchestration
      //   against real keepers and a live faucet. They are covered by test/e2e, which
      //   needs a deployment and cannot run here. Low is expected, not neglect — but it
      //   does mean CI never exercises them, so a change there is caught only by running
      //   the live suite.
      //
      //   A REAL GAP — reachable with a stubbed `fetch`. THIS LIST IS NOW EMPTY. Every
      //   directory but the two structural ones above is at ~93% statements or better, and
      //   what remains uncovered anywhere is the unreachable set enumerated at the bottom of
      //   this comment. A new entry here means someone added code without a test for it.
      //
      // Every other directory came OFF that list by being tested rather than by being
      // excluded, which is where these numbers came from:
      //   src/client       ~55%/~43% → ~99%/~92%  (client.auth.ts, client.rotation.ts,
      //                                            client.session-edges.ts)
      //   src/committee    ~71%/~62% → ~98%/~98%  (committee.one-call.ts, committee.guards.ts)
      //   src/crypto       ~91%/~71% → ~98%/~97%  (crypto.guards.ts)
      //   src/chain        ~70%/~75% → ~93%/~89%  (chain.format.ts, chain.read-client.ts,
      //                                            chain.slot-client.ts, chain.write-actions.ts,
      //                                            chain.offchain.ts, chain.manifest.test.ts)
      //   src/signing      ~51%/~39% → ~99%/~86%  (signing.paths.ts)
      //   src/oid4vp       ~78%/~67% → 100%/~95%  (oid4vp.primitives.ts, oid4vp.flows.ts)
      //   src/auth         ~87%/~80% → ~98%/~94%  (auth.verifier-client.ts,
      //                                            oid4vp.dcql-validation.ts)
      //   src/recipient    ~88%/~62% → 100%       (recipient.store.ts extended)
      //   src/keys         ~97%/~75% → 100%       (keys.node-client.ts)
      // Five files were the weakest in the package and are no longer: src/chain/client.ts
      // (~13% → 100%, every typed reader's contract+selector pinned), src/chain/write.ts
      // (~54% → ~98%, every wallet action's target+selector+args and which ones are relayed),
      // src/auth/verifier.ts (~48% → fully covered), src/chain/offchain.ts (~6% → fully
      // covered, every endpoint's URL plus the timeout that keeps an aggregator loop moving)
      // and src/chain/manifest.ts (~65% → 100%, `observeNetworkManifest` including the
      // swapped-implementation-behind-an-unchanged-proxy case it exists for).
      // Nothing structural had been in the way of any of it — only absent tests.
      //
      // ⚠ WHAT IS LEFT IS MOSTLY UNREACHABLE, and is left alone on purpose. Deleting a
      // defensive guard in a crypto or slot-creation path to move a number is the wrong
      // trade, so these stay uncovered rather than being removed or forced:
      //
      //   • rejection-sampling retries — `randomScalar()` in ibe.ts and kem.ts loops only if a
      //     512-bit random reduces to exactly zero (p ≈ 2^-255).
      //   • zero-scalar and zero-Lagrange arms (frost.ts `mul`, kem.ts's `lambda !== 0n`): a
      //     Lagrange coefficient is never zero for distinct identifiers.
      //   • the `fulfilled` arm of the error-aggregation mappers in committee/client.ts: that
      //     mapper only runs when NOTHING fulfilled, so the branch cannot be taken.
      //   • `?? fallback` arms where the lookup table is built from the same array being
      //     indexed (committee/client.ts `verifiers[i]`, committee/request.ts `byIndex.get`).
      //   • the draw's selection cap (token.ts) and `compareBytes`'s equal-byte continue,
      //     which need crafted digests rather than a test.
      //   • src/chain/write.ts's `relayForward` with no relay and `policyTuple` with no
      //     policy — no caller in this package can reach either.
      //   • src/chain/events.ts's positional-args branch, unreachable while no vendored ABI
      //     has unnamed event params.
      //   • `(claims ?? [])` arms and `if (claims !== undefined)` in auth/oid4vp.ts: every
      //     credential query is REQUIRED to carry an ["iss"] entry, so `claims` is never
      //     undefined by the time those run.
      //   • auth/oid4vp.ts's hand-written integer-index check: the path grammar
      //     (`asClaimPath`) already refuses a numeric segment, so the later `some(typeof ===
      //     'number')` cannot fire. The comment above it says it is enforced by hand because
      //     "nothing else would notice" — something else does now.
      //   • `e instanceof Error` false arms around JSON.parse: it only ever throws SyntaxError.
      //
      // A redundant guard found this way has since been FIXED rather than left: session.ts's
      // `#reassemble` used to repeat `ensureFresh`'s JWT-renewal condition on a path nothing
      // could reach, so relaxing the skew in one place would have left the other enforcing the
      // old rule. Both now call one private `#renewJwtIfStale`, and session.ts went to 100%
      // statements/functions/lines as a result — the unreachable branches disappeared because
      // the duplication did, not because a test contorted its way into them.
    },
  },
})
