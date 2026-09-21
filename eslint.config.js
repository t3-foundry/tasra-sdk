// Flat ESLint config (ESLint 9/10 "flat config" format).
//
// `@eslint/js` recommended + typescript-eslint **recommendedTypeChecked**. The
// type-aware variant is the point: it is the only way to get `no-floating-promises`,
// `no-misused-promises` and `await-thenable`, and an unawaited promise in a session or
// crypto path is a real bug class in this package.
//
// Type-aware linting needs a project for every linted file. `tsconfig.json` covers
// `src/` only, so `tsconfig.test.json` (src + test + examples + this repo's configs) is
// listed alongside it; a file in neither is a parse error rather than a silent skip.
//
// Every deviation below is justified inline. The rule is that lint stays GREEN — a
// finding is either fixed, or downgraded with the reason it is not a defect here.

import js from '@eslint/js'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  // ---------------------------------------------------------------------
  // Global ignores. A config object with only `ignores` applies repo-wide.
  // ---------------------------------------------------------------------
  {
    ignores: [
      'dist/**', // build output
      'node_modules/**',
      'src/chain/abis/**', // AUTO-GENERATED
      'coverage/**', // vitest coverage report (generated)
    ],
  },

  // ---------------------------------------------------------------------
  // TypeScript sources across the repo (src/, test/, examples/).
  // ---------------------------------------------------------------------
  {
    files: ['**/*.ts'],
    extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      parserOptions: {
        project: ['./tsconfig.json', './tsconfig.test.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Many response bodies are untyped JSON handled as `Record<string, any>`.
      // Keep it visible but non-blocking rather than churning real types now.
      '@typescript-eslint/no-explicit-any': 'warn',

      // The `no-unsafe-*` family all descend from that same deliberate `any` at the
      // network boundary: a decoded JSON body is genuinely unknown until validated.
      // Warn, consistent with `no-explicit-any` above — turning these into errors would
      // mean either lying with casts or blocking on a full response-type effort.
      '@typescript-eslint/no-unsafe-member-access': 'warn',
      '@typescript-eslint/no-unsafe-assignment': 'warn',
      '@typescript-eslint/no-unsafe-argument': 'warn',
      '@typescript-eslint/no-unsafe-return': 'warn',
      '@typescript-eslint/no-unsafe-call': 'warn',

      // ⚠ WARN, and do NOT run `eslint --fix` for this one. Its autofix is unsound
      // against viem's deeply-generic ABI types: removing the assertion changes what
      // TypeScript infers, and a fix pass over this repo produced code that eslint
      // called clean and `tsc` rejected in src/chain/{client,serviceIdentity}.ts. If you
      // act on one of these, delete the assertion by hand and run `npm run typecheck`.
      '@typescript-eslint/no-unnecessary-type-assertion': 'warn',

      // ⚠ OFF deliberately. The flagged sites forward `AbortSignal.reason` —
      // `reject(signal.reason)` — which is the correct way to propagate the real abort
      // cause. The DOM types `reason` as `any`, so the rule cannot see that the
      // abort sites pass an Error. Rejecting with a fresh Error instead would DISCARD
      // the cause, which is strictly worse.
      '@typescript-eslint/prefer-promise-reject-errors': 'off',

      // Warn: the flagged reads are closures off an object literal
      // (`{...discovery, relayRequest: relay.request}`), not prototype methods, so
      // unbinding them is safe. Kept visible in case a real prototype method appears.
      '@typescript-eslint/unbound-method': 'warn',

      // Empty `catch {}` is used intentionally throughout for best-effort
      // fallbacks (feature detection, optional parses). Allow it; still flag
      // other empty blocks.
      'no-empty': ['error', { allowEmptyCatch: true }],

      // Allow deliberately-unused bindings when prefixed with `_`, and don't
      // flag unused caught errors (we frequently swallow them by design).
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrors: 'none',
          ignoreRestSiblings: true,
        },
      ],
    },
  },

  // ---------------------------------------------------------------------
  // Library code (src/) should not ship stray console output. Warn only.
  // examples/ and test/ are CLIs/harnesses — console is expected.
  // ---------------------------------------------------------------------
  {
    files: ['src/**/*.ts'],
    ignores: ['src/chain/abis/**'],
    rules: {
      'no-console': 'warn',

      // Warn, not error: the one site is `async close(): Promise<void>` with nothing to
      // await yet. It is async because the public API is documented as returning a
      // promise and `closeAll()` awaits it — making it sync would be a breaking change,
      // and it leaves room for async teardown later.
      '@typescript-eslint/require-await': 'warn',
    },
  },

  // ---------------------------------------------------------------------
  // Harnesses and examples. These are scripts, not library code.
  // ---------------------------------------------------------------------
  {
    files: ['test/**/*.ts', 'examples/**/*.ts'],
    rules: {
      // 84 of the 85 findings are here, and they are interface conformance: a harness
      // helper is `async` because its caller awaits it and a sibling implementation
      // does await. Making them sync would churn every call site for no gain.
      '@typescript-eslint/require-await': 'off',

      // Diagnostic output interpolates values whose type is deliberately loose
      // (decoded JSON, vector fields). A wrong string in a test message is visible
      // immediately; it is not worth a cast at every interpolation.
      '@typescript-eslint/restrict-template-expressions': 'off',
      '@typescript-eslint/no-base-to-string': 'off',
    },
  },
)
