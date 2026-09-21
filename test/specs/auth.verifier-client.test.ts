// Vitest wrapper for test/auth.verifier-client.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('auth.verifier-client', () => runSuite(() => import('../auth.verifier-client.ts')))
