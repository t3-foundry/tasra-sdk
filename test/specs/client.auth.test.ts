// Vitest wrapper for test/client.auth.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('client.auth', () => runSuite(() => import('../client.auth.ts')))
