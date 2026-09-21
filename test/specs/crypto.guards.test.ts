// Vitest wrapper for test/crypto.guards.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('crypto.guards', () => runSuite(() => import('../crypto.guards.ts')))
