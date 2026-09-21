// Vitest wrapper for test/frost.crypto.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('frost.crypto', () => runSuite(() => import('../frost.crypto.ts')))
