// Vitest wrapper for test/dpop.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('dpop', () => runSuite(() => import('../dpop.ts')))
