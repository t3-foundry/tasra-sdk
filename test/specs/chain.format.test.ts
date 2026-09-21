// Vitest wrapper for test/chain.format.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('chain.format', () => runSuite(() => import('../chain.format.ts')))
