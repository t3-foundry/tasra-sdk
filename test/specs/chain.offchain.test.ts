// Vitest wrapper for test/chain.offchain.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('chain.offchain', () => runSuite(() => import('../chain.offchain.ts')))
