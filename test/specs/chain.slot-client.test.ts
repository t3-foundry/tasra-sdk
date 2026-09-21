// Vitest wrapper for test/chain.slot-client.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('chain.slot-client', () => runSuite(() => import('../chain.slot-client.ts')))
