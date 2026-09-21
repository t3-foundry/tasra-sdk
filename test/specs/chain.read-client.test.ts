// Vitest wrapper for test/chain.read-client.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('chain.read-client', () => runSuite(() => import('../chain.read-client.ts')))
