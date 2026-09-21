// Vitest wrapper for test/chain.events.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('chain.events', () => runSuite(() => import('../chain.events.ts')))
