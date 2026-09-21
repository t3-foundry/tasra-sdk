// Vitest wrapper for test/recipient.store.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('recipient.store', () => runSuite(() => import('../recipient.store.ts')))
