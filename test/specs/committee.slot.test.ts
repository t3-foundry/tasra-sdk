// Vitest wrapper for test/committee.slot.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('committee.slot', () => runSuite(() => import('../committee.slot.ts')))
