// Vitest wrapper for test/committee.flow.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('committee.flow', () => runSuite(() => import('../committee.flow.ts')))
