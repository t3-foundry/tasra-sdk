// Vitest wrapper for test/committee.guards.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('committee.guards', () => runSuite(() => import('../committee.guards.ts')))
