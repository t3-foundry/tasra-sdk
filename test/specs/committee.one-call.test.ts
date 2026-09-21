// Vitest wrapper for test/committee.one-call.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('committee.one-call', () => runSuite(() => import('../committee.one-call.ts')))
