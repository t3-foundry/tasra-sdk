// Vitest wrapper for test/committee.request.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('committee.request', () => runSuite(() => import('../committee.request.ts')))
