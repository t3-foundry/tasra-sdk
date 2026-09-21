// Vitest wrapper for test/committee.conformance.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('committee.conformance', () => runSuite(() => import('../committee.conformance.ts')))
