// Vitest wrapper for test/ibe.conformance.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('ibe.conformance', () => runSuite(() => import('../ibe.conformance.ts')))
