// Vitest wrapper for test/holder-proof.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('holder-proof', () => runSuite(() => import('../holder-proof.ts')))
