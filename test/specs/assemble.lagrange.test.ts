// Vitest wrapper for test/assemble.lagrange.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('assemble.lagrange', () => runSuite(() => import('../assemble.lagrange.ts')))
