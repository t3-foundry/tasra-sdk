// Vitest wrapper for test/errors.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('errors', () => runSuite(() => import('../errors.ts')))
