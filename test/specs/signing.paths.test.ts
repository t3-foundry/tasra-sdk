// Vitest wrapper for test/signing.paths.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('signing.paths', () => runSuite(() => import('../signing.paths.ts')))
