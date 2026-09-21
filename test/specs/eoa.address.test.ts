// Vitest wrapper for test/eoa.address.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('eoa.address', () => runSuite(() => import('../eoa.address.ts')))
