// Vitest wrapper for test/decrypt.shares.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('decrypt.shares', () => runSuite(() => import('../decrypt.shares.ts')))
