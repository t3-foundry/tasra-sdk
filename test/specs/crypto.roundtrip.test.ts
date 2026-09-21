// Vitest wrapper for test/crypto.roundtrip.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('crypto.roundtrip', () => runSuite(() => import('../crypto.roundtrip.ts')))
