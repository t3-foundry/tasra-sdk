// Vitest wrapper for test/chain.write-signer.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('chain.write-signer', () => runSuite(() => import('../chain.write-signer.ts')))
