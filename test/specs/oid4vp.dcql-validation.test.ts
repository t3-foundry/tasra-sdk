// Vitest wrapper for test/oid4vp.dcql-validation.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('oid4vp.dcql-validation', () => runSuite(() => import('../oid4vp.dcql-validation.ts')))
