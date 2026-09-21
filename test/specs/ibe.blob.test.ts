// Vitest wrapper for test/ibe.blob.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('ibe.blob', () => runSuite(() => import('../ibe.blob.ts')))
