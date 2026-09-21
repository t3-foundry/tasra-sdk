// Vitest wrapper for test/client.rotation.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('client.rotation', () => runSuite(() => import('../client.rotation.ts')))
