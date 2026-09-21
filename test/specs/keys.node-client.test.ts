// Vitest wrapper for test/keys.node-client.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('keys.node-client', () => runSuite(() => import('../keys.node-client.ts')))
