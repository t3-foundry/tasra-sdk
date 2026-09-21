// Vitest wrapper for test/client.session.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('client.session', () => runSuite(() => import('../client.session.ts')))
