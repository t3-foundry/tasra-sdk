// Vitest wrapper for test/client.session-edges.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('client.session-edges', () => runSuite(() => import('../client.session-edges.ts')))
