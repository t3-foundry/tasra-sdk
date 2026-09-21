// Vitest wrapper for test/chain.deployments.ts — see test/_runSuite.ts for why.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('chain.deployments', () => runSuite(() => import('../chain.deployments.ts')))
