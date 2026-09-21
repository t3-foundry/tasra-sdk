// Vitest wrapper for test/chain.write-actions.ts — see test/_runSuite.ts for why.
//
// 30s rather than the 5s default: the commit-reveal check drives the client's REAL
// epoch-wait loop, which sleeps 3s between beacon polls. Shortening that would mean
// asserting a wait that never waited, which is the part worth testing — commit-reveal is
// grinding-resistant only because the reveal happens after the beacon has moved.
import {test} from 'vitest'
import {runSuite} from '../_runSuite.ts'

test('chain.write-actions', () => runSuite(() => import('../chain.write-actions.ts')), 30_000)
