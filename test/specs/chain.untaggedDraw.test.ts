import {describe, expect, it} from 'vitest'
import {untaggedDrawSeatsNonKeepers} from '../../src/chain/write.js'

// `tasra-cli` carries the same gate (`untagged_draw_verdict`). Two entry points into one
// contract behaviour, so both must refuse it — a hardening applied to one of two identical
// siblings is half a fix.
describe('untagged committee draw', () => {
  it('refuses the mixed active set that produced the bug on Fuji', () => {
    // 15 active operators, 9 keeper-tagged; the rest accountants and verifiers. An untagged
    // draw seated acct-2 and two verifiers: the slot was created and paid for, its DKG never
    // ran, and the only symptom was a 404 when its rule was provisioned. Unrepairable —
    // `reshare` needs a published key the DKG never produced.
    expect(untaggedDrawSeatsNonKeepers(15n, 9n)).toBe(true)
  })

  it('leaves a homogeneous fleet alone', () => {
    // Every active operator is a keeper, so an untagged draw is correct. Refusing here would
    // be a false positive on exactly the deployments that never had the problem.
    expect(untaggedDrawSeatsNonKeepers(10n, 10n)).toBe(false)
  })

  it('leaves a deployment that does not use the tag alone', () => {
    // Nothing to advise: the check must not invent a requirement never adopted here.
    expect(untaggedDrawSeatsNonKeepers(10n, 0n)).toBe(false)
  })

  it('does not read an impossible count as a mix', () => {
    expect(untaggedDrawSeatsNonKeepers(5n, 9n)).toBe(false)
  })
})
