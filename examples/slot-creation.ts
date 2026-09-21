import type {CreateSlotArgs, TasraWriteClient} from 'tasra-sdk/chain'

/** Keep custody explicit; commit/reveal cannot create an exportable slot. */
export async function createExampleSlot(writer: TasraWriteClient, requiresCommitReveal: boolean, args: CreateSlotArgs) {
  if (requiresCommitReveal && args.exportable) {
    throw new Error('This deployment requires commit/reveal and cannot create exportable personal-vault slots')
  }
  return requiresCommitReveal ? writer.createSlotCommitReveal(args) : writer.createSlot(args)
}
