import { z } from 'zod';

/**
 * Key rotation confirmation schema
 */
export const rotateKeysSchema = z.object({
  confirm: z.boolean().refine((val) => val === true, {
    message: 'You must confirm key rotation',
  }),
});

export type RotateKeysInput = z.infer<typeof rotateKeysSchema>;
