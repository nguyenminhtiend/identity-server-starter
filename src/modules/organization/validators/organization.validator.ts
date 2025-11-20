import { z } from 'zod';

/**
 * Organization slug validation
 * Must be URL-friendly: lowercase letters, numbers, hyphens
 */
export const organizationSlugSchema = z
  .string()
  .min(3, 'Slug must be at least 3 characters')
  .max(50, 'Slug must be at most 50 characters')
  .regex(/^[a-z0-9-]+$/, 'Slug must contain only lowercase letters, numbers, and hyphens')
  .regex(/^[a-z]/, 'Slug must start with a letter')
  .regex(/[a-z0-9]$/, 'Slug must end with a letter or number')
  .refine((slug) => !slug.includes('--'), {
    message: 'Slug cannot contain consecutive hyphens',
  });

/**
 * Organization name validation
 */
export const organizationNameSchema = z
  .string()
  .min(1, 'Organization name is required')
  .max(255, 'Organization name must be at most 255 characters')
  .trim();

/**
 * Create organization validation schema
 */
export const createOrganizationSchema = z.object({
  name: organizationNameSchema,
  slug: organizationSlugSchema,
  ownerUserId: z.string().uuid('Invalid owner user ID'),
});

export type CreateOrganizationInput = z.infer<typeof createOrganizationSchema>;

/**
 * Update organization validation schema
 */
export const updateOrganizationSchema = z.object({
  name: organizationNameSchema.optional(),
  slug: organizationSlugSchema.optional(),
  isActive: z.boolean().optional(),
});

export type UpdateOrganizationInput = z.infer<typeof updateOrganizationSchema>;

/**
 * Organization ID parameter validation
 */
export const organizationIdParamSchema = z.object({
  id: z.string().uuid('Invalid organization ID'),
});

export type OrganizationIdParam = z.infer<typeof organizationIdParamSchema>;

/**
 * List organizations query validation
 */
export const listOrganizationsQuerySchema = z.object({
  isActive: z
    .string()
    .optional()
    .transform((val) => {
      if (val === 'true') return true;
      if (val === 'false') return false;
      return undefined;
    }),
  limit: z
    .string()
    .optional()
    .transform((val) => (val !== undefined ? parseInt(val, 10) : 20))
    .pipe(z.number().min(1).max(100)),
  offset: z
    .string()
    .optional()
    .transform((val) => (val !== undefined ? parseInt(val, 10) : 0))
    .pipe(z.number().min(0)),
});

export type ListOrganizationsQuery = z.infer<typeof listOrganizationsQuerySchema>;
