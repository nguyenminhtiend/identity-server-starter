import { z } from 'zod';

/**
 * Client type enum
 */
export const clientTypeSchema = z.enum(['confidential', 'public']);

/**
 * Grant types validation
 */
export const grantTypesSchema = z
  .array(z.enum(['authorization_code', 'refresh_token', 'client_credentials']))
  .min(1, 'At least one grant type is required')
  .refine(
    (grantTypes) => {
      // If authorization_code is used, refresh_token is typically also needed
      if (grantTypes.includes('authorization_code') && !grantTypes.includes('refresh_token')) {
        return false;
      }
      return true;
    },
    {
      message: 'authorization_code grant type requires refresh_token grant type',
    }
  );

/**
 * Redirect URIs validation
 */
export const redirectUrisSchema = z
  .array(z.string().url('Invalid redirect URI'))
  .min(1, 'At least one redirect URI is required')
  .refine(
    (uris) => {
      // Ensure all URIs use HTTPS in production (except localhost)
      if (process.env.NODE_ENV === 'production') {
        return uris.every((uri) => {
          const parsed = new URL(uri);
          return (
            parsed.protocol === 'https:' ||
            parsed.hostname === 'localhost' ||
            parsed.hostname === '127.0.0.1'
          );
        });
      }
      return true;
    },
    {
      message: 'Redirect URIs must use HTTPS in production (except localhost)',
    }
  );

/**
 * CORS origins validation
 */
export const corsOriginsSchema = z
  .array(z.string().url('Invalid CORS origin'))
  .optional()
  .refine(
    (origins) => {
      if (!origins) return true;
      // Validate that all origins are valid URLs
      return origins.every((origin) => {
        try {
          new URL(origin);
          return true;
        } catch {
          return false;
        }
      });
    },
    {
      message: 'All CORS origins must be valid URLs',
    }
  );

/**
 * Create client validation schema
 */
export const createClientSchema = z
  .object({
    name: z
      .string()
      .min(1, 'Client name is required')
      .max(255, 'Client name must be at most 255 characters'),
    clientType: clientTypeSchema,
    redirectUris: redirectUrisSchema,
    grantTypes: grantTypesSchema,
    allowedScopes: z
      .string()
      .min(1, 'At least one scope is required')
      .regex(/^[\w\s]+$/, 'Scopes must contain only alphanumeric characters and spaces'),
    organizationId: z.string().uuid('Invalid organization ID').optional(),
    logoUrl: z.string().url('Invalid logo URL').optional(),
    allowedCorsOrigins: corsOriginsSchema,
    termsUrl: z.string().url('Invalid terms URL').optional(),
    privacyUrl: z.string().url('Invalid privacy URL').optional(),
    homepageUrl: z.string().url('Invalid homepage URL').optional(),
    contacts: z.array(z.string().email('Invalid contact email')).optional(),
  })
  .refine(
    (data) => {
      // Public clients cannot use client_credentials grant
      if (data.clientType === 'public' && data.grantTypes.includes('client_credentials')) {
        return false;
      }
      return true;
    },
    {
      message: 'Public clients cannot use client_credentials grant type',
      path: ['grantTypes'],
    }
  )
  .refine(
    (data) => {
      // Public clients should have CORS origins if they use authorization_code flow
      if (
        data.clientType === 'public' &&
        data.grantTypes.includes('authorization_code') &&
        (!data.allowedCorsOrigins || data.allowedCorsOrigins.length === 0)
      ) {
        return false;
      }
      return true;
    },
    {
      message: 'Public clients using authorization_code flow should specify allowed CORS origins',
      path: ['allowedCorsOrigins'],
    }
  );

export type CreateClientInput = z.infer<typeof createClientSchema>;

/**
 * Update client validation schema
 */
export const updateClientSchema = z.object({
  name: z
    .string()
    .min(1, 'Client name is required')
    .max(255, 'Client name must be at most 255 characters')
    .optional(),
  redirectUris: redirectUrisSchema.optional(),
  logoUrl: z.string().url('Invalid logo URL').optional(),
  allowedCorsOrigins: corsOriginsSchema,
  termsUrl: z.string().url('Invalid terms URL').optional(),
  privacyUrl: z.string().url('Invalid privacy URL').optional(),
  homepageUrl: z.string().url('Invalid homepage URL').optional(),
  contacts: z.array(z.string().email('Invalid contact email')).optional(),
  allowedScopes: z
    .string()
    .min(1, 'At least one scope is required')
    .regex(/^[\w\s]+$/, 'Scopes must contain only alphanumeric characters and spaces')
    .optional(),
  isActive: z.boolean().optional(),
});

export type UpdateClientInput = z.infer<typeof updateClientSchema>;

/**
 * Client ID parameter validation
 */
export const clientIdParamSchema = z.object({
  id: z.string().uuid('Invalid client ID'),
});

export type ClientIdParam = z.infer<typeof clientIdParamSchema>;

/**
 * List clients query validation
 */
export const listClientsQuerySchema = z.object({
  organizationId: z.string().uuid('Invalid organization ID').optional(),
  clientType: clientTypeSchema.optional(),
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

export type ListClientsQuery = z.infer<typeof listClientsQuerySchema>;

/**
 * Regenerate secret request validation
 */
export const regenerateSecretSchema = z.object({
  confirm: z.boolean().refine((val) => val === true, {
    message: 'You must confirm secret regeneration',
  }),
});

export type RegenerateSecretInput = z.infer<typeof regenerateSecretSchema>;
