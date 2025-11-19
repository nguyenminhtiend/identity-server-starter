import { z } from 'zod';

/**
 * Client Management Validation Schemas
 * For creating and managing OAuth clients
 */

// Client types
export const clientTypeSchema = z.enum(['confidential', 'public'], {
  message: 'Client type must be either "confidential" or "public"',
});

// Grant types
export const grantTypesSchema = z
  .array(z.enum(['authorization_code', 'refresh_token', 'client_credentials']))
  .min(1, 'At least one grant type is required')
  .refine(
    (_grantTypes) => {
      // Public clients cannot use client_credentials
      // This will be checked in combination with clientType
      return true;
    },
    { message: 'Invalid grant type combination' }
  );

// Redirect URIs (array)
export const redirectUrisSchema = z
  .array(
    z
      .string()
      .url('Each redirect URI must be a valid URL')
      .refine(
        (uri) => {
          const url = new URL(uri);
          return (
            url.protocol === 'https:' ||
            url.hostname === 'localhost' ||
            url.hostname === '127.0.0.1' ||
            uri.startsWith('http://localhost') ||
            uri.startsWith('http://127.0.0.1')
          );
        },
        { message: 'Redirect URIs must use HTTPS (or http://localhost for development)' }
      )
  )
  .min(1, 'At least one redirect URI is required');

// CORS origins (array, for public clients)
export const corsOriginsSchema = z
  .array(
    z
      .string()
      .url('Each CORS origin must be a valid URL')
      .refine(
        (origin) => {
          const url = new URL(origin);
          // Must be just the origin (no path, query, or fragment)
          return url.pathname === '/' && !url.search && !url.hash;
        },
        { message: 'CORS origins must be just the origin (e.g., https://example.com)' }
      )
  )
  .optional();

// Scopes (space-separated string or array)
export const allowedScopesSchema = z
  .string()
  .min(1, 'Allowed scopes are required')
  .regex(/^[a-zA-Z0-9_\-\s]+$/, 'Invalid scope format')
  .transform((val) => val.trim());

// Client name
export const clientNameSchema = z
  .string()
  .min(1, 'Client name is required')
  .max(255, 'Client name too long')
  .trim();

// URLs
export const urlSchema = z.string().url('Must be a valid URL').optional().or(z.literal(''));

// Email addresses (for contacts)
export const emailArraySchema = z.array(z.string().email('Invalid email format')).optional();

/**
 * Create Client Request
 * POST /admin/clients
 */
export const createClientRequestSchema = z
  .object({
    name: clientNameSchema,
    clientType: clientTypeSchema,
    organizationId: z.string().uuid().optional().or(z.literal('')),
    redirectUris: redirectUrisSchema,
    grantTypes: grantTypesSchema,
    allowedScopes: allowedScopesSchema,
    logoUrl: urlSchema,
    allowedCorsOrigins: corsOriginsSchema,
    termsUrl: urlSchema,
    privacyUrl: urlSchema,
    homepageUrl: urlSchema,
    contacts: emailArraySchema,
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
    (_data) => {
      // Public clients should have CORS origins if they're SPAs
      // This is a warning, not a hard requirement
      return true;
    },
    { message: 'Consider adding CORS origins for public clients' }
  );

export type CreateClientRequest = z.infer<typeof createClientRequestSchema>;

/**
 * Update Client Request
 * PUT /admin/clients/:id
 */
export const updateClientRequestSchema = z.object({
  name: clientNameSchema.optional(),
  redirectUris: redirectUrisSchema.optional(),
  grantTypes: grantTypesSchema.optional(),
  allowedScopes: allowedScopesSchema.optional(),
  logoUrl: urlSchema,
  allowedCorsOrigins: corsOriginsSchema,
  termsUrl: urlSchema,
  privacyUrl: urlSchema,
  homepageUrl: urlSchema,
  contacts: emailArraySchema,
  isActive: z.boolean().optional(),
});

export type UpdateClientRequest = z.infer<typeof updateClientRequestSchema>;

/**
 * Client List Query Parameters
 * GET /admin/clients
 */
export const clientListQuerySchema = z.object({
  organizationId: z.string().uuid().optional(),
  clientType: clientTypeSchema.optional(),
  isActive: z
    .string()
    .transform((val) => val === 'true')
    .optional(),
  page: z
    .string()
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().int().positive())
    .optional()
    .default(1),
  limit: z
    .string()
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().int().positive().max(100))
    .optional()
    .default(20),
});

export type ClientListQuery = z.infer<typeof clientListQuerySchema>;

/**
 * Client ID Parameter
 * GET /admin/clients/:id
 */
export const clientIdParamSchema = z.object({
  id: z.string().uuid('Invalid client ID format'),
});

export type ClientIdParam = z.infer<typeof clientIdParamSchema>;

/**
 * Regenerate Client Secret Request
 * POST /admin/clients/:id/secret
 */
export const regenerateSecretRequestSchema = z.object({
  confirmRegenerate: z.boolean().refine((val) => val === true, {
    message: 'You must confirm secret regeneration',
  }),
});

export type RegenerateSecretRequest = z.infer<typeof regenerateSecretRequestSchema>;
