import { z } from 'zod';

/**
 * OAuth 2.0 Validation Schemas
 * Using Zod for runtime type checking and validation
 */

// Response types
export const responseTypeSchema = z.enum(['code', 'token', 'id_token']);

// Grant types
export const grantTypeSchema = z.enum([
  'authorization_code',
  'refresh_token',
  'client_credentials',
  'password', // Not recommended, but included for completeness
]);

// Code challenge methods
export const codeChallengeMethodSchema = z.enum(['S256', 'plain']);

// Scopes (space-separated string)
export const scopeSchema = z
  .string()
  .min(1)
  .regex(/^[a-zA-Z0-9_\-\s]+$/, 'Invalid scope format')
  .transform((val) => val.trim());

// Redirect URI validation
export const redirectUriSchema = z
  .string()
  .url('Invalid redirect URI')
  .refine(
    (uri) => {
      // Must use https in production, or http://localhost for development
      const url = new URL(uri);
      return (
        url.protocol === 'https:' || url.hostname === 'localhost' || url.hostname === '127.0.0.1'
      );
    },
    { message: 'Redirect URI must use HTTPS (or http://localhost for development)' }
  );

// PKCE code verifier (43-128 characters, unreserved chars only)
export const codeVerifierSchema = z
  .string()
  .min(43, 'Code verifier must be at least 43 characters')
  .max(128, 'Code verifier must be at most 128 characters')
  .regex(/^[A-Za-z0-9._~-]+$/, 'Code verifier must contain only unreserved characters');

// PKCE code challenge (base64url encoded)
export const codeChallengeSchema = z
  .string()
  .min(43, 'Code challenge must be at least 43 characters')
  .regex(/^[A-Za-z0-9_-]+$/, 'Code challenge must be base64url encoded');

// Client ID format
export const clientIdSchema = z
  .string()
  .min(1, 'Client ID is required')
  .max(255, 'Client ID too long');

// Authorization code
export const authorizationCodeSchema = z.string().min(1, 'Authorization code is required');

// State parameter (CSRF protection)
export const stateSchema = z.optional(z.string().min(1).max(500));

// Nonce (for OIDC)
export const nonceSchema = z.optional(z.string().min(1).max(500));

/**
 * Authorization Request Validation
 * GET /oauth/authorize
 */
export const authorizeRequestSchema = z.object({
  response_type: responseTypeSchema,
  client_id: clientIdSchema,
  redirect_uri: redirectUriSchema,
  scope: scopeSchema,
  state: stateSchema,
  code_challenge: codeChallengeSchema,
  code_challenge_method: codeChallengeMethodSchema,
  nonce: nonceSchema,
});

export type AuthorizeRequest = z.infer<typeof authorizeRequestSchema>;

/**
 * Token Request - Authorization Code Grant
 * POST /oauth/token
 */
export const tokenRequestAuthCodeSchema = z.object({
  grant_type: z.literal('authorization_code'),
  code: authorizationCodeSchema,
  redirect_uri: redirectUriSchema,
  client_id: clientIdSchema,
  client_secret: z.optional(z.string()), // Required for confidential clients
  code_verifier: codeVerifierSchema,
});

export type TokenRequestAuthCode = z.infer<typeof tokenRequestAuthCodeSchema>;

/**
 * Token Request - Refresh Token Grant
 * POST /oauth/token
 */
export const tokenRequestRefreshSchema = z.object({
  grant_type: z.literal('refresh_token'),
  refresh_token: z.string().min(1),
  client_id: clientIdSchema,
  client_secret: z.optional(z.string()), // Required for confidential clients
  scope: z.optional(scopeSchema),
});

export type TokenRequestRefresh = z.infer<typeof tokenRequestRefreshSchema>;

/**
 * Token Request - Client Credentials Grant
 * POST /oauth/token
 */
export const tokenRequestClientCredentialsSchema = z.object({
  grant_type: z.literal('client_credentials'),
  client_id: clientIdSchema,
  client_secret: z.string().min(1),
  scope: z.optional(scopeSchema),
});

export type TokenRequestClientCredentials = z.infer<typeof tokenRequestClientCredentialsSchema>;

/**
 * Combined Token Request Schema
 */
export const tokenRequestSchema = z.discriminatedUnion('grant_type', [
  tokenRequestAuthCodeSchema,
  tokenRequestRefreshSchema,
  tokenRequestClientCredentialsSchema,
]);

export type TokenRequest = z.infer<typeof tokenRequestSchema>;

/**
 * Token Revocation Request
 * POST /oauth/revoke
 */
export const revokeRequestSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.optional(z.enum(['access_token', 'refresh_token'])),
  client_id: clientIdSchema,
  client_secret: z.optional(z.string()),
});

export type RevokeRequest = z.infer<typeof revokeRequestSchema>;

/**
 * Token Introspection Request
 * POST /oauth/introspect
 */
export const introspectRequestSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.optional(z.enum(['access_token', 'refresh_token'])),
  client_id: clientIdSchema,
  client_secret: z.string().min(1),
});

export type IntrospectRequest = z.infer<typeof introspectRequestSchema>;

/**
 * Consent Decision
 * POST /consent
 */
export const consentDecisionSchema = z.object({
  decision: z.enum(['allow', 'deny']),
  scope: z.optional(scopeSchema),
  remember: z.optional(z.boolean()),
});

export type ConsentDecision = z.infer<typeof consentDecisionSchema>;
