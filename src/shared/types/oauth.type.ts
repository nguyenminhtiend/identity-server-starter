import type { JWTPayload } from 'jose';

/**
 * Extended JWT Payload for OAuth/OIDC tokens
 */
export interface OAuthJWTPayload extends JWTPayload {
  sub: string; // Subject (user ID)
  iss: string; // Issuer
  aud: string | string[]; // Audience (client ID)
  exp: number; // Expiration time (Unix timestamp)
  iat: number; // Issued at (Unix timestamp)
  scope?: string; // OAuth scopes
  client_id?: string; // Client ID
  email?: string; // User email (optional)
  email_verified?: boolean; // Email verification status (optional)
  nonce?: string; // Nonce from authorization request
  auth_time?: number; // Time when authentication occurred
  azp?: string; // Authorized party (client ID)
}

/**
 * Refresh token data from database
 */
export interface RefreshTokenData {
  token: string;
  client_id: string;
  user_id: string;
  scope: string;
  expires_at: Date | string;
  created_at: Date | string;
  revoked: boolean;
}

/**
 * Authorization request stored in session
 */
export interface AuthorizationRequest {
  client_id: string;
  redirect_uri: string;
  scope: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  response_type?: string;
  nonce?: string;
}

/**
 * Zod validation error structure
 */
export interface ZodValidationError {
  path: (string | number)[];
  message: string;
}

/**
 * Custom error with status code
 */
export interface ErrorWithStatus extends Error {
  statusCode?: number;
}
