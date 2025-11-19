import type * as jose from 'jose';

/**
 * User info for token generation
 */
export interface UserInfo {
  id: string;
  email: string;
  emailVerified: boolean;
}

/**
 * Token verification result
 */
export interface TokenVerificationResult {
  valid: boolean;
  payload?: jose.JWTPayload;
  error?: string;
}

/**
 * Token Service Interface
 * Handles JWT access token and ID token generation, signing, and verification
 */
export interface ITokenService {
  /**
   * Generate a JWT access token
   * @param user - User information
   * @param clientId - OAuth client ID
   * @param scope - Granted scopes
   * @param ttlSeconds - Token time-to-live in seconds (default: 900 = 15 min)
   * @returns Signed JWT access token
   */
  generateAccessToken(
    user: UserInfo,
    clientId: string,
    scope: string,
    ttlSeconds?: number
  ): Promise<string>;

  /**
   * Generate an OIDC ID token
   * @param user - User information
   * @param clientId - OAuth client ID
   * @param scope - Granted scopes
   * @param nonce - Nonce from authorization request (optional)
   * @param ttlSeconds - Token time-to-live in seconds (default: 3600 = 1 hour)
   * @returns Signed JWT ID token
   */
  generateIDToken(
    user: UserInfo,
    clientId: string,
    scope: string,
    nonce?: string,
    ttlSeconds?: number
  ): Promise<string>;

  /**
   * Verify a JWT token signature and claims
   * @param token - JWT token to verify
   * @param expectedAudience - Expected audience (client ID)
   * @returns Verification result with payload
   */
  verifyToken(token: string, expectedAudience?: string): Promise<TokenVerificationResult>;

  /**
   * Decode a JWT token without verification (for inspection only)
   * WARNING: Do not use for authentication - always verify first!
   * @param token - JWT token to decode
   * @returns Decoded payload or null if invalid
   */
  decodeToken(token: string): jose.JWTPayload | null;

  /**
   * Extract user ID from a verified token
   * @param token - JWT token
   * @returns User ID (sub claim) or null
   */
  extractUserId(token: string): Promise<string | null>;

  /**
   * Extract client ID from a verified token
   * @param token - JWT token
   * @returns Client ID or null
   */
  extractClientId(token: string): Promise<string | null>;

  /**
   * Extract scopes from a verified token
   * @param token - JWT token
   * @returns Array of scopes or empty array
   */
  extractScopes(token: string): Promise<string[]>;

  /**
   * Check if token has a specific scope
   * @param token - JWT token
   * @param requiredScope - Required scope to check
   * @returns True if token has the scope
   */
  hasScope(token: string, requiredScope: string): Promise<boolean>;

  /**
   * Get user info from a verified token
   * @param token - JWT token
   * @returns User info object or null
   */
  getUserInfo(token: string): Promise<Partial<UserInfo> | null>;
}
