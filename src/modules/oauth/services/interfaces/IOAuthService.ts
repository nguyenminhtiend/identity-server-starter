/**
 * OAuth Client record
 */
export interface OAuthClient {
  id: string;
  clientId: string;
  clientSecretHash: string | null;
  name: string;
  clientType: string;
  organizationId: string | null;
  redirectUris: string[];
  grantTypes: string[];
  allowedScopes: string;
  logoUrl: string | null;
  allowedCorsOrigins: string[] | null;
  termsUrl: string | null;
  privacyUrl: string | null;
  homepageUrl: string | null;
  contacts: string[] | null;
  isActive: boolean;
}

/**
 * Token generation result
 */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope: string;
}

/**
 * OAuth Service Interface
 * Handles OAuth 2.0 authorization flow logic
 */
export interface IOAuthService {
  /**
   * Validate and retrieve a client by client_id
   * @param clientId - OAuth client ID
   * @returns Client record or null if not found
   */
  getClient(clientId: string): Promise<OAuthClient | null>;

  /**
   * Validate client credentials (for confidential clients)
   * @param clientId - OAuth client ID
   * @param clientSecret - Client secret
   * @returns True if credentials are valid
   */
  validateClientCredentials(clientId: string, clientSecret: string): Promise<boolean>;

  /**
   * Validate redirect URI against client's registered URIs
   * @param client - OAuth client
   * @param redirectUri - Redirect URI to validate
   * @returns True if redirect URI is valid
   */
  validateRedirectUri(client: OAuthClient, redirectUri: string): boolean;

  /**
   * Validate requested scopes against client's allowed scopes
   * @param client - OAuth client
   * @param requestedScopes - Requested scope string
   * @returns Array of valid scopes
   */
  validateScopes(client: OAuthClient, requestedScopes: string): string[];

  /**
   * Check if user has granted consent for client and scopes
   * @param userId - User ID
   * @param clientId - Client UUID (not client_id string)
   * @param scope - Requested scopes
   * @returns True if consent exists
   */
  hasConsent(userId: string, clientId: string, scope: string): Promise<boolean>;

  /**
   * Grant consent for a client and scopes
   * @param userId - User ID
   * @param clientId - Client UUID
   * @param scope - Granted scopes
   */
  grantConsent(userId: string, clientId: string, scope: string): Promise<void>;

  /**
   * Create an authorization code
   * @param clientId - Client UUID
   * @param userId - User ID
   * @param redirectUri - Redirect URI
   * @param scope - Granted scopes
   * @param codeChallenge - PKCE code challenge
   * @param codeChallengeMethod - PKCE method (S256)
   * @param ttlSeconds - Code time-to-live (default: 600 = 10 min)
   * @returns Authorization code string
   */
  createAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scope: string,
    codeChallenge: string,
    codeChallengeMethod: string,
    ttlSeconds?: number
  ): Promise<string>;

  /**
   * Exchange authorization code for tokens
   * @param code - Authorization code
   * @param clientId - Client ID string
   * @param redirectUri - Redirect URI (must match original)
   * @param codeVerifier - PKCE code verifier
   * @returns Token response
   */
  exchangeAuthorizationCode(
    code: string,
    clientId: string,
    redirectUri: string,
    codeVerifier: string
  ): Promise<TokenResponse | null>;

  /**
   * Create a refresh token
   * @param clientId - Client UUID
   * @param userId - User ID
   * @param scope - Granted scopes
   * @param ttlSeconds - Token time-to-live (default: 2592000 = 30 days)
   * @returns Refresh token string
   */
  createRefreshToken(
    clientId: string,
    userId: string,
    scope: string,
    ttlSeconds?: number
  ): Promise<string>;

  /**
   * Rotate refresh token (exchange old for new)
   * @param token - Current refresh token
   * @param clientId - Client ID string
   * @returns Token response with new tokens
   */
  rotateRefreshToken(token: string, clientId: string): Promise<TokenResponse | null>;

  /**
   * Revoke a token (refresh token or access token)
   * @param token - Token to revoke
   * @param clientId - Client UUID
   * @param tokenTypeHint - Token type hint
   */
  revokeToken(token: string, clientId: string, tokenTypeHint?: string): Promise<void>;

  /**
   * Validate grant type for a client
   * @param client - OAuth client
   * @param grantType - Requested grant type
   * @returns True if grant type is allowed
   */
  validateGrantType(client: OAuthClient, grantType: string): boolean;

  /**
   * Check if client is public (requires PKCE)
   * @param client - OAuth client
   * @returns True if client is public
   */
  isPublicClient(client: OAuthClient): boolean;

  /**
   * Check if client is confidential (has client_secret)
   * @param client - OAuth client
   * @returns True if client is confidential
   */
  isConfidentialClient(client: OAuthClient): boolean;

  /**
   * Validate client secret for a given client
   * @param clientId - Client UUID (not client_id string)
   * @param clientSecret - Client secret to validate
   * @returns True if secret is valid
   */
  validateClientSecret(clientId: string, clientSecret: string): Promise<boolean>;

  /**
   * Get refresh token data by token string
   * @param token - Refresh token string
   * @returns Refresh token data or null
   */
  getRefreshToken(token: string): Promise<{
    token: string;
    client_id: string;
    user_id: string;
    scope: string;
    expires_at: Date;
    created_at: Date;
    revoked: boolean;
  } | null>;
}
