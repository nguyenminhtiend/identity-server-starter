import { eq, and } from 'drizzle-orm';
import {
  db,
  clients,
  authorizationCodes,
  refreshTokens,
  consents,
  users,
} from '../../../shared/database/index.js';
import {
  generateRandomToken,
  sha256Hash,
  verifyPassword,
  constantTimeCompare as _constantTimeCompare,
} from '../../../shared/utils/crypto.util.js';
import { PKCEService } from './pkce.service.js';
import type { UserInfo } from './token.service.js';
import type { ITokenService } from './interfaces/token-service.interface.js';
import type {
  IOAuthService,
  OAuthClient,
  TokenResponse,
} from './interfaces/oauth-service.interface.js';

/**
 * Authorization code record
 */
export interface AuthorizationCode {
  id: string;
  code: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  expiresAt: Date;
  usedAt: Date | null;
}

/**
 * OAuth Service
 * Handles OAuth 2.0 authorization flow logic
 * - Client validation and authentication
 * - Authorization code generation and exchange
 * - Refresh token rotation
 * - Consent management
 */
export class OAuthService implements IOAuthService {
  private tokenService: ITokenService;

  constructor(tokenService: ITokenService) {
    this.tokenService = tokenService;
  }

  /**
   * Validate and retrieve a client by client_id
   * @param clientId - OAuth client ID
   * @returns Client record or null if not found
   */
  async getClient(clientId: string): Promise<OAuthClient | null> {
    const [client] = await db
      .select()
      .from(clients)
      .where(and(eq(clients.clientId, clientId), eq(clients.isActive, true)))
      .limit(1);

    return client ?? null;
  }

  /**
   * Validate client credentials (for confidential clients)
   * @param clientId - OAuth client ID
   * @param clientSecret - Client secret
   * @returns True if credentials are valid
   */
  async validateClientCredentials(clientId: string, clientSecret: string): Promise<boolean> {
    const client = await this.getClient(clientId);

    if (!client) {
      return false;
    }

    // Public clients don't have secrets
    if (client.clientType === 'public') {
      return false;
    }

    // Confidential clients must provide valid secret
    if (!client.clientSecretHash || !clientSecret) {
      return false;
    }

    // Verify secret using constant-time comparison
    return verifyPassword(clientSecret, client.clientSecretHash);
  }

  /**
   * Validate redirect URI against client's registered URIs
   * @param client - OAuth client
   * @param redirectUri - Redirect URI to validate
   * @returns True if redirect URI is valid
   */
  validateRedirectUri(client: OAuthClient, redirectUri: string): boolean {
    if (!redirectUri) {
      return false;
    }

    // Check if redirect URI matches any registered URI (exact match)
    return client.redirectUris.includes(redirectUri);
  }

  /**
   * Validate requested scopes against client's allowed scopes
   * @param client - OAuth client
   * @param requestedScopes - Requested scope string
   * @returns Array of valid scopes
   */
  validateScopes(client: OAuthClient, requestedScopes: string): string[] {
    const allowedScopes = client.allowedScopes.split(' ').filter((s) => s.length > 0);
    const requested = requestedScopes.split(' ').filter((s) => s.length > 0);

    // Return only scopes that are both requested and allowed
    return requested.filter((scope) => allowedScopes.includes(scope));
  }

  /**
   * Check if user has granted consent for client and scopes
   * @param userId - User ID
   * @param clientId - Client UUID (not client_id string)
   * @param scope - Requested scopes
   * @returns True if consent exists
   */
  async hasConsent(userId: string, clientId: string, scope: string): Promise<boolean> {
    const [consent] = await db
      .select()
      .from(consents)
      .where(and(eq(consents.userId, userId), eq(consents.clientId, clientId)))
      .limit(1);

    if (!consent) {
      return false;
    }

    // Check if all requested scopes are in granted consent
    const requestedScopes = scope.split(' ');
    const grantedScopes = consent.scope.split(' ');

    return requestedScopes.every((s) => grantedScopes.includes(s));
  }

  /**
   * Grant consent for a client and scopes
   * @param userId - User ID
   * @param clientId - Client UUID
   * @param scope - Granted scopes
   */
  async grantConsent(userId: string, clientId: string, scope: string): Promise<void> {
    // Upsert consent (insert or update if exists)
    await db
      .insert(consents)
      .values({
        userId,
        clientId,
        scope,
      })
      .onConflictDoUpdate({
        target: [consents.userId, consents.clientId],
        set: {
          scope,
          grantedAt: new Date(),
        },
      });
  }

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
  async createAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scope: string,
    codeChallenge: string,
    codeChallengeMethod: string,
    ttlSeconds = 600
  ): Promise<string> {
    // Generate secure authorization code
    const code = generateRandomToken(32);

    // Calculate expiration
    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + ttlSeconds);

    // Store authorization code
    await db.insert(authorizationCodes).values({
      code,
      clientId,
      userId,
      redirectUri,
      scope,
      codeChallenge,
      codeChallengeMethod,
      expiresAt,
    });

    return code;
  }

  /**
   * Exchange authorization code for tokens
   * @param code - Authorization code
   * @param clientId - Client ID string
   * @param redirectUri - Redirect URI (must match original)
   * @param codeVerifier - PKCE code verifier
   * @returns Token response
   */
  async exchangeAuthorizationCode(
    code: string,
    clientId: string,
    redirectUri: string,
    codeVerifier: string
  ): Promise<TokenResponse | null> {
    // Retrieve authorization code
    const [authCode] = await db
      .select()
      .from(authorizationCodes)
      .where(eq(authorizationCodes.code, code))
      .limit(1);

    if (!authCode) {
      throw new Error('Invalid authorization code');
    }

    // Check if already used
    if (authCode.usedAt) {
      throw new Error('Authorization code already used');
    }

    // Check if expired
    if (new Date() > authCode.expiresAt) {
      throw new Error('Authorization code expired');
    }

    // Get client
    const client = await this.getClient(clientId);
    if (!client || client.id !== authCode.clientId) {
      throw new Error('Client mismatch');
    }

    // Validate redirect URI
    if (authCode.redirectUri !== redirectUri) {
      throw new Error('Redirect URI mismatch');
    }

    // Verify PKCE
    const pkceResult = PKCEService.verify(
      codeVerifier,
      authCode.codeChallenge,
      authCode.codeChallengeMethod as 'S256'
    );

    if (!pkceResult.valid) {
      throw new Error(pkceResult.error ?? 'PKCE verification failed');
    }

    // Mark code as used
    await db
      .update(authorizationCodes)
      .set({ usedAt: new Date() })
      .where(eq(authorizationCodes.id, authCode.id));

    // Get user
    const [user] = await db.select().from(users).where(eq(users.id, authCode.userId)).limit(1);

    if (!user) {
      throw new Error('User not found');
    }

    // Generate tokens
    const userInfo: UserInfo = {
      id: user.id,
      email: user.email,
      emailVerified: user.emailVerified,
    };

    const accessToken = await this.tokenService.generateAccessToken(
      userInfo,
      clientId,
      authCode.scope
    );

    // Generate refresh token
    const refreshToken = await this.createRefreshToken(client.id, user.id, authCode.scope);

    // Generate ID token if openid scope is requested
    let idToken: string | undefined;
    if (authCode.scope.includes('openid')) {
      idToken = await this.tokenService.generateIDToken(userInfo, clientId, authCode.scope);
    }

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes
      refresh_token: refreshToken,
      id_token: idToken,
      scope: authCode.scope,
    };
  }

  /**
   * Create a refresh token
   * @param clientId - Client UUID
   * @param userId - User ID
   * @param scope - Granted scopes
   * @param ttlSeconds - Token time-to-live (default: 2592000 = 30 days)
   * @returns Refresh token string
   */
  async createRefreshToken(
    clientId: string,
    userId: string,
    scope: string,
    ttlSeconds = 2592000
  ): Promise<string> {
    // Generate refresh token
    const token = generateRandomToken(48);
    const tokenHash = sha256Hash(token);

    // Calculate expiration
    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + ttlSeconds);

    // Store refresh token
    await db.insert(refreshTokens).values({
      tokenHash,
      clientId,
      userId,
      scope,
      expiresAt,
      revoked: false,
    });

    return token;
  }

  /**
   * Rotate refresh token (exchange old for new)
   * @param token - Current refresh token
   * @param clientId - Client ID string
   * @returns Token response with new tokens
   */
  async rotateRefreshToken(token: string, clientId: string): Promise<TokenResponse | null> {
    const tokenHash = sha256Hash(token);

    // Retrieve refresh token
    const [refreshToken] = await db
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.tokenHash, tokenHash))
      .limit(1);

    if (!refreshToken) {
      throw new Error('Invalid refresh token');
    }

    // Check if revoked
    if (refreshToken.revoked) {
      throw new Error('Refresh token revoked');
    }

    // Check if expired
    if (new Date() > refreshToken.expiresAt) {
      throw new Error('Refresh token expired');
    }

    // Get client
    const client = await this.getClient(clientId);
    if (!client || client.id !== refreshToken.clientId) {
      throw new Error('Client mismatch');
    }

    // Get user
    const [user] = await db.select().from(users).where(eq(users.id, refreshToken.userId)).limit(1);

    if (!user) {
      throw new Error('User not found');
    }

    // Revoke old refresh token
    await db
      .update(refreshTokens)
      .set({ revoked: true })
      .where(eq(refreshTokens.id, refreshToken.id));

    // Generate new tokens
    const userInfo: UserInfo = {
      id: user.id,
      email: user.email,
      emailVerified: user.emailVerified,
    };

    const accessToken = await this.tokenService.generateAccessToken(
      userInfo,
      clientId,
      refreshToken.scope
    );

    // Generate new refresh token with rotation tracking
    const newRefreshToken = await this.createRefreshToken(client.id, user.id, refreshToken.scope);

    // Update new refresh token with previous token hash for audit trail
    await db
      .update(refreshTokens)
      .set({ previousTokenHash: tokenHash })
      .where(eq(refreshTokens.tokenHash, sha256Hash(newRefreshToken)));

    // Generate ID token if openid scope is requested
    let idToken: string | undefined;
    if (refreshToken.scope.includes('openid')) {
      idToken = await this.tokenService.generateIDToken(userInfo, clientId, refreshToken.scope);
    }

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes
      refresh_token: newRefreshToken,
      id_token: idToken,
      scope: refreshToken.scope,
    };
  }

  /**
   * Get refresh token data by token string
   * @param token - Refresh token string
   * @returns Refresh token data or null
   */
  async getRefreshToken(token: string): Promise<{
    token: string;
    client_id: string;
    user_id: string;
    scope: string;
    expires_at: Date;
    created_at: Date;
    revoked: boolean;
  } | null> {
    const tokenHash = sha256Hash(token);

    const [refreshToken] = await db
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.tokenHash, tokenHash))
      .limit(1);

    if (!refreshToken) {
      return null;
    }

    return {
      token,
      client_id: refreshToken.clientId,
      user_id: refreshToken.userId,
      scope: refreshToken.scope,
      expires_at: refreshToken.expiresAt,
      created_at: refreshToken.createdAt,
      revoked: refreshToken.revoked,
    };
  }

  /**
   * Revoke a refresh token
   * @param token - Refresh token to revoke
   */
  async revokeRefreshToken(token: string): Promise<void> {
    const tokenHash = sha256Hash(token);

    await db
      .update(refreshTokens)
      .set({ revoked: true })
      .where(eq(refreshTokens.tokenHash, tokenHash));
  }

  /**
   * Revoke a token (refresh token or access token)
   * @param token - Token to revoke
   * @param clientId - Client UUID
   * @param tokenTypeHint - Token type hint
   */
  async revokeToken(token: string, _clientId: string, tokenTypeHint?: string): Promise<void> {
    // For now, we only support revoking refresh tokens
    // Access tokens (JWTs) are stateless and cannot be revoked
    // In a production system, you might maintain a revocation list
    if (tokenTypeHint === 'access_token') {
      // Access tokens can't be revoked (they're stateless JWTs)
      // In production, implement a token revocation list if needed
      return;
    }

    // Try to revoke as refresh token
    await this.revokeRefreshToken(token);
  }

  /**
   * Validate client secret for a given client
   * @param clientId - Client UUID (not client_id string)
   * @param clientSecret - Client secret to validate
   * @returns True if secret is valid
   */
  async validateClientSecret(clientId: string, clientSecret: string): Promise<boolean> {
    const [client] = await db
      .select()
      .from(clients)
      .where(and(eq(clients.id, clientId), eq(clients.isActive, true)))
      .limit(1);

    if (!client?.clientSecretHash) {
      return false;
    }

    return verifyPassword(clientSecret, client.clientSecretHash);
  }

  /**
   * Validate grant type for a client
   * @param client - OAuth client
   * @param grantType - Requested grant type
   * @returns True if grant type is allowed
   */
  validateGrantType(client: OAuthClient, grantType: string): boolean {
    return client.grantTypes.includes(grantType);
  }

  /**
   * Check if client is public (requires PKCE)
   * @param client - OAuth client
   * @returns True if client is public
   */
  isPublicClient(client: OAuthClient): boolean {
    return client.clientType === 'public';
  }

  /**
   * Check if client is confidential (has client_secret)
   * @param client - OAuth client
   * @returns True if client is confidential
   */
  isConfidentialClient(client: OAuthClient): boolean {
    return client.clientType === 'confidential';
  }
}
