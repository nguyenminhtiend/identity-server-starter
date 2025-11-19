import * as jose from 'jose';
import type { IKeyManagementService } from '../../key-management/services/interfaces/key-management-service.interface.js';
import type { ITokenService } from './interfaces/token-service.interface.js';

/**
 * JWT Token Payload (standard claims)
 */
export interface TokenPayload {
  sub: string; // Subject (user ID)
  iss: string; // Issuer
  aud: string | string[]; // Audience (client ID)
  exp: number; // Expiration time (Unix timestamp)
  iat: number; // Issued at (Unix timestamp)
  scope: string; // OAuth scopes
  client_id: string; // Client ID
  email?: string; // User email (optional)
  email_verified?: boolean; // Email verification status (optional)
}

/**
 * ID Token Payload (OIDC claims)
 */
export interface IDTokenPayload extends TokenPayload {
  nonce?: string; // Nonce from authorization request
  auth_time?: number; // Time when authentication occurred
  azp?: string; // Authorized party (client ID)
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
 * User info for token generation
 */
export interface UserInfo {
  id: string;
  email: string;
  emailVerified: boolean;
}

/**
 * Token Service
 * Handles JWT access token and ID token generation, signing, and verification
 * - Uses RS256 signing with database-stored keys
 * - Includes kid (key ID) header for key rotation support
 * - Supports OIDC ID tokens
 */
export class TokenService implements ITokenService {
  private keyManagementService: IKeyManagementService;
  private issuer: string;

  constructor(issuer: string, keyManagementService: IKeyManagementService) {
    this.issuer = issuer;
    this.keyManagementService = keyManagementService;
  }

  /**
   * Generate a JWT access token
   * @param user - User information
   * @param clientId - OAuth client ID
   * @param scope - Granted scopes
   * @param ttlSeconds - Token time-to-live in seconds (default: 900 = 15 min)
   * @returns Signed JWT access token
   */
  async generateAccessToken(
    user: UserInfo,
    clientId: string,
    scope: string,
    ttlSeconds = 900
  ): Promise<string> {
    // Get primary signing key
    const signingKey = await this.keyManagementService.getPrimarySigningKey();

    // Import private key
    const privateKey = await jose.importPKCS8(signingKey.privateKey, signingKey.algorithm);

    // Current time
    const now = Math.floor(Date.now() / 1000);

    // Create JWT payload
    const payload: TokenPayload = {
      sub: user.id,
      iss: this.issuer,
      aud: clientId,
      exp: now + ttlSeconds,
      iat: now,
      scope,
      client_id: clientId,
    };

    // Sign JWT with kid header
    const jwt = await new jose.SignJWT(payload as jose.JWTPayload)
      .setProtectedHeader({
        alg: signingKey.algorithm,
        typ: 'JWT',
        kid: signingKey.keyId, // Include key ID for rotation support
      })
      .setIssuedAt(now)
      .setExpirationTime(now + ttlSeconds)
      .setIssuer(this.issuer)
      .setSubject(user.id)
      .setAudience(clientId)
      .sign(privateKey);

    return jwt;
  }

  /**
   * Generate an OIDC ID token
   * @param user - User information
   * @param clientId - OAuth client ID
   * @param scope - Granted scopes
   * @param nonce - Nonce from authorization request (optional)
   * @param ttlSeconds - Token time-to-live in seconds (default: 3600 = 1 hour)
   * @returns Signed JWT ID token
   */
  async generateIDToken(
    user: UserInfo,
    clientId: string,
    scope: string,
    nonce?: string,
    ttlSeconds = 3600
  ): Promise<string> {
    // Get primary signing key
    const signingKey = await this.keyManagementService.getPrimarySigningKey();

    // Import private key
    const privateKey = await jose.importPKCS8(signingKey.privateKey, signingKey.algorithm);

    // Current time
    const now = Math.floor(Date.now() / 1000);

    // Parse scopes to determine which claims to include
    const scopes = scope.split(' ');
    const includeEmail = scopes.includes('email');
    // const _includeProfile = scopes.includes('profile'); // TODO: implement profile claims

    // Create ID token payload
    const payload: IDTokenPayload = {
      sub: user.id,
      iss: this.issuer,
      aud: clientId,
      exp: now + ttlSeconds,
      iat: now,
      scope,
      client_id: clientId,
      auth_time: now,
      azp: clientId,
    };

    // Add nonce if provided
    if (nonce) {
      payload.nonce = nonce;
    }

    // Add email claims if requested
    if (includeEmail) {
      payload.email = user.email;
      payload.email_verified = user.emailVerified;
    }

    // Sign JWT with kid header
    const jwt = await new jose.SignJWT(payload as jose.JWTPayload)
      .setProtectedHeader({
        alg: signingKey.algorithm,
        typ: 'JWT',
        kid: signingKey.keyId, // Include key ID for rotation support
      })
      .setIssuedAt(now)
      .setExpirationTime(now + ttlSeconds)
      .setIssuer(this.issuer)
      .setSubject(user.id)
      .setAudience(clientId)
      .sign(privateKey);

    return jwt;
  }

  /**
   * Verify a JWT token signature and claims
   * @param token - JWT token to verify
   * @param expectedAudience - Expected audience (client ID)
   * @returns Verification result with payload
   */
  async verifyToken(token: string, expectedAudience?: string): Promise<TokenVerificationResult> {
    try {
      // Decode header to get kid
      const decodedHeader = jose.decodeProtectedHeader(token);
      const kid = decodedHeader.kid;

      if (!kid) {
        return {
          valid: false,
          error: 'Token missing kid (key ID) header',
        };
      }

      // Get signing key by kid
      const signingKey = await this.keyManagementService.getKeyById(kid);

      if (!signingKey) {
        return {
          valid: false,
          error: `Unknown key ID: ${kid}`,
        };
      }

      // Import public key
      const publicKey = await jose.importSPKI(signingKey.publicKey, signingKey.algorithm);

      // Verify JWT
      const { payload } = await jose.jwtVerify(token, publicKey, {
        issuer: this.issuer,
        audience: expectedAudience,
      });

      return {
        valid: true,
        payload,
      };
    } catch (error) {
      if (error instanceof Error) {
        return {
          valid: false,
          error: error.message,
        };
      }

      return {
        valid: false,
        error: 'Unknown verification error',
      };
    }
  }

  /**
   * Decode a JWT token without verification (for inspection only)
   * WARNING: Do not use for authentication - always verify first!
   * @param token - JWT token to decode
   * @returns Decoded payload or null if invalid
   */
  decodeToken(token: string): jose.JWTPayload | null {
    try {
      return jose.decodeJwt(token);
    } catch {
      return null;
    }
  }

  /**
   * Extract user ID from a verified token
   * @param token - JWT token
   * @returns User ID (sub claim) or null
   */
  async extractUserId(token: string): Promise<string | null> {
    const result = await this.verifyToken(token);
    if (!result.valid || !result.payload) {
      return null;
    }

    return result.payload.sub ?? null;
  }

  /**
   * Extract client ID from a verified token
   * @param token - JWT token
   * @returns Client ID or null
   */
  async extractClientId(token: string): Promise<string | null> {
    const result = await this.verifyToken(token);
    if (!result.valid || result.payload === undefined) {
      return null;
    }

    const payload = result.payload as { client_id?: string };
    return payload.client_id ?? null;
  }

  /**
   * Extract scopes from a verified token
   * @param token - JWT token
   * @returns Array of scopes or empty array
   */
  async extractScopes(token: string): Promise<string[]> {
    const result = await this.verifyToken(token);
    if (!result.valid || result.payload === undefined) {
      return [];
    }

    const payload = result.payload as { scope?: string };
    const scope = payload.scope ?? '';
    return scope.split(' ').filter((s: string) => s.length > 0);
  }

  /**
   * Check if token has a specific scope
   * @param token - JWT token
   * @param requiredScope - Required scope to check
   * @returns True if token has the scope
   */
  async hasScope(token: string, requiredScope: string): Promise<boolean> {
    const scopes = await this.extractScopes(token);
    return scopes.includes(requiredScope);
  }

  /**
   * Get user info from a verified token
   * @param token - JWT token
   * @returns User info object or null
   */
  async getUserInfo(token: string): Promise<Partial<UserInfo> | null> {
    const result = await this.verifyToken(token);
    if (!result.valid || result.payload === undefined) {
      return null;
    }

    const payload = result.payload as { sub?: string; email?: string; email_verified?: boolean };

    return {
      id: payload.sub,
      email: payload.email,
      emailVerified: payload.email_verified,
    };
  }
}
