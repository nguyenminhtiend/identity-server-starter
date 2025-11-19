import { type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { type OAuthService } from '../services/OAuthService';
import { type TokenService } from '../services/TokenService';
import { type PKCEService } from '../services/PKCEService';

const authorizationCodeGrantSchema = z.object({
  grant_type: z.literal('authorization_code'),
  code: z.string().min(1),
  redirect_uri: z.string().url(),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
  code_verifier: z.string().min(43).max(128),
});

const refreshTokenGrantSchema = z.object({
  grant_type: z.literal('refresh_token'),
  refresh_token: z.string().min(1),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
  scope: z.string().optional(),
});

const clientCredentialsGrantSchema = z.object({
  grant_type: z.literal('client_credentials'),
  client_id: z.string().min(1),
  client_secret: z.string().min(1),
  scope: z.string().optional(),
});

export class TokenController {
  constructor(
    private oauthService: OAuthService,
    private tokenService: TokenService,
    private pkceService: PKCEService
  ) {}

  /**
   * POST /oauth/token
   * OAuth 2.0 Token Endpoint
   * Supports: authorization_code, refresh_token, client_credentials
   */
  async token(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { grant_type } = req.body;

      switch (grant_type) {
        case 'authorization_code':
          return await this.handleAuthorizationCodeGrant(req, res);
        case 'refresh_token':
          return await this.handleRefreshTokenGrant(req, res);
        case 'client_credentials':
          return await this.handleClientCredentialsGrant(req, res);
        default:
          return res.status(400).json({
            error: 'unsupported_grant_type',
            error_description: `Grant type '${grant_type}' is not supported`,
          });
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: error.errors.map((e) => e.message).join(', '),
        });
      }
      next(error);
    }
  }

  /**
   * Handle authorization_code grant type
   */
  private async handleAuthorizationCodeGrant(req: Request, res: Response): Promise<void> {
    const params = authorizationCodeGrantSchema.parse(req.body);

    // Validate client
    const client = await this.oauthService.validateClient(params.client_id);
    if (!client) {
      return res.status(400).json({
        error: 'invalid_client',
        error_description: 'Client not found',
      });
    }

    // Authenticate confidential clients
    if (client.client_type === 'confidential') {
      if (!params.client_secret) {
        return res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client secret is required for confidential clients',
        });
      }

      const isValidSecret = await this.oauthService.validateClientSecret(
        client.id,
        params.client_secret
      );

      if (!isValidSecret) {
        return res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client credentials',
        });
      }
    }

    // Retrieve and validate authorization code
    const authCode = await this.oauthService.getAuthorizationCode(params.code);
    if (!authCode) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code',
      });
    }

    // Check if code has already been used
    if (authCode.used_at) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Authorization code has already been used',
      });
    }

    // Check if code has expired
    if (new Date() > new Date(authCode.expires_at)) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Authorization code has expired',
      });
    }

    // Verify client matches
    if (authCode.client_id !== client.id) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Authorization code was issued to a different client',
      });
    }

    // Verify redirect_uri matches
    if (authCode.redirect_uri !== params.redirect_uri) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Redirect URI does not match',
      });
    }

    // Verify PKCE code_verifier
    const isValidVerifier = this.pkceService.verifyChallenge(
      params.code_verifier,
      authCode.code_challenge,
      authCode.code_challenge_method as 'S256'
    );

    if (!isValidVerifier) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid PKCE code_verifier',
      });
    }

    // Mark code as used
    await this.oauthService.markAuthorizationCodeAsUsed(authCode.id);

    // Generate access token
    const accessToken = await this.tokenService.generateAccessToken({
      userId: authCode.user_id,
      clientId: client.id,
      scope: authCode.scope,
    });

    // Generate refresh token
    const refreshToken = await this.oauthService.generateRefreshToken({
      userId: authCode.user_id,
      clientId: client.id,
      scope: authCode.scope,
    });

    // Generate ID token if openid scope is requested
    let idToken: string | undefined;
    if (authCode.scope.includes('openid')) {
      idToken = await this.tokenService.generateIdToken({
        userId: authCode.user_id,
        clientId: client.id,
        scope: authCode.scope,
      });
    }

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes
      refresh_token: refreshToken,
      ...(idToken && { id_token: idToken }),
      scope: authCode.scope,
    });
  }

  /**
   * Handle refresh_token grant type
   */
  private async handleRefreshTokenGrant(req: Request, res: Response): Promise<void> {
    const params = refreshTokenGrantSchema.parse(req.body);

    // Validate client
    const client = await this.oauthService.validateClient(params.client_id);
    if (!client) {
      return res.status(400).json({
        error: 'invalid_client',
        error_description: 'Client not found',
      });
    }

    // Authenticate confidential clients
    if (client.client_type === 'confidential') {
      if (!params.client_secret) {
        return res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client secret is required for confidential clients',
        });
      }

      const isValidSecret = await this.oauthService.validateClientSecret(
        client.id,
        params.client_secret
      );

      if (!isValidSecret) {
        return res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client credentials',
        });
      }
    }

    // Validate and rotate refresh token
    const tokenData = await this.oauthService.validateAndRotateRefreshToken(
      params.refresh_token,
      client.id
    );

    if (!tokenData) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired refresh token',
      });
    }

    // Use requested scope or fall back to original scope
    const scope = params.scope || tokenData.scope;

    // Validate that requested scope is not broader than original
    if (params.scope && !this.oauthService.isScopeSubset(params.scope, tokenData.scope)) {
      return res.status(400).json({
        error: 'invalid_scope',
        error_description: 'Requested scope is broader than original scope',
      });
    }

    // Generate new access token
    const accessToken = await this.tokenService.generateAccessToken({
      userId: tokenData.userId,
      clientId: client.id,
      scope,
    });

    // Generate ID token if openid scope is present
    let idToken: string | undefined;
    if (scope.includes('openid')) {
      idToken = await this.tokenService.generateIdToken({
        userId: tokenData.userId,
        clientId: client.id,
        scope,
      });
    }

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes
      refresh_token: tokenData.newRefreshToken,
      ...(idToken && { id_token: idToken }),
      scope,
    });
  }

  /**
   * Handle client_credentials grant type
   */
  private async handleClientCredentialsGrant(req: Request, res: Response): Promise<void> {
    const params = clientCredentialsGrantSchema.parse(req.body);

    // Validate client
    const client = await this.oauthService.validateClient(params.client_id);
    if (!client) {
      return res.status(400).json({
        error: 'invalid_client',
        error_description: 'Client not found',
      });
    }

    // Only confidential clients can use client_credentials grant
    if (client.client_type !== 'confidential') {
      return res.status(400).json({
        error: 'unauthorized_client',
        error_description: 'Client is not authorized to use this grant type',
      });
    }

    // Validate client credentials
    const isValidSecret = await this.oauthService.validateClientSecret(
      client.id,
      params.client_secret
    );

    if (!isValidSecret) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials',
      });
    }

    const scope = params.scope || client.allowed_scopes;

    // Generate access token (no user context)
    const accessToken = await this.tokenService.generateAccessToken({
      clientId: client.id,
      scope,
    });

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes
      scope,
    });
  }
}
