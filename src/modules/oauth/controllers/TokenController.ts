import { type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { type OAuthService } from '../services/OAuthService';
import { type TokenService } from '../services/TokenService';

const authorizationCodeGrantSchema = z.object({
  grant_type: z.literal('authorization_code'),
  code: z.string().min(1),
  redirect_uri: z.string().url(),
  client_id: z.string().min(1),
  client_secret: z.optional(z.string()),
  code_verifier: z.string().min(43).max(128),
});

const refreshTokenGrantSchema = z.object({
  grant_type: z.literal('refresh_token'),
  refresh_token: z.string().min(1),
  client_id: z.string().min(1),
  client_secret: z.optional(z.string()),
  scope: z.optional(z.string()),
});

const clientCredentialsGrantSchema = z.object({
  grant_type: z.literal('client_credentials'),
  client_id: z.string().min(1),
  client_secret: z.string().min(1),
  scope: z.optional(z.string()),
});

export class TokenController {
  constructor(
    private oauthService: OAuthService,
    private tokenService: TokenService
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
          res.status(400).json({
            error: 'unsupported_grant_type',
            error_description: `Grant type '${grant_type}' is not supported`,
          });
          return;
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: error.issues.map((e) => e.message).join(', '),
        });
        return;
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
    const client = await this.oauthService.getClient(params.client_id);
    if (client === null) {
      res.status(400).json({
        error: 'invalid_client',
        error_description: 'Client not found',
      });
      return;
    }

    // Authenticate confidential clients
    if (this.oauthService.isConfidentialClient(client)) {
      if (!params.client_secret) {
        res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client secret is required for confidential clients',
        });
        return;
      }

      const isValidSecret = await this.oauthService.validateClientCredentials(
        params.client_id,
        params.client_secret
      );

      if (isValidSecret === false) {
        res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client credentials',
        });
        return;
      }
    }

    // Exchange authorization code for tokens
    const tokenResponse = await this.oauthService.exchangeAuthorizationCode(
      params.code,
      params.client_id,
      params.redirect_uri,
      params.code_verifier
    );

    if (tokenResponse === null) {
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code',
      });
      return;
    }

    res.json(tokenResponse);
  }

  /**
   * Handle refresh_token grant type
   */
  private async handleRefreshTokenGrant(req: Request, res: Response): Promise<void> {
    const params = refreshTokenGrantSchema.parse(req.body);

    // Validate client
    const client = await this.oauthService.getClient(params.client_id);
    if (client === null) {
      res.status(400).json({
        error: 'invalid_client',
        error_description: 'Client not found',
      });
      return;
    }

    // Authenticate confidential clients
    if (this.oauthService.isConfidentialClient(client)) {
      if (!params.client_secret) {
        res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client secret is required for confidential clients',
        });
        return;
      }

      const isValidSecret = await this.oauthService.validateClientCredentials(
        params.client_id,
        params.client_secret
      );

      if (isValidSecret === false) {
        res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client credentials',
        });
        return;
      }
    }

    // Rotate refresh token and get new tokens
    const tokenResponse = await this.oauthService.rotateRefreshToken(
      params.refresh_token,
      params.client_id
    );

    if (tokenResponse === null) {
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired refresh token',
      });
      return;
    }

    res.json(tokenResponse);
  }

  /**
   * Handle client_credentials grant type
   */
  private async handleClientCredentialsGrant(req: Request, res: Response): Promise<void> {
    const params = clientCredentialsGrantSchema.parse(req.body);

    // Validate client
    const client = await this.oauthService.getClient(params.client_id);
    if (client === null) {
      res.status(400).json({
        error: 'invalid_client',
        error_description: 'Client not found',
      });
      return;
    }

    // Only confidential clients can use client_credentials grant
    if (!this.oauthService.isConfidentialClient(client)) {
      res.status(400).json({
        error: 'unauthorized_client',
        error_description: 'Client is not authorized to use this grant type',
      });
      return;
    }

    // Validate client credentials
    const isValidSecret = await this.oauthService.validateClientSecret(
      client.id,
      params.client_secret
    );

    if (!isValidSecret) {
      res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials',
      });
      return;
    }

    const scope = params.scope ?? client.allowedScopes;

    // Generate access token (no user context)
    // For client_credentials grant, we create a minimal user object with just the client ID
    const accessToken = await this.tokenService.generateAccessToken(
      { id: client.id, email: '', emailVerified: false },
      client.id,
      scope,
      900
    );

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes
      scope,
    });
  }
}
