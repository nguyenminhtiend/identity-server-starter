import { type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { type OAuthService } from '../services/OAuthService';
import { type TokenService } from '../services/TokenService';

const introspectSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
});

export class IntrospectController {
  constructor(
    private oauthService: OAuthService,
    private tokenService: TokenService
  ) {}

  /**
   * POST /oauth/introspect
   * OAuth 2.0 Token Introspection Endpoint (RFC 7662)
   * Returns metadata about a token
   */
  async introspect(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const params = introspectSchema.parse(req.body);

      // Validate client
      const client = await this.oauthService.validateClient(params.client_id);
      if (!client) {
        return res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client not found',
        });
      }

      // Authenticate confidential clients (introspection requires authentication)
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
      } else {
        // Public clients must provide client_secret for introspection
        return res.status(400).json({
          error: 'invalid_client',
          error_description: 'Token introspection requires client authentication',
        });
      }

      // Determine token type and validate
      let tokenMetadata: any;
      const hint = params.token_type_hint;

      if (hint === 'refresh_token' || !hint) {
        // Try as refresh token first
        tokenMetadata = await this.introspectRefreshToken(params.token, client.id);
        if (tokenMetadata) {
          return res.json(tokenMetadata);
        }
      }

      if (hint === 'access_token' || !hint) {
        // Try as access token
        tokenMetadata = await this.introspectAccessToken(params.token);
        if (tokenMetadata) {
          return res.json(tokenMetadata);
        }
      }

      // Token is invalid or not found
      return res.json({ active: false });
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
   * Introspect a refresh token
   */
  private async introspectRefreshToken(token: string, clientId: string): Promise<object | null> {
    const refreshTokenData = await this.oauthService.getRefreshToken(token);

    if (!refreshTokenData) {
      return null;
    }

    // Check if token belongs to the requesting client
    if (refreshTokenData.client_id !== clientId) {
      return null;
    }

    // Check if token is revoked
    if (refreshTokenData.revoked) {
      return {
        active: false,
      };
    }

    // Check if token is expired
    const isExpired = new Date() > new Date(refreshTokenData.expires_at);
    if (isExpired) {
      return {
        active: false,
      };
    }

    // Token is active
    return {
      active: true,
      scope: refreshTokenData.scope,
      client_id: clientId,
      token_type: 'refresh_token',
      exp: Math.floor(new Date(refreshTokenData.expires_at).getTime() / 1000),
      iat: Math.floor(new Date(refreshTokenData.created_at).getTime() / 1000),
      sub: refreshTokenData.user_id,
    };
  }

  /**
   * Introspect an access token (JWT)
   */
  private async introspectAccessToken(token: string): Promise<object | null> {
    try {
      const payload = await this.tokenService.verifyAccessToken(token);

      if (!payload) {
        return null;
      }

      // Token is valid
      return {
        active: true,
        scope: payload.scope,
        client_id: payload.client_id,
        token_type: 'Bearer',
        exp: payload.exp,
        iat: payload.iat,
        sub: payload.sub,
        iss: payload.iss,
      };
    } catch (_error) {
      // Token is invalid
      return null;
    }
  }
}
