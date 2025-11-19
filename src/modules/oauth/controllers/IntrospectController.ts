import { type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { type OAuthService } from '../services/OAuthService';
import { type TokenService } from '../services/TokenService';

const introspectSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.optional(z.enum(['access_token', 'refresh_token'])),
  client_id: z.string().min(1),
  client_secret: z.optional(z.string()),
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
      const client = await this.oauthService.getClient(params.client_id);
      if (client === null) {
        res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client not found',
        });
        return;
      }

      // Authenticate confidential clients (introspection requires authentication)
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
      } else {
        // Public clients must provide client_secret for introspection
        res.status(400).json({
          error: 'invalid_client',
          error_description: 'Token introspection requires client authentication',
        });
        return;
      }

      // Determine token type and validate
      let tokenMetadata: Record<string, unknown> | null;
      const hint = params.token_type_hint;

      if (hint === 'refresh_token' || hint === undefined) {
        // Try as refresh token first
        tokenMetadata = await this.introspectRefreshToken(params.token, client.id);
        if (tokenMetadata !== null) {
          res.json(tokenMetadata);
          return;
        }
      }

      if (hint === 'access_token' || hint === undefined) {
        // Try as access token
        tokenMetadata = await this.introspectAccessToken(params.token);
        if (tokenMetadata !== null) {
          res.json(tokenMetadata);
          return;
        }
      }

      // Token is invalid or not found
      res.json({ active: false });
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
   * Introspect a refresh token
   */
  private async introspectRefreshToken(
    token: string,
    clientId: string
  ): Promise<Record<string, unknown> | null> {
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
  private async introspectAccessToken(token: string): Promise<Record<string, unknown> | null> {
    try {
      const result = await this.tokenService.verifyToken(token);

      if (!result.valid || !result.payload) {
        return null;
      }

      const payload = result.payload as any;

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
