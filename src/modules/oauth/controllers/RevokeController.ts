import { type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { type OAuthService } from '../services/OAuthService';

const revokeSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
});

export class RevokeController {
  constructor(private oauthService: OAuthService) {}

  /**
   * POST /oauth/revoke
   * OAuth 2.0 Token Revocation Endpoint (RFC 7009)
   */
  async revoke(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const params = revokeSchema.parse(req.body);

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

      // Revoke the token
      // Per RFC 7009: The authorization server responds with HTTP 200
      // regardless of whether the token was successfully revoked or not
      await this.oauthService.revokeToken(params.token, client.id, params.token_type_hint);

      // Return 200 OK with empty body (per RFC 7009)
      res.status(200).end();
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
}
