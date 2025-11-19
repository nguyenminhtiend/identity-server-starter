import { type Request, type Response } from 'express';
import { z } from 'zod';
import { type OAuthService } from '../services/OAuthService';

const authorizeSchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  response_type: z.literal('code'),
  scope: z.string().min(1),
  state: z.optional(z.string()),
  code_challenge: z.string().min(43).max(128),
  code_challenge_method: z.enum(['S256']),
});

export class AuthorizeController {
  constructor(private oauthService: OAuthService) {}

  /**
   * GET /oauth/authorize
   * OAuth 2.0 Authorization Endpoint with PKCE
   */
  async authorize(req: Request, res: Response): Promise<void> {
    // Validate query parameters
    const params = authorizeSchema.parse(req.query);

    // Validate client exists and redirect_uri is allowed
    const client = await this.oauthService.getClient(params.client_id);
    if (client === null) {
      res.status(400).json({
        error: 'invalid_client',
        error_description: 'Client not found',
      });
      return;
    }

    if (!client.isActive) {
      res.status(400).json({
        error: 'invalid_client',
        error_description: 'Client is not active',
      });
      return;
    }

    // Validate redirect URI
    const isValidRedirect = this.oauthService.validateRedirectUri(client, params.redirect_uri);

    if (!isValidRedirect) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Invalid redirect_uri',
      });
      return;
    }

    // Validate PKCE parameters
    if (params.code_challenge_method !== 'S256') {
      this.redirectWithError(
        res,
        params.redirect_uri,
        'invalid_request',
        'Only S256 code_challenge_method is supported',
        params.state
      );
      return;
    }

    // Check if user is authenticated
    if (!req.session?.userId) {
      // Store authorization request in session and redirect to login
      req.session.authRequest = {
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        scope: params.scope,
        state: params.state,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
      };

      return res.redirect(`/login?returnUrl=${encodeURIComponent(req.originalUrl)}`);
    }

    const userId = req.session.userId;

    // Check if user has previously granted consent
    const hasConsent = await this.oauthService.hasConsent(userId, client.id, params.scope);

    if (hasConsent === false) {
      // Show consent screen
      return res.render('oauth/consent', {
        client,
        scope: params.scope,
        state: params.state,
        requestParams: params,
      });
    }

    // Generate authorization code
    const code = await this.oauthService.createAuthorizationCode(
      client.id,
      userId,
      params.redirect_uri,
      params.scope,
      params.code_challenge,
      params.code_challenge_method
    );

    // Redirect back to client with code
    const redirectUrl = new URL(params.redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (params.state) {
      redirectUrl.searchParams.set('state', params.state);
    }

    res.redirect(redirectUrl.toString());
  }

  /**
   * POST /oauth/consent
   * Handle user consent decision
   */
  async consent(req: Request, res: Response): Promise<void> {
    const {
      client_id,
      scope,
      redirect_uri,
      state,
      code_challenge,
      code_challenge_method,
      allow,
    } = req.body;

    if (!req.session?.userId) {
      res.status(401).json({
        error: 'unauthorized',
        error_description: 'User not authenticated',
      });
      return;
    }

    const userId = req.session.userId;

    // User denied consent
    if (allow !== 'true' && allow !== true) {
      this.redirectWithError(
        res,
        redirect_uri,
        'access_denied',
        'User denied the request',
        state
      );
      return;
    }

    // Validate client
    const client = await this.oauthService.getClient(client_id);
    if (client === null) {
      res.status(400).json({
        error: 'invalid_client',
        error_description: 'Client not found',
      });
      return;
    }

    // Save consent
    await this.oauthService.grantConsent(userId, client.id, scope);

    // Generate authorization code
    const code = await this.oauthService.createAuthorizationCode(
      client.id,
      userId,
      redirect_uri,
      scope,
      code_challenge,
      code_challenge_method
    );

    // Redirect back to client with code
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (state) {
      redirectUrl.searchParams.set('state', state);
    }

    res.redirect(redirectUrl.toString());
  }

  /**
   * Helper method to redirect with OAuth error
   */
  private redirectWithError(
    res: Response,
    redirectUri: string,
    error: string,
    errorDescription: string,
    state?: string
  ): void {
    const url = new URL(redirectUri);
    url.searchParams.set('error', error);
    url.searchParams.set('error_description', errorDescription);
    if (state) {
      url.searchParams.set('state', state);
    }
    res.redirect(url.toString());
  }
}
