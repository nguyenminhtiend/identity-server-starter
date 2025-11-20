import { Router, type Router as RouterType } from 'express';
import {
  AuthorizeController,
  TokenController,
  RevokeController,
  IntrospectController,
} from '../controllers';
import { getService, SERVICE_IDENTIFIERS } from '../../../shared/di';
import type { IOAuthService, ITokenService } from '../services/interfaces';

// Get services from DI container
const oauthService = getService<IOAuthService>(SERVICE_IDENTIFIERS.OAuthService);
const tokenService = getService<ITokenService>(SERVICE_IDENTIFIERS.TokenService);

// Initialize controllers with injected dependencies
const authorizeController = new AuthorizeController(oauthService);
const tokenController = new TokenController(oauthService, tokenService);
const revokeController = new RevokeController(oauthService);
const introspectController = new IntrospectController(oauthService, tokenService);

const router: RouterType = Router();

/**
 * OAuth 2.0 Authorization Endpoint
 * GET /oauth/authorize
 */
router.get('/authorize', authorizeController.authorize);

/**
 * OAuth 2.0 Consent Endpoint
 * POST /oauth/consent
 */
router.post('/consent', authorizeController.consent);

/**
 * OAuth 2.0 Token Endpoint
 * POST /oauth/token
 *
 * Supports grant types:
 * - authorization_code
 * - refresh_token
 * - client_credentials
 */
router.post('/token', tokenController.token);

/**
 * OAuth 2.0 Token Revocation Endpoint (RFC 7009)
 * POST /oauth/revoke
 */
router.post('/revoke', revokeController.revoke);

/**
 * OAuth 2.0 Token Introspection Endpoint (RFC 7662)
 * POST /oauth/introspect
 */
router.post('/introspect', introspectController.introspect);

export default router;
