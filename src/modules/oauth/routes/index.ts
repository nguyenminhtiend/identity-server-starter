import { Router, type Router as RouterType } from 'express';
import { AuthorizeController } from '../controllers/authorize-controller.js';
import { TokenController } from '../controllers/token-controller.js';
import { RevokeController } from '../controllers/revoke-controller.js';
import { IntrospectController } from '../controllers/introspect-controller.js';
import { getService, SERVICE_IDENTIFIERS } from '../../../shared/di/container.config.js';
import type { IOAuthService } from '../services/interfaces/oauth-service.interface.js';
import type { ITokenService } from '../services/interfaces/token-service.interface.js';

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
router.get('/authorize', (req, res) => authorizeController.authorize(req, res));

/**
 * OAuth 2.0 Consent Endpoint
 * POST /oauth/consent
 */
router.post('/consent', (req, res) => authorizeController.consent(req, res));

/**
 * OAuth 2.0 Token Endpoint
 * POST /oauth/token
 *
 * Supports grant types:
 * - authorization_code
 * - refresh_token
 * - client_credentials
 */
router.post('/token', (req, res) => tokenController.token(req, res));

/**
 * OAuth 2.0 Token Revocation Endpoint (RFC 7009)
 * POST /oauth/revoke
 */
router.post('/revoke', (req, res) => revokeController.revoke(req, res));

/**
 * OAuth 2.0 Token Introspection Endpoint (RFC 7662)
 * POST /oauth/introspect
 */
router.post('/introspect', (req, res) => introspectController.introspect(req, res));

export default router;
