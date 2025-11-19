import { Router, type Router as RouterType } from 'express';
import { AuthorizeController } from '../controllers/AuthorizeController';
import { TokenController } from '../controllers/TokenController';
import { RevokeController } from '../controllers/RevokeController';
import { IntrospectController } from '../controllers/IntrospectController';
import { OAuthService } from '../services/OAuthService';
import { TokenService } from '../services/TokenService';
import { config } from '../../../shared/config';

// Initialize services
const oauthService = new OAuthService(config.issuer);
const tokenService = new TokenService(config.issuer);

// Initialize controllers
const authorizeController = new AuthorizeController(oauthService);
const tokenController = new TokenController(oauthService, tokenService);
const revokeController = new RevokeController(oauthService);
const introspectController = new IntrospectController(oauthService, tokenService);

const router: RouterType = Router();

/**
 * OAuth 2.0 Authorization Endpoint
 * GET /oauth/authorize
 */
router.get('/authorize', (req, res, next) => authorizeController.authorize(req, res, next));

/**
 * OAuth 2.0 Consent Endpoint
 * POST /oauth/consent
 */
router.post('/consent', (req, res, next) => authorizeController.consent(req, res, next));

/**
 * OAuth 2.0 Token Endpoint
 * POST /oauth/token
 *
 * Supports grant types:
 * - authorization_code
 * - refresh_token
 * - client_credentials
 */
router.post('/token', (req, res, next) => tokenController.token(req, res, next));

/**
 * OAuth 2.0 Token Revocation Endpoint (RFC 7009)
 * POST /oauth/revoke
 */
router.post('/revoke', (req, res, next) => revokeController.revoke(req, res, next));

/**
 * OAuth 2.0 Token Introspection Endpoint (RFC 7662)
 * POST /oauth/introspect
 */
router.post('/introspect', (req, res, next) => introspectController.introspect(req, res, next));

export default router;
