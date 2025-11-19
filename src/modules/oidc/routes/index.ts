import { Router, type Router as RouterType } from 'express';
import { DiscoveryController } from '../controllers/DiscoveryController.js';
import { JWKSController } from '../controllers/JWKSController.js';
import { UserInfoController } from '../controllers/UserInfoController.js';
import { getService, SERVICE_IDENTIFIERS } from '../../../shared/di/container.js';
import type { ITokenService } from '../../oauth/services/interfaces/ITokenService.js';
import type { IKeyManagementService } from '../../key-management/services/interfaces/IKeyManagementService.js';
import type { OIDCService } from '../services/OIDCService.js';

// Get services from DI container
const tokenService = getService<ITokenService>(SERVICE_IDENTIFIERS.TokenService);
const keyManagementService = getService<IKeyManagementService>(
  SERVICE_IDENTIFIERS.KeyManagementService
);
const oidcService = getService<OIDCService>(SERVICE_IDENTIFIERS.OIDCService);

// Initialize controllers with injected dependencies
const discoveryController = new DiscoveryController(oidcService);
const jwksController = new JWKSController(keyManagementService);
const userInfoController = new UserInfoController(tokenService);

const router: RouterType = Router();

/**
 * OIDC Discovery Endpoints
 */

// OpenID Connect Discovery Document
// GET /.well-known/openid-configuration
router.get(
  '/.well-known/openid-configuration',
  discoveryController.getDiscoveryDocument.bind(discoveryController)
);

// JSON Web Key Set (JWKS)
// GET /.well-known/jwks.json
router.get('/.well-known/jwks.json', jwksController.getJWKS.bind(jwksController));

/**
 * OIDC UserInfo Endpoint
 */

// UserInfo endpoint (requires Bearer token)
// GET /oauth/userinfo
router.get('/oauth/userinfo', userInfoController.getUserInfo.bind(userInfoController));

export default router;
