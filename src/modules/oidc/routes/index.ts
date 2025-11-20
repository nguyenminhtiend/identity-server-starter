import { Router, type Router as RouterType } from 'express';
import { DiscoveryController, JWKSController, UserInfoController } from '../controllers';
import { getService, SERVICE_IDENTIFIERS } from '../../../shared/di';
import type { ITokenService } from '../../oauth/services/interfaces';
import type { IKeyManagementService } from '../../key-management/services/interfaces';
import type { OIDCService } from '../services';

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
router.get('/.well-known/openid-configuration', discoveryController.getDiscoveryDocument);

// JSON Web Key Set (JWKS)
// GET /.well-known/jwks.json
router.get('/.well-known/jwks.json', jwksController.getJWKS);

/**
 * OIDC UserInfo Endpoint
 */

// UserInfo endpoint (requires Bearer token)
// GET /oauth/userinfo
router.get('/oauth/userinfo', userInfoController.getUserInfo);

export default router;
