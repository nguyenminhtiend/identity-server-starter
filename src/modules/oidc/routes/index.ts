import { Router, type Router as RouterType } from 'express';
import { discoveryController } from '../controllers/DiscoveryController.js';
import { jwksController } from '../controllers/JWKSController.js';
import { userInfoController } from '../controllers/UserInfoController.js';

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
