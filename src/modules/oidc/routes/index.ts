import { Router, type Router as RouterType } from 'express';
import { DiscoveryController, JWKSController, UserInfoController } from '../controllers';
import type { Services } from '../../../shared/services';

/**
 * Create OIDC router with injected services
 * @param services - Application services
 * @returns Configured OIDC router
 */
export function createOIDCRouter(services: Services): RouterType {
  const { tokenService, keyManagementService, oidcService } = services;

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

  return router;
}
