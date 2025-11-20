import { config } from './config';
import { KeyManagementService } from '../modules/key-management/services';
import { TokenService, OAuthService } from '../modules/oauth/services';
import { OIDCService } from '../modules/oidc/services';
import type { IKeyManagementService } from '../modules/key-management/services/interfaces';
import type { ITokenService, IOAuthService } from '../modules/oauth/services/interfaces';

/**
 * Services container
 * All application services with their dependencies
 */
export interface Services {
  keyManagementService: IKeyManagementService;
  tokenService: ITokenService;
  oauthService: IOAuthService;
  oidcService: OIDCService;
}

/**
 * Create all application services with explicit dependency injection
 * @returns Services object with all instantiated services
 */
export function createServices(): Services {
  // Create KeyManagementService (no dependencies)
  const keyManagementService = new KeyManagementService(config.keys.encryptionSecret);

  // Create TokenService (depends on KeyManagementService)
  const tokenService = new TokenService(config.issuer, keyManagementService);

  // Create OAuthService (depends on TokenService)
  const oauthService = new OAuthService(tokenService);

  // Create OIDCService (no dependencies)
  const oidcService = new OIDCService();

  return {
    keyManagementService,
    tokenService,
    oauthService,
    oidcService,
  };
}
