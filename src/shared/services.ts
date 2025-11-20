import { config } from './config';
import { KeyManagementService } from '../modules/key-management/services';
import { TokenService, OAuthService } from '../modules/oauth/services';
import { OIDCService } from '../modules/oidc/services';
import { UserService, type IUserService } from '../modules/user/services';
import { ClientService, type IClientService } from '../modules/client/services';
import { OrganizationService, type IOrganizationService } from '../modules/organization/services';
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
  userService: IUserService;
  clientService: IClientService;
  organizationService: IOrganizationService;
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

  // Create UserService (no dependencies)
  const userService = new UserService();

  // Create ClientService (no dependencies)
  const clientService = new ClientService();

  // Create OrganizationService (no dependencies)
  const organizationService = new OrganizationService();

  return {
    keyManagementService,
    tokenService,
    oauthService,
    oidcService,
    userService,
    clientService,
    organizationService,
  };
}
