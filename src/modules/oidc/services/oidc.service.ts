import { config } from '../../../shared/config';

/**
 * OpenID Connect Discovery Document
 * Describes the OIDC provider's configuration
 */
export interface OIDCDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  registration_endpoint?: string;
  scopes_supported: string[];
  response_types_supported: string[];
  response_modes_supported?: string[];
  grant_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  claims_supported: string[];
  code_challenge_methods_supported: string[];
  revocation_endpoint?: string;
  introspection_endpoint?: string;
}

/**
 * OIDC Service
 * Handles OpenID Connect specific operations
 */
export class OIDCService {
  /**
   * Get the OpenID Connect Discovery Document
   * Provides metadata about the OIDC provider
   */
  getDiscoveryDocument(): OIDCDiscoveryDocument {
    const issuer = config.issuer;

    return {
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      userinfo_endpoint: `${issuer}/oauth/userinfo`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      revocation_endpoint: `${issuer}/oauth/revoke`,
      introspection_endpoint: `${issuer}/oauth/introspect`,

      scopes_supported: [
        'openid',
        'profile',
        'email',
        'offline_access', // For refresh tokens
      ],

      response_types_supported: [
        'code', // Authorization code flow
      ],

      response_modes_supported: ['query', 'fragment'],

      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],

      subject_types_supported: [
        'public', // Subject identifiers are the same for all clients
      ],

      id_token_signing_alg_values_supported: [
        'RS256', // RSA Signature with SHA-256
      ],

      token_endpoint_auth_methods_supported: [
        'client_secret_post', // Client credentials in POST body
        'client_secret_basic', // Client credentials in Authorization header
        'none', // For public clients with PKCE
      ],

      claims_supported: [
        'sub', // Subject identifier
        'iss', // Issuer
        'aud', // Audience
        'exp', // Expiration time
        'iat', // Issued at
        'email',
        'email_verified',
        'name',
        'given_name',
        'family_name',
        'picture',
      ],

      code_challenge_methods_supported: [
        'S256', // SHA-256 hash (PKCE)
      ],
    };
  }

  /**
   * Get supported scopes with descriptions
   * Useful for consent screens and documentation
   */
  getScopesWithDescriptions(): Record<string, string> {
    return {
      openid: 'Authenticate using OpenID Connect',
      profile: 'Access your profile information (name, picture, etc.)',
      email: 'Access your email address',
      offline_access: 'Maintain access when you are not present (refresh token)',
    };
  }

  /**
   * Get claims for a given scope
   * Maps scopes to the claims they provide
   */
  getClaimsForScope(scope: string): string[] {
    const scopeClaimsMap: Record<string, string[]> = {
      openid: ['sub', 'iss', 'aud', 'exp', 'iat'],
      profile: ['name', 'given_name', 'family_name', 'picture'],
      email: ['email', 'email_verified'],
    };

    return scopeClaimsMap[scope] ?? [];
  }

  /**
   * Validate if a scope is supported
   */
  isScopeSupported(scope: string): boolean {
    const supportedScopes = this.getDiscoveryDocument().scopes_supported;
    return supportedScopes.includes(scope);
  }

  /**
   * Validate if all requested scopes are supported
   */
  validateScopes(requestedScopes: string[]): { valid: boolean; unsupportedScopes: string[] } {
    const unsupportedScopes = requestedScopes.filter((scope) => !this.isScopeSupported(scope));

    return {
      valid: unsupportedScopes.length === 0,
      unsupportedScopes,
    };
  }
}

// Export singleton instance
export const oidcService = new OIDCService();
