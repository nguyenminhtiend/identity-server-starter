import { config } from '../config';
import { TokenService, OAuthService } from '../../modules/oauth/services';
import { OIDCService } from '../../modules/oidc/services';
import { KeyManagementService } from '../../modules/key-management/services';
import type { ITokenService, IOAuthService } from '../../modules/oauth/services/interfaces';
import type { IKeyManagementService } from '../../modules/key-management/services/interfaces';

/**
 * Transient service descriptor
 */
interface TransientServiceDescriptor<T> {
  isTransient: true;
  factory: () => T;
}

/**
 * Service type union
 */
type ServiceDescriptor<T> = T | TransientServiceDescriptor<T>;

/**
 * Dependency Injection Container
 * Centralized service instantiation and lifecycle management
 *
 * Benefits:
 * - Single source of truth for dependency wiring
 * - Easy to swap implementations for testing
 * - Clear visibility of service dependencies
 * - Supports both singleton and transient lifetimes
 */
export class DIContainer {
  private static instance: DIContainer | undefined;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private services = new Map<string, ServiceDescriptor<any>>();

  private constructor() {
    // Private constructor for singleton pattern
  }

  /**
   * Get the singleton container instance
   */
  static getInstance(): DIContainer {
    DIContainer.instance ??= new DIContainer();
    return DIContainer.instance;
  }

  /**
   * Register a singleton service
   * @param key - Service identifier
   * @param factory - Factory function to create the service
   */
  registerSingleton<T>(key: string, factory: () => T): void {
    if (!this.services.has(key)) {
      this.services.set(key, factory());
    }
  }

  /**
   * Register a transient service (created on each resolve)
   * @param key - Service identifier
   * @param factory - Factory function to create the service
   */
  registerTransient<T>(key: string, factory: () => T): void {
    this.services.set(key, { isTransient: true, factory });
  }

  /**
   * Type guard for transient service descriptor
   */
  private isTransientDescriptor<T>(
    service: ServiceDescriptor<T>
  ): service is TransientServiceDescriptor<T> {
    return (
      typeof service === 'object' &&
      service !== null &&
      'isTransient' in service &&
      service.isTransient === true &&
      'factory' in service
    );
  }

  /**
   * Resolve a service by key
   * @param key - Service identifier
   * @returns Service instance
   */
  resolve<T>(key: string): T {
    const service = this.services.get(key) as ServiceDescriptor<T> | undefined;

    if (service === undefined) {
      throw new Error(`Service ${key} not registered in DI container`);
    }

    // Check if it's a transient service
    if (this.isTransientDescriptor(service)) {
      return service.factory();
    }

    return service;
  }

  /**
   * Check if a service is registered
   * @param key - Service identifier
   * @returns True if service is registered
   */
  has(key: string): boolean {
    return this.services.has(key);
  }

  /**
   * Clear all registered services (useful for testing)
   */
  clear(): void {
    this.services.clear();
  }

  /**
   * Reset the container singleton (useful for testing)
   */
  static reset(): void {
    if (DIContainer.instance !== undefined) {
      DIContainer.instance.clear();
      DIContainer.instance = undefined;
    }
  }
}

/**
 * Service identifiers (type-safe keys)
 */
export const SERVICE_IDENTIFIERS = {
  KeyManagementService: 'IKeyManagementService',
  TokenService: 'ITokenService',
  OAuthService: 'IOAuthService',
  OIDCService: 'OIDCService',
} as const;

/**
 * Initialize and configure the DI container with all services
 */
export function configureDIContainer(): DIContainer {
  const container = DIContainer.getInstance();

  // Register KeyManagementService as singleton
  container.registerSingleton<IKeyManagementService>(SERVICE_IDENTIFIERS.KeyManagementService, () =>
    KeyManagementService.getInstance(config.keys.encryptionSecret)
  );

  // Register TokenService as singleton
  container.registerSingleton<ITokenService>(SERVICE_IDENTIFIERS.TokenService, () => {
    const keyManagementService = container.resolve<IKeyManagementService>(
      SERVICE_IDENTIFIERS.KeyManagementService
    );
    return new TokenService(config.issuer, keyManagementService);
  });

  // Register OAuthService as singleton
  container.registerSingleton<IOAuthService>(SERVICE_IDENTIFIERS.OAuthService, () => {
    const tokenService = container.resolve<ITokenService>(SERVICE_IDENTIFIERS.TokenService);
    return new OAuthService(tokenService);
  });

  // Register OIDCService as singleton
  container.registerSingleton(SERVICE_IDENTIFIERS.OIDCService, () => {
    return new OIDCService();
  });

  return container;
}

/**
 * Get a service from the container (convenience function)
 * @param identifier - Service identifier
 * @returns Service instance
 */
export function getService<T>(identifier: string): T {
  const container = DIContainer.getInstance();
  return container.resolve<T>(identifier);
}
