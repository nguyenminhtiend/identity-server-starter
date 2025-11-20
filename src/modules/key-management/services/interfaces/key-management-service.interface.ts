/**
 * Public Key JWK format for JWKS endpoint
 */
export interface PublicKeyJWK {
  kid: string;
  kty: string;
  alg: string;
  use: string;
  n: string;
  e: string;
}

/**
 * Decrypted key pair for signing
 */
export interface DecryptedKeyPair {
  id: string;
  keyId: string;
  publicKey: string;
  privateKey: string;
  algorithm: string;
  isActive: boolean;
  isPrimary: boolean;
  createdAt: Date;
  nextRotationAt: Date | null;
  publicKeyPem: string;
}

/**
 * Key metadata for admin endpoints
 */
export interface KeyMetadata {
  id: string;
  keyId: string;
  algorithm: string;
  isActive: boolean;
  isPrimary: boolean;
  createdAt: Date;
  expiresAt: Date | null;
  rotatedAt: Date | null;
  nextRotationAt: Date | null;
  publicKeyPem: string;
}

/**
 * Key rotation status
 */
export interface RotationStatus {
  currentPrimaryKeyId: string;
  nextRotationAt: Date | null;
  activeKeysCount: number;
  rotationIntervalDays: number;
}

/**
 * Key Management Service Interface
 * Handles cryptographic key lifecycle management for JWT signing
 */
export interface IKeyManagementService {
  /**
   * Initialize the service by loading keys from database
   */
  initialize(): Promise<void>;

  /**
   * Get the primary signing key (for creating new JWTs)
   * @returns Decrypted primary key pair
   */
  getPrimarySigningKey(): Promise<DecryptedKeyPair>;

  /**
   * Get all active public keys for JWKS endpoint
   * @returns Array of public keys in JWK format
   */
  getPublicKeys(): Promise<PublicKeyJWK[]>;

  /**
   * Get a specific key by key ID (for verification)
   * @param keyId - The key ID
   * @returns Decrypted key pair or null if not found
   */
  getKeyById(keyId: string): Promise<DecryptedKeyPair | null>;

  /**
   * List all keys (for admin endpoints)
   * @returns Array of key metadata
   */
  listAllKeys(): Promise<KeyMetadata[]>;

  /**
   * Manually trigger key rotation
   */
  rotateKeys(): Promise<void>;

  /**
   * Get rotation status
   * @returns Current rotation status
   */
  getRotationStatus(): Promise<RotationStatus>;
}
