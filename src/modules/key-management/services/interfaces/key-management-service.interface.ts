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
  keyId: string;
  publicKey: string;
  privateKey: string;
  algorithm: string;
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
}
