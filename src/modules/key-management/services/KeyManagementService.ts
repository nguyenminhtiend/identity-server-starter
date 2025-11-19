import crypto from 'crypto';
import { eq, and, desc } from 'drizzle-orm';
import type * as jose from 'jose';
import { db, signingKeys } from '../../../shared/database/index.js';
import { encryptAES, decryptAES, generateRSAKeyPair } from '../../../shared/utils/crypto.js';

/**
 * Signing Key interface (from database)
 */
export interface SigningKey {
  id: string;
  keyId: string;
  algorithm: string;
  publicKeyPem: string;
  privateKeyEncrypted: string;
  isActive: boolean;
  isPrimary: boolean;
  createdAt: Date;
  expiresAt: Date | null;
  rotatedAt: Date | null;
  nextRotationAt: Date | null;
}

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
interface DecryptedKeyPair {
  keyId: string;
  publicKey: string;
  privateKey: string;
  algorithm: string;
}

/**
 * Key Management Service
 * Handles cryptographic key lifecycle management for JWT signing
 * - Stores keys in database with encrypted private keys
 * - Supports key rotation without downtime
 * - Provides primary signing key and all active public keys
 * - Caches keys in memory for performance
 */
export class KeyManagementService {
  private static instance: KeyManagementService;
  private encryptionSecret: string;
  private cachedKeys = new Map<string, DecryptedKeyPair>();
  private primaryKeyId: string | null = null;
  private lastRefresh: Date = new Date(0);
  private readonly CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

  private constructor(encryptionSecret: string) {
    this.encryptionSecret = encryptionSecret;
  }

  /**
   * Get singleton instance
   * @param encryptionSecret - Master key for encrypting/decrypting private keys
   */
  static getInstance(encryptionSecret?: string): KeyManagementService {
    if (!KeyManagementService.instance) {
      if (!encryptionSecret) {
        throw new Error('Encryption secret is required for first initialization');
      }
      KeyManagementService.instance = new KeyManagementService(encryptionSecret);
    }
    return KeyManagementService.instance;
  }

  /**
   * Initialize the service by loading keys from database
   */
  async initialize(): Promise<void> {
    await this.refreshKeys();
  }

  /**
   * Refresh keys from database (checks cache TTL)
   */
  private async refreshKeys(): Promise<void> {
    const now = new Date();
    const timeSinceLastRefresh = now.getTime() - this.lastRefresh.getTime();

    // Skip refresh if cache is still valid
    if (timeSinceLastRefresh < this.CACHE_TTL_MS && this.cachedKeys.size > 0) {
      return;
    }

    // Load all active keys from database
    const activeKeys = await db
      .select()
      .from(signingKeys)
      .where(eq(signingKeys.isActive, true))
      .orderBy(desc(signingKeys.createdAt));

    // Clear cache and reload
    this.cachedKeys.clear();
    this.primaryKeyId = null;

    for (const key of activeKeys) {
      try {
        // Decrypt private key
        const privateKey = decryptAES(key.privateKeyEncrypted, this.encryptionSecret);

        // Cache the decrypted key pair
        this.cachedKeys.set(key.keyId, {
          keyId: key.keyId,
          publicKey: key.publicKeyPem,
          privateKey,
          algorithm: key.algorithm,
        });

        // Set primary key
        if (key.isPrimary) {
          this.primaryKeyId = key.keyId;
        }
      } catch (error) {
        console.error(`Failed to decrypt key ${key.keyId}:`, error);
      }
    }

    this.lastRefresh = now;

    if (!this.primaryKeyId) {
      throw new Error('No primary signing key found');
    }
  }

  /**
   * Get the primary signing key (for creating new JWTs)
   * @returns Decrypted primary key pair
   */
  async getPrimarySigningKey(): Promise<DecryptedKeyPair> {
    await this.refreshKeys();

    if (!this.primaryKeyId) {
      throw new Error('No primary signing key available');
    }

    const key = this.cachedKeys.get(this.primaryKeyId);
    if (!key) {
      throw new Error('Primary signing key not found in cache');
    }

    return key;
  }

  /**
   * Get all active public keys for JWKS endpoint
   * @returns Array of public keys in JWK format
   */
  async getPublicKeys(): Promise<PublicKeyJWK[]> {
    await this.refreshKeys();

    const publicKeys: PublicKeyJWK[] = [];

    for (const [keyId, keyPair] of this.cachedKeys.entries()) {
      try {
        // Import public key as crypto.KeyObject
        const publicKeyObject = crypto.createPublicKey({
          key: keyPair.publicKey,
          format: 'pem',
          type: 'spki',
        });

        // Export as JWK
        const jwk = publicKeyObject.export({ format: 'jwk' }) as jose.JWK;

        publicKeys.push({
          kid: keyId,
          kty: jwk.kty || 'RSA',
          alg: keyPair.algorithm,
          use: 'sig',
          n: jwk.n || '',
          e: jwk.e || 'AQAB',
        });
      } catch (error) {
        console.error(`Failed to export public key ${keyId}:`, error);
      }
    }

    return publicKeys;
  }

  /**
   * Get a specific key by key ID (for verification)
   * @param keyId - The key ID
   * @returns Decrypted key pair or null if not found
   */
  async getKeyById(keyId: string): Promise<DecryptedKeyPair | null> {
    await this.refreshKeys();
    return this.cachedKeys.get(keyId) || null;
  }

  /**
   * Generate a new RSA key pair
   * @returns Public and private keys in PEM format
   */
  generateKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
    return generateRSAKeyPair();
  }

  /**
   * Encrypt a private key for database storage
   * @param privateKey - Private key in PEM format
   * @returns Encrypted private key
   */
  encryptPrivateKey(privateKey: string): string {
    return encryptAES(privateKey, this.encryptionSecret);
  }

  /**
   * Decrypt a private key from database storage
   * @param encrypted - Encrypted private key
   * @returns Decrypted private key in PEM format
   */
  decryptPrivateKey(encrypted: string): string {
    return decryptAES(encrypted, this.encryptionSecret);
  }

  /**
   * Generate a new key ID
   * Format: YYYY-MM-DD-vN
   * @returns Key ID string
   */
  generateKeyId(): string {
    const now = new Date();
    const dateStr = now.toISOString().split('T')[0]; // YYYY-MM-DD
    const randomSuffix = crypto.randomBytes(4).toString('hex');
    return `${dateStr}-${randomSuffix}`;
  }

  /**
   * Create and store a new signing key
   * @param isPrimary - Whether this should be the primary key
   * @returns The created key record
   */
  async createSigningKey(isPrimary = false): Promise<SigningKey> {
    // Generate key pair
    const { publicKey, privateKey } = await this.generateKeyPair();

    // Encrypt private key
    const privateKeyEncrypted = this.encryptPrivateKey(privateKey);

    // Generate key ID
    const keyId = this.generateKeyId();

    // Calculate next rotation date (90 days from now)
    const nextRotationAt = new Date();
    nextRotationAt.setDate(nextRotationAt.getDate() + 90);

    // If this will be primary, deactivate current primary
    if (isPrimary) {
      await db.update(signingKeys).set({ isPrimary: false }).where(eq(signingKeys.isPrimary, true));
    }

    // Insert new key
    const [newKey] = await db
      .insert(signingKeys)
      .values({
        keyId,
        algorithm: 'RS256',
        publicKeyPem: publicKey,
        privateKeyEncrypted,
        isActive: true,
        isPrimary,
        nextRotationAt,
      })
      .returning();

    // Invalidate cache to force refresh
    this.lastRefresh = new Date(0);

    return newKey;
  }

  /**
   * Rotate keys: create new primary key and mark old primary as non-primary
   * @returns The new primary key
   */
  async rotateKeys(): Promise<SigningKey> {
    console.log('Starting key rotation...');

    // Get current primary key
    const [currentPrimary] = await db
      .select()
      .from(signingKeys)
      .where(and(eq(signingKeys.isPrimary, true), eq(signingKeys.isActive, true)))
      .limit(1);

    // Create new primary key
    const newPrimaryKey = await this.createSigningKey(true);

    // Mark old primary as rotated (keep active for verification)
    if (currentPrimary) {
      await db
        .update(signingKeys)
        .set({
          isPrimary: false,
          rotatedAt: new Date(),
        })
        .where(eq(signingKeys.id, currentPrimary.id));

      console.log(`Rotated key ${currentPrimary.keyId} -> ${newPrimaryKey.keyId}`);
    }

    // Invalidate cache
    this.lastRefresh = new Date(0);

    console.log('Key rotation completed');
    return newPrimaryKey;
  }

  /**
   * Check if key rotation is due and perform it if necessary
   */
  async checkRotationSchedule(): Promise<void> {
    const [primaryKey] = await db
      .select()
      .from(signingKeys)
      .where(and(eq(signingKeys.isPrimary, true), eq(signingKeys.isActive, true)))
      .limit(1);

    if (!primaryKey?.nextRotationAt) {
      return;
    }

    const now = new Date();
    if (now >= primaryKey.nextRotationAt) {
      console.log('Automatic key rotation triggered');
      await this.rotateKeys();
    }
  }

  /**
   * Deactivate a signing key (soft delete)
   * @param keyId - The key ID to deactivate
   */
  async deactivateKey(keyId: string): Promise<void> {
    await db.update(signingKeys).set({ isActive: false }).where(eq(signingKeys.keyId, keyId));

    // Invalidate cache
    this.lastRefresh = new Date(0);

    console.log(`Key ${keyId} deactivated`);
  }

  /**
   * Get all signing keys (for admin purposes)
   * @returns All signing keys (without decrypted private keys)
   */
  async getAllKeys(): Promise<SigningKey[]> {
    return db.select().from(signingKeys).orderBy(desc(signingKeys.createdAt));
  }
}
