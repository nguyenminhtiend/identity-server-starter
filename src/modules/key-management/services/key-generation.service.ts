import { db, signingKeys } from '../../../shared/database';
import { generateRSAKeyPair, encryptAES } from '../../../shared/utils/crypto.util.js';
import { logger } from '../../../shared/utils/logger.util.js';
import * as dotenv from 'dotenv';

dotenv.config();

/**
 * Service for generating and storing cryptographic keys in the database
 */
export class KeyGenerationService {
  private readonly encryptionSecret: string;
  private readonly keyRotationDays: number;

  constructor() {
    this.encryptionSecret = process.env.KEY_ENCRYPTION_SECRET ?? '';
    this.keyRotationDays = parseInt(process.env.KEY_ROTATION_DAYS ?? '90', 10);

    if (!this.encryptionSecret || this.encryptionSecret.length < 32) {
      throw new Error('KEY_ENCRYPTION_SECRET must be at least 32 characters long');
    }
  }

  /**
   * Generate a key ID in format: YYYY-MM-DD-vN
   */
  private generateKeyId(): string {
    const now = new Date();
    const dateStr = now.toISOString().split('T')[0]; // YYYY-MM-DD
    const timestamp = now.getTime();
    return `${dateStr}-v${timestamp}`;
  }

  /**
   * Calculate next rotation date
   */
  private calculateNextRotation(): Date {
    const nextRotation = new Date();
    nextRotation.setDate(nextRotation.getDate() + this.keyRotationDays);
    return nextRotation;
  }

  /**
   * Generate a new signing key pair and store it in the database
   * @param isPrimary - Whether this key should be the primary signing key
   * @returns The generated key ID
   */
  async generateAndStoreKey(isPrimary = true): Promise<string> {
    // Generate RSA key pair
    const { publicKey, privateKey } = generateRSAKeyPair();

    // Encrypt the private key
    const privateKeyEncrypted = encryptAES(privateKey, this.encryptionSecret);

    // Generate key ID
    const keyId = this.generateKeyId();

    // Calculate next rotation date
    const nextRotationAt = this.calculateNextRotation();

    // If this is going to be the primary key, deactivate the current primary
    if (isPrimary) {
      await db.update(signingKeys).set({ isPrimary: false }).execute();
    }

    // Insert the new key into the database
    await db.insert(signingKeys).values({
      keyId,
      algorithm: 'RS256',
      publicKeyPem: publicKey,
      privateKeyEncrypted,
      isActive: true,
      isPrimary,
      nextRotationAt,
    });

    logger.info(
      { keyId, isPrimary, nextRotationAt: nextRotationAt.toISOString() },
      `✓ Generated and stored new signing key: ${keyId}`
    );
    logger.info(`  - Primary: ${isPrimary}`);
    logger.info(`  - Next rotation: ${nextRotationAt.toISOString()}`);

    return keyId;
  }

  /**
   * Generate the initial signing key for the system
   */
  async generateInitialKey(): Promise<string> {
    logger.info('Generating initial signing key...');
    return this.generateAndStoreKey(true);
  }
}

// CLI script: run this file directly to generate a key
if (import.meta.url === `file://${process.argv[1]}`) {
  const service = new KeyGenerationService();
  service
    .generateInitialKey()
    .then((keyId) => {
      logger.info(`\n✓ Initial signing key generated successfully!`);
      logger.info({ keyId }, `Key ID: ${keyId}`);
      process.exit(0);
    })
    .catch((error) => {
      logger.error({ err: error }, '✗ Failed to generate signing key');
      process.exit(1);
    });
}
