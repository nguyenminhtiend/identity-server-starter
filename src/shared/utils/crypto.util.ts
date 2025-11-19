import crypto from 'crypto';
import bcrypt from 'bcrypt';

/**
 * Hash a password using bcrypt with 12 rounds
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

/**
 * Verify a password against a bcrypt hash
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Generate a random token using crypto.randomBytes
 */
export function generateRandomToken(length = 32): string {
  return crypto.randomBytes(length).toString('base64url');
}

/**
 * Generate SHA256 hash of a string (used for refresh token hashing)
 */
export function sha256Hash(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Hash a string using SHA256 and encode as base64url (for PKCE code_challenge)
 * @param data - String to hash
 * @returns Base64URL-encoded SHA256 hash
 */
export function sha256Base64Url(data: string): string {
  return crypto.createHash('sha256').update(data).digest('base64url').replace(/=/g, '');
}

/**
 * Constant-time string comparison to prevent timing attacks
 * @param a - First string
 * @param b - Second string
 * @returns True if strings match, false otherwise
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * Generate a master encryption key (for KEY_ENCRYPTION_SECRET)
 * @returns 64-character hex string (32 bytes)
 */
export function generateMasterKey(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Encrypt data using AES-256-GCM
 */
export function encryptAES(data: string, secret: string): string {
  // Derive a key from the secret
  const key = crypto.scryptSync(secret, 'salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  // Return iv:authTag:encrypted
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypt data using AES-256-GCM
 */
export function decryptAES(encryptedData: string, secret: string): string {
  const [ivHex, authTagHex, encrypted] = encryptedData.split(':');

  if (!ivHex || !authTagHex || !encrypted) {
    throw new Error('Invalid encrypted data format');
  }

  const key = crypto.scryptSync(secret, 'salt', 32);
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Generate RSA key pair (2048-bit) for JWT signing
 */
export function generateRSAKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return { publicKey, privateKey };
}
