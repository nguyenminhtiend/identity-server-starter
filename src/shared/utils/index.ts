/**
 * Utility functions barrel export
 * Provides centralized access to crypto, logging, and validation utilities
 */

// Crypto utilities
export {
  hashPassword,
  verifyPassword,
  generateRandomToken,
  sha256Hash,
  sha256Base64Url,
  constantTimeCompare,
  generateMasterKey,
  encryptAES,
  decryptAES,
  generateRSAKeyPair,
} from './crypto.util.js';

// Logger utilities
export { logger, createLogger } from './logger.util.js';

// Validation utilities
export {
  formatValidationError,
  validateBody,
  validateQuery,
  validateParams,
  validate,
  isValidUrl,
  isValidUuid,
  isValidEmail,
  sanitizeString,
  isValidScope,
  parseScopes,
  hasRequiredScopes,
} from './validation.util.js';

// Types
export type { ValidationErrorResponse } from './validation.util.js';
