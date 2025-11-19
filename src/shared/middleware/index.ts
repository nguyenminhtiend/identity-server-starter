/**
 * Middleware exports
 * Centralized exports for all middleware modules
 */

// Error handling
export {
  OAuthError,
  OAuthErrors,
  errorHandler,
  asyncHandler,
  notFoundHandler,
} from './errorHandler.js';

// Authentication
export {
  requireSession,
  optionalSession,
  requireBearerToken,
  requireClientAuth,
  requireAdmin,
  type AuthenticatedRequest,
} from './authenticate.js';

// Rate limiting
export {
  tokenRateLimiter,
  authRateLimiter,
  loginRateLimiter,
  registerRateLimiter,
  adminRateLimiter,
  generalRateLimiter,
  jwksRateLimiter,
  discoveryRateLimiter,
} from './rateLimiter.js';

// Security
export {
  helmetConfig,
  createCorsMiddleware,
  devCorsMiddleware,
  enforceHttps,
  oauthSecurityHeaders,
  csrfProtection,
  generateCsrfToken,
} from './security.js';

// Validation
export {
  validate,
  validateBody,
  validateQuery,
  validateParams,
  validateHeaders,
  commonSchemas,
  jsonStringSchema,
  commaSeparatedString,
} from './validator.js';
