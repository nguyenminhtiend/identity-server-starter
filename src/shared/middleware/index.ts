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
} from './error-handler.middleware.js';

// Authentication
export {
  requireSession,
  optionalSession,
  requireBearerToken,
  requireClientAuth,
  requireAdmin,
  type AuthenticatedRequest,
} from './authenticate.middleware.js';

// Security
export {
  helmetConfig,
  createCorsMiddleware,
  devCorsMiddleware,
  enforceHttps,
  oauthSecurityHeaders,
  csrfProtection,
  generateCsrfToken,
} from './security.middleware.js';

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
} from './validator.middleware.js';
