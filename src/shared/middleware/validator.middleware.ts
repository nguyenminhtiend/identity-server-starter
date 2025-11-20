import type { Request, Response, NextFunction } from 'express';
import { z, type ZodType, ZodError } from 'zod';
import { OAuthErrors } from './error-handler.middleware.js';

/**
 * Validation target: where to validate data from
 */
type ValidationTarget = 'body' | 'query' | 'params' | 'headers';

/**
 * Validation options
 */
interface ValidateOptions {
  target?: ValidationTarget;
  stripUnknown?: boolean; // Remove unknown fields
}

/**
 * Generic validation middleware factory
 * Validates request data against a Zod schema
 */
export function validate(schema: ZodType, options: ValidateOptions = {}) {
  const { target = 'body', stripUnknown = true } = options;

  return (req: Request, _res: Response, next: NextFunction): void => {
    try {
      // Get data from the specified target
      const data = (req as unknown as Record<string, unknown>)[target];

      // Parse and validate data
      const parsed = stripUnknown ? schema.parse(data) : schema.parse(data);

      // Replace request data with validated data
      (req as unknown as Record<string, unknown>)[target] = parsed;

      next();
    } catch (error) {
      if (error instanceof ZodError) {
        // Format Zod errors into OAuth-friendly format
        const messages = error.issues.map((err) => {
          const path = err.path.join('.');
          return path.length > 0 ? `${path}: ${err.message}` : err.message;
        });

        throw OAuthErrors.INVALID_REQUEST(messages.join(', '));
      }

      // Re-throw other errors
      throw error;
    }
  };
}

/**
 * Validate request body
 */
export function validateBody(schema: ZodType) {
  return validate(schema, { target: 'body' });
}

/**
 * Validate query parameters
 */
export function validateQuery(schema: ZodType) {
  return validate(schema, { target: 'query' });
}

/**
 * Validate URL parameters
 */
export function validateParams(schema: ZodType) {
  return validate(schema, { target: 'params' });
}

/**
 * Validate request headers
 */
export function validateHeaders(schema: ZodType) {
  return validate(schema, { target: 'headers', stripUnknown: false });
}

/**
 * Common validation schemas
 */
export const commonSchemas = {
  /**
   * UUID validation
   */
  uuid: z.uuid(),

  /**
   * Email validation
   */
  email: z.email().toLowerCase(),

  /**
   * Password validation (2025 standards)
   * - At least 8 characters
   * - At least one uppercase letter
   * - At least one lowercase letter
   * - At least one number
   * - At least one special character
   */
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),

  /**
   * URL validation
   */
  url: z.url(),

  /**
   * Redirect URI validation
   * Must be HTTPS in production, can be HTTP for localhost
   */
  redirectUri: z.url().refine(
    (url) => {
      const parsed = new URL(url);

      // Allow HTTP for localhost in development
      if (process.env.NODE_ENV === 'development') {
        if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
          return true;
        }
      }

      // Require HTTPS for all other cases
      return parsed.protocol === 'https:';
    },
    {
      message: 'Redirect URI must use HTTPS (except localhost in development)',
    }
  ),

  /**
   * Client ID validation
   */
  clientId: z.string().min(1).max(255),

  /**
   * Client secret validation
   */
  clientSecret: z.string().min(32).max(255),

  /**
   * OAuth scope validation
   * Space-separated list of scopes
   */
  scope: z
    .string()
    .regex(/^[\w\s]+$/, 'Scope must contain only alphanumeric characters and spaces')
    .transform((val) => val.trim()),

  /**
   * Grant type validation
   */
  grantType: z.enum(['authorization_code', 'refresh_token', 'client_credentials']),

  /**
   * Response type validation
   */
  responseType: z.enum(['code']),

  /**
   * Code challenge method validation (PKCE)
   */
  codeChallengeMethod: z.enum(['S256']),

  /**
   * Code challenge validation
   * Base64 URL encoded string, 43-128 characters
   */
  codeChallenge: z
    .string()
    .min(43, 'Code challenge must be at least 43 characters')
    .max(128, 'Code challenge must be at most 128 characters')
    .regex(/^[A-Za-z0-9_-]+$/, 'Code challenge must be base64url encoded'),

  /**
   * Code verifier validation (PKCE)
   * 43-128 characters
   */
  codeVerifier: z
    .string()
    .min(43, 'Code verifier must be at least 43 characters')
    .max(128, 'Code verifier must be at most 128 characters')
    .regex(/^[A-Za-z0-9_-]+$/, 'Code verifier must contain only unreserved characters'),

  /**
   * State parameter validation
   * Optional, but recommended for CSRF protection
   */
  state: z.optional(z.string()),

  /**
   * Nonce validation (OIDC)
   * Optional, but recommended for replay protection
   */
  nonce: z.optional(z.string()),

  /**
   * Client type validation
   */
  clientType: z.enum(['confidential', 'public']),

  /**
   * Boolean string validation
   * Converts string "true"/"false" to boolean
   */
  booleanString: z
    .string()
    .transform((val) => val === 'true')
    .pipe(z.boolean()),

  /**
   * Pagination limit validation
   */
  paginationLimit: z
    .optional(z.string())
    .transform((val) => (val ? parseInt(val, 10) : 20))
    .pipe(z.number().min(1).max(100)),

  /**
   * Pagination offset validation
   */
  paginationOffset: z
    .optional(z.string())
    .transform((val) => (val ? parseInt(val, 10) : 0))
    .pipe(z.number().min(0)),
};

/**
 * Helper to create a schema for JSON string fields
 * Useful for validating JSON fields in query parameters
 */
export function jsonStringSchema<T>(schema: z.ZodType<T>) {
  return z
    .string()
    .transform((val): unknown => {
      try {
        return JSON.parse(val) as unknown;
      } catch {
        throw new Error('Invalid JSON string');
      }
    })
    .pipe(schema);
}

/**
 * Helper to create a schema for comma-separated string arrays
 */
export function commaSeparatedString(itemSchema?: ZodType) {
  const schema = itemSchema ?? z.string();

  return z
    .string()
    .transform((val) => val.split(',').map((item) => item.trim()))
    .pipe(z.array(schema) as any);
}
