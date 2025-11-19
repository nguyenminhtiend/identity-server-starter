import { type z, ZodError } from 'zod';
import { type Request, type Response, type NextFunction } from 'express';

/**
 * Validation utilities for request validation
 * Provides middleware and helper functions for Zod schema validation
 */

/**
 * Validation error response format
 */
export interface ValidationErrorResponse {
  error: string;
  errors: {
    field: string;
    message: string;
  }[];
}

/**
 * Format Zod validation errors for API response
 * @param error - Zod validation error
 * @returns Formatted error response
 */
export function formatValidationError(error: ZodError): ValidationErrorResponse {
  return {
    error: 'Validation failed',
    errors: error.errors.map((err) => {
      const field = err.path.join('.');
      const message = err.message;
      return {
        field,
        message,
      };
    }),
  };
}

/**
 * Create validation middleware for request body
 * @param schema - Zod schema to validate against
 * @returns Express middleware
 */
export function validateBody<T extends z.ZodType>(schema: T) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body = await schema.parseAsync(req.body);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        return res.status(400).json(formatValidationError(error));
      }
      next(error);
    }
  };
}

/**
 * Create validation middleware for query parameters
 * @param schema - Zod schema to validate against
 * @returns Express middleware
 */
export function validateQuery<T extends z.ZodType>(schema: T) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      req.query = await schema.parseAsync(req.query);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        return res.status(400).json(formatValidationError(error));
      }
      next(error);
    }
  };
}

/**
 * Create validation middleware for route parameters
 * @param schema - Zod schema to validate against
 * @returns Express middleware
 */
export function validateParams<T extends z.ZodType>(schema: T) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      req.params = await schema.parseAsync(req.params);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        return res.status(400).json(formatValidationError(error));
      }
      next(error);
    }
  };
}

/**
 * Validate data synchronously
 * @param schema - Zod schema
 * @param data - Data to validate
 * @returns Validation result with parsed data or errors
 */
export function validate<T extends z.ZodType>(
  schema: T,
  data: unknown
): { success: true; data: z.infer<T> } | { success: false; errors: ValidationErrorResponse } {
  const result = schema.safeParse(data);

  if (result.success) {
    return { success: true, data: result.data };
  }

  return {
    success: false,
    errors: formatValidationError(result.error),
  };
}

/**
 * Check if a string is a valid URL
 * @param url - URL string to validate
 * @returns True if valid URL
 */
export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if a string is a valid UUID
 * @param uuid - UUID string to validate
 * @returns True if valid UUID
 */
export function isValidUuid(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

/**
 * Check if a string is a valid email
 * @param email - Email string to validate
 * @returns True if valid email
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Sanitize string for safe output (prevent XSS)
 * @param str - String to sanitize
 * @returns Sanitized string
 */
export function sanitizeString(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Validate OAuth scope format
 * @param scope - Scope string to validate
 * @returns True if valid scope format
 */
export function isValidScope(scope: string): boolean {
  // Scopes should be space-separated alphanumeric strings with _ and -
  const scopeRegex = /^[a-zA-Z0-9_-]+(\s+[a-zA-Z0-9_-]+)*$/;
  return scopeRegex.test(scope.trim());
}

/**
 * Parse and validate scopes array
 * @param scope - Space-separated scope string
 * @returns Array of individual scopes
 */
export function parseScopes(scope: string): string[] {
  return scope
    .split(' ')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Check if all required scopes are present
 * @param grantedScopes - Space-separated granted scopes
 * @param requiredScopes - Array of required scopes
 * @returns True if all required scopes are granted
 */
export function hasRequiredScopes(grantedScopes: string, requiredScopes: string[]): boolean {
  const granted = parseScopes(grantedScopes);
  return requiredScopes.every((required) => granted.includes(required));
}
