import type { Request, Response, NextFunction } from 'express';

/**
 * Custom error class for OAuth 2.0 errors
 * Following RFC 6749 error response format
 */
export class OAuthError extends Error {
  constructor(
    public error: string,
    public error_description: string,
    public statusCode = 400,
    public error_uri?: string
  ) {
    super(error_description);
    this.name = 'OAuthError';
  }
}

/**
 * Predefined OAuth error types
 */
export const OAuthErrors = {
  INVALID_REQUEST: (description: string) => new OAuthError('invalid_request', description, 400),

  INVALID_CLIENT: (description: string) => new OAuthError('invalid_client', description, 401),

  INVALID_GRANT: (description: string) => new OAuthError('invalid_grant', description, 400),

  UNAUTHORIZED_CLIENT: (description: string) =>
    new OAuthError('unauthorized_client', description, 400),

  UNSUPPORTED_GRANT_TYPE: (description: string) =>
    new OAuthError('unsupported_grant_type', description, 400),

  INVALID_SCOPE: (description: string) => new OAuthError('invalid_scope', description, 400),

  ACCESS_DENIED: (description: string) => new OAuthError('access_denied', description, 403),

  SERVER_ERROR: (description: string) => new OAuthError('server_error', description, 500),

  TEMPORARILY_UNAVAILABLE: (description: string) =>
    new OAuthError('temporarily_unavailable', description, 503),
};

/**
 * Global error handler middleware
 * Handles OAuth errors, validation errors, and general errors
 */
export function errorHandler(err: Error, req: Request, res: Response, _next: NextFunction): void {
  // Log error for debugging
  console.error('[Error Handler]', {
    name: err.name,
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method,
  });

  // Handle OAuth errors
  if (err instanceof OAuthError) {
    res.status(err.statusCode).json({
      error: err.error,
      error_description: err.error_description,
      ...(err.error_uri && { error_uri: err.error_uri }),
    });
    return;
  }

  // Handle Zod validation errors
  if (err.name === 'ZodError') {
    const zodError = err as any;
    const messages = zodError.errors
      ?.map((e: any) => `${e.path.join('.')}: ${e.message}`)
      .join(', ');

    res.status(400).json({
      error: 'invalid_request',
      error_description: messages || 'Validation failed',
    });
    return;
  }

  // Handle JWT errors
  if (err.name === 'JWTExpired' || err.name === 'JWTInvalid') {
    res.status(401).json({
      error: 'invalid_token',
      error_description: 'The access token provided is expired, revoked, or invalid',
    });
    return;
  }

  // Handle generic errors
  const statusCode = (err as any).statusCode || 500;
  const isDevelopment = process.env.NODE_ENV === 'development';

  res.status(statusCode).json({
    error: 'server_error',
    error_description: isDevelopment ? err.message : 'An internal server error occurred',
    ...(isDevelopment && { stack: err.stack }),
  });
}

/**
 * Async error wrapper to catch errors in async route handlers
 */
export function asyncHandler<T>(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<T>
) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * 404 Not Found handler
 */
export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({
    error: 'not_found',
    error_description: `Route ${req.method} ${req.path} not found`,
  });
}
