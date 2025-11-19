import rateLimit from 'express-rate-limit';
import type { Request, Response } from 'express';

/**
 * Custom key generator that uses IP address
 * In production, consider using a more sophisticated approach
 * that takes into account proxies and load balancers
 */
function getClientIp(req: Request): string {
  // Check for common proxy headers
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }

  const realIp = req.headers['x-real-ip'];
  if (typeof realIp === 'string') {
    return realIp;
  }

  // Fall back to socket address
  return req.socket.remoteAddress || 'unknown';
}

/**
 * Custom handler for rate limit exceeded
 */
function rateLimitHandler(req: Request, res: Response): void {
  res.status(429).json({
    error: 'too_many_requests',
    error_description: 'Too many requests, please try again later',
  });
}

/**
 * Rate limiter for token endpoint
 * Stricter limits due to security sensitivity
 * 10 requests per minute per IP
 */
export const tokenRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per window
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  keyGenerator: getClientIp,
  handler: rateLimitHandler,
  skip: (_req) => {
    // Skip rate limiting in test environment
    return process.env.NODE_ENV === 'test';
  },
});

/**
 * Rate limiter for authorization endpoint
 * Moderate limits for user-facing flows
 * 20 requests per minute per IP
 */
export const authRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  handler: rateLimitHandler,
  skip: (_req) => {
    return process.env.NODE_ENV === 'test';
  },
});

/**
 * Rate limiter for login endpoint
 * Prevent brute force attacks
 * 5 requests per minute per IP
 */
export const loginRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  handler: rateLimitHandler,
  skip: (_req) => {
    return process.env.NODE_ENV === 'test';
  },
  skipSuccessfulRequests: true, // Only count failed attempts
});

/**
 * Rate limiter for registration endpoint
 * Prevent spam registrations
 * 3 requests per 15 minutes per IP
 */
export const registerRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // 3 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  handler: rateLimitHandler,
  skip: (_req) => {
    return process.env.NODE_ENV === 'test';
  },
});

/**
 * Rate limiter for admin endpoints
 * Moderate protection for sensitive operations
 * 30 requests per minute per IP
 */
export const adminRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  handler: rateLimitHandler,
  skip: (_req) => {
    return process.env.NODE_ENV === 'test';
  },
});

/**
 * General API rate limiter
 * Applied to all routes not covered by specific limiters
 * 100 requests per minute per IP
 */
export const generalRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  handler: rateLimitHandler,
  skip: (_req) => {
    return process.env.NODE_ENV === 'test';
  },
});

/**
 * JWKS endpoint rate limiter
 * More relaxed since this is a public endpoint
 * but still needs protection against abuse
 * 60 requests per minute per IP
 */
export const jwksRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  handler: rateLimitHandler,
  skip: (_req) => {
    return process.env.NODE_ENV === 'test';
  },
});

/**
 * Discovery endpoint rate limiter
 * More relaxed since this is a public endpoint
 * 60 requests per minute per IP
 */
export const discoveryRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  handler: rateLimitHandler,
  skip: (_req) => {
    return process.env.NODE_ENV === 'test';
  },
});
