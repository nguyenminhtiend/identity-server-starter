import helmet from 'helmet';
import cors, { type CorsOptions } from 'cors';
import type { Request, Response, NextFunction } from 'express';

/**
 * Helmet security headers configuration
 * Following 2025 best practices
 */
export const helmetConfig = helmet({
  // Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for EJS templates
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'], // Allow images from HTTPS and data URIs
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },

  // Strict Transport Security (HSTS)
  // Force HTTPS for 1 year
  hsts: {
    maxAge: 31536000, // 1 year in seconds
    includeSubDomains: true,
    preload: true,
  },

  // Prevent MIME type sniffing
  noSniff: true,

  // Disable X-Powered-By header
  hidePoweredBy: true,

  // Prevent clickjacking
  frameguard: {
    action: 'deny',
  },

  // XSS Protection (legacy but still useful)
  xssFilter: true,

  // Referrer Policy
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin',
  },
});

/**
 * Dynamic CORS configuration
 * Checks if the origin is allowed for the requested client
 */
export function createCorsMiddleware(getAllowedOrigins: (clientId?: string) => Promise<string[]>) {
  const corsOptions: CorsOptions = {
    origin: async (origin, callback) => {
      // Allow requests with no origin (mobile apps, curl, etc.)
      if (!origin) {
        callback(null, true);
        return;
      }

      try {
        // In development, allow all origins
        if (process.env.NODE_ENV === 'development') {
          callback(null, true);
          return;
        }

        // Get allowed origins (will be enhanced to check per-client origins)
        const allowedOrigins = await getAllowedOrigins();

        if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS'));
        }
      } catch (error) {
        callback(error as Error);
      }
    },
    credentials: true, // Allow cookies
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
    exposedHeaders: ['RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset'],
    maxAge: 86400, // 24 hours
  };

  return cors(corsOptions);
}

/**
 * Simple CORS middleware for development
 * Allows all origins
 */
export const devCorsMiddleware = cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  exposedHeaders: ['RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset'],
});

/**
 * HTTPS enforcement middleware
 * Redirects HTTP to HTTPS in production
 */
export function enforceHttps(req: Request, res: Response, next: NextFunction): void {
  // Skip in development
  if (process.env.NODE_ENV !== 'production') {
    next();
    return;
  }

  // Check if request is already HTTPS
  const isHttps =
    req.secure ||
    req.headers['x-forwarded-proto'] === 'https' ||
    req.headers['x-forwarded-ssl'] === 'on';

  if (!isHttps) {
    // Redirect to HTTPS
    const httpsUrl = `https://${req.hostname}${req.url}`;
    res.redirect(301, httpsUrl);
    return;
  }

  next();
}

/**
 * Security headers for OAuth/OIDC responses
 * Adds cache control and no-store directives
 */
export function oauthSecurityHeaders(req: Request, res: Response, next: NextFunction): void {
  // Prevent caching of OAuth responses
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');

  next();
}

/**
 * CSRF protection for state-changing operations
 * Simple token-based implementation
 */
export function csrfProtection(req: Request, res: Response, next: NextFunction): void {
  // Skip for non-state-changing methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    next();
    return;
  }

  // Skip for API endpoints (protected by OAuth tokens)
  if (req.path.startsWith('/oauth/') || req.path.startsWith('/api/')) {
    next();
    return;
  }

  // Check CSRF token
  const csrfToken = req.body._csrf || req.headers['x-csrf-token'];
  const sessionToken = req.session?.csrfToken;

  if (!csrfToken || csrfToken !== sessionToken) {
    res.status(403).json({
      error: 'invalid_request',
      error_description: 'CSRF token validation failed',
    });
    return;
  }

  next();
}

/**
 * Generate and attach CSRF token to session
 */
export function generateCsrfToken(req: Request, res: Response, next: NextFunction): void {
  if (!req.session) {
    next();
    return;
  }

  // Generate CSRF token if not exists
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomUUID();
  }

  // Make CSRF token available to templates
  res.locals.csrfToken = req.session.csrfToken;

  next();
}

/**
 * Extend Express Session to include CSRF token
 */
declare module 'express-session' {
  interface SessionData {
    csrfToken?: string;
  }
}
