import type { Request, Response, NextFunction } from 'express';
import { OAuthErrors } from './error-handler.middleware.js';

/**
 * Extended Express Request with authenticated user
 */
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    email_verified: boolean;
  };
  client?: {
    id: string;
    client_id: string;
    name: string;
    client_type: 'confidential' | 'public';
  };
}

/**
 * Session-based authentication middleware
 * Checks if user is authenticated via session
 * Used for UI routes (login, consent, etc.)
 */
export function requireSession(req: Request, res: Response, next: NextFunction): void {
  const authReq = req as AuthenticatedRequest;

  if (!req.session?.userId) {
    // Store the original URL for redirect after login
    req.session.returnTo = req.originalUrl;

    res.redirect('/login');
    return;
  }

  // Attach user info from session to request
  authReq.user = {
    id: req.session.userId,
    email: req.session.userEmail ?? '',
    email_verified: req.session.emailVerified ?? false,
  };

  next();
}

/**
 * Optional session authentication
 * Attaches user info if session exists, but doesn't require it
 */
export function optionalSession(req: Request, _res: Response, next: NextFunction): void {
  const authReq = req as AuthenticatedRequest;

  if (req.session?.userId) {
    authReq.user = {
      id: req.session.userId,
      email: req.session.userEmail ?? '',
      email_verified: req.session.emailVerified ?? false,
    };
  }

  next();
}

/**
 * JWT Bearer token authentication middleware
 * Verifies access token from Authorization header
 * Used for API routes (userinfo, introspection, etc.)
 */
export function requireBearerToken(req: Request, _res: Response, _next: NextFunction): void {
  // const _authReq = req as AuthenticatedRequest;
  const authHeader = req.headers.authorization;

  // eslint-disable-next-line @typescript-eslint/strict-boolean-expressions
  if (!authHeader?.startsWith('Bearer ')) {
    throw OAuthErrors.INVALID_REQUEST('Missing or invalid Authorization header');
  }

  const token = authHeader.substring(7); // Remove 'Bearer ' prefix

  if (token.length === 0) {
    throw OAuthErrors.INVALID_REQUEST('Access token is required');
  }

  try {
    // Token verification will be implemented in TokenService
    // For now, we'll add a placeholder
    // The actual verification will use KeyManagementService
    // This middleware will be updated in Phase 5 when TokenService is ready

    // TODO: Verify token using TokenService.verifyAccessToken()
    // const payload = await tokenService.verifyAccessToken(token);
    // authReq.user = payload.user;

    // Placeholder for now
    throw new Error('Token verification not yet implemented');
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('expired')) {
        throw OAuthErrors.INVALID_REQUEST('Access token has expired');
      }
      throw OAuthErrors.INVALID_REQUEST('Invalid access token');
    }
    throw error;
  }
}

/**
 * Client authentication middleware
 * Verifies client credentials from Authorization header or request body
 * Used for token endpoint and other client-authenticated endpoints
 */
export function requireClientAuth(req: Request, _res: Response, _next: NextFunction): void {
  // const _authReq = req as AuthenticatedRequest;

  let clientId: string | undefined;
  // let _clientSecret: string | undefined;

  // Try to get credentials from Authorization header (Basic Auth)
  const authHeader = req.headers.authorization;
  // eslint-disable-next-line @typescript-eslint/strict-boolean-expressions
  if (authHeader?.startsWith('Basic ')) {
    const base64Credentials = authHeader.substring(6);
    const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
    [clientId] = credentials.split(':');
  }

  // Fall back to request body (client_secret_post)
  clientId ??= (req.body as { client_id?: string }).client_id;

  if (!clientId) {
    throw OAuthErrors.INVALID_CLIENT('Client authentication required');
  }

  try {
    // Client verification will be implemented in ClientService
    // For now, we'll add a placeholder
    // This middleware will be updated in Phase 5 when ClientService is ready

    // TODO: Verify client using ClientService.verifyCredentials()
    // const client = await clientService.verifyCredentials(clientId, clientSecret);
    // authReq.client = client;

    // Placeholder for now
    throw new Error('Client verification not yet implemented');
  } catch (_error) {
    throw OAuthErrors.INVALID_CLIENT('Invalid client credentials');
  }
}

/**
 * Admin authentication middleware
 * Requires user to be authenticated and have admin role
 * Used for admin panel routes
 */
export async function requireAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authReq = req as AuthenticatedRequest;

  if (!req.session?.userId) {
    res.redirect('/login');
    return;
  }

  // Import db and users here to avoid circular dependencies
  const { db, users } = await import('../database/index.js');
  const { eq } = await import('drizzle-orm');

  // Query database to check admin role
  const userResult = await db.select().from(users).where(eq(users.id, req.session.userId)).limit(1);

  if (!userResult[0]) {
    res.redirect('/login');
    return;
  }

  const user = userResult[0];

  if (!user.isAdmin) {
    throw OAuthErrors.ACCESS_DENIED('Admin access required');
  }

  authReq.user = {
    id: user.id,
    email: user.email,
    email_verified: user.emailVerified,
  };

  next();
}

/**
 * Extend Express Session to include user data
 */
declare module 'express-session' {
  interface SessionData {
    userId?: string;
    userEmail?: string;
    emailVerified?: boolean;
    returnTo?: string;

    // OAuth flow state
    oauthState?: {
      clientId: string;
      redirectUri: string;
      scope: string;
      codeChallenge: string;
      codeChallengeMethod: string;
      state?: string;
      nonce?: string;
    };
  }
}
