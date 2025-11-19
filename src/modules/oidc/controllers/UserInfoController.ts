import { type Request, type Response } from 'express';
import { TokenService } from '../../oauth/services/TokenService.js';
import { config } from '../../../shared/config/index.js';
import { db, users } from '../../../shared/database/index.js';
import { eq } from 'drizzle-orm';

/**
 * UserInfo Response according to OIDC spec
 */
interface UserInfoResponse {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
}

/**
 * UserInfo Controller
 * Handles the OIDC UserInfo endpoint
 */
export class UserInfoController {
  private tokenService: TokenService;

  constructor() {
    this.tokenService = new TokenService(config.issuer);
  }

  /**
   * GET /oauth/userinfo
   * Returns user claims based on the access token and granted scopes
   * Requires a valid Bearer token in the Authorization header
   */
  async getUserInfo(req: Request, res: Response): Promise<void> {
    // Extract Bearer token from Authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Missing or invalid Authorization header',
      });
      return;
    }

    const token = authHeader.substring(7); // Remove "Bearer " prefix

    // Verify token
    const verificationResult = await this.tokenService.verifyToken(token);

    if (!verificationResult.valid) {
      res.status(401).json({
        error: 'invalid_token',
        error_description: verificationResult.error ?? 'Token verification failed',
      });
      return;
    }

    const payload = verificationResult.payload as any;

    // Extract user ID and scopes from token
    const userId = payload.sub;
    const scope = payload.scope ?? '';
    const scopes = scope.split(' ');

    // Check if openid scope is present (required for UserInfo endpoint)
    if (!scopes.includes('openid')) {
      res.status(403).json({
        error: 'insufficient_scope',
        error_description: 'The openid scope is required to access UserInfo endpoint',
      });
      return;
    }

    // Fetch user from database
    const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);

    if (!user) {
      res.status(404).json({
        error: 'user_not_found',
        error_description: 'User not found',
      });
      return;
    }

    // Build UserInfo response based on granted scopes
    const userInfo: UserInfoResponse = {
      sub: userId,
    };

    // Add email claims if email scope is granted
    if (scopes.includes('email')) {
      userInfo.email = user.email;
      userInfo.email_verified = user.emailVerified;
    }

    // Add profile claims if profile scope is granted
    // Note: Current schema doesn't have name/picture fields
    // This is a placeholder for when those fields are added
    if (scopes.includes('profile')) {
      // userInfo.name = user.name;
      // userInfo.given_name = user.givenName;
      // userInfo.family_name = user.familyName;
      // userInfo.picture = user.picture;

      // For now, we can derive a name from email
      const emailLocalPart = user.email.split('@')[0];
      userInfo.name = emailLocalPart;
    }

    // Return UserInfo response
    res.json(userInfo);
  }
}

export const userInfoController = new UserInfoController();
