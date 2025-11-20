import { type Request, type Response } from 'express';
import { loginRequestSchema, registerRequestSchema } from '../validators';
import type { IUserService } from '../../user/services';

/**
 * Helper to safely extract string value from request body
 */
function getStringFromBody(body: unknown, key: string, defaultValue = ''): string {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
  const value = (body as any)[key];
  return typeof value === 'string' ? value : defaultValue;
}

/**
 * Authentication Controller
 * Handles user login, registration, and logout
 */
export class AuthController {
  constructor(private userService: IUserService) {}

  /**
   * GET /login
   * Display login page
   */
  showLogin = (req: Request, res: Response): void => {
    const returnUrl = (req.query.returnUrl as string) || '/';
    const error = req.query.error as string;

    res.render('auth/views/login', {
      returnUrl,
      error,
      email: '',
    });
  };

  /**
   * POST /login
   * Handle login form submission
   */
  login = async (req: Request, res: Response): Promise<void> => {
    try {
      // Validate input
      const { email, password, remember } = loginRequestSchema.parse(req.body);
      const returnUrl = getStringFromBody(req.body, 'returnUrl', '/');

      // Authenticate user
      const userId = await this.userService.authenticateUser(email, password);

      if (userId === null) {
        // Authentication failed
        const loginError = 'Invalid email or password';
        res.render('auth/views/login', {
          returnUrl,
          error: loginError,
          email,
        });
        return;
      }

      // Set session
      req.session.userId = userId;

      // Extend session TTL if remember me is checked
      if (remember === true && req.session.cookie !== undefined) {
        req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
      }

      // Save session and redirect
      await new Promise<void>((resolve, reject) => {
        req.session.save((err) => {
          if (err !== undefined && err !== null) {
            reject(new Error(`Session save failed: ${String(err)}`));
          } else {
            resolve();
          }
        });
      });

      res.redirect(returnUrl);
    } catch (error) {
      // Validation error or other error
      const returnUrl = getStringFromBody(req.body, 'returnUrl', '/');
      const emailValue = getStringFromBody(req.body, 'email');
      const errorMessage: string =
        error instanceof Error ? error.message : 'An error occurred during login';

      res.render('auth/views/login', {
        returnUrl,
        error: errorMessage,
        email: emailValue,
      });
    }
  };

  /**
   * GET /register
   * Display registration page
   */
  showRegister = (_req: Request, res: Response): void => {
    res.render('auth/views/register', {
      error: null,
      email: '',
    });
  };

  /**
   * POST /register
   * Handle registration form submission
   */
  register = async (req: Request, res: Response): Promise<void> => {
    try {
      // Validate input
      const { email, password } = registerRequestSchema.parse(req.body);

      // Check if email already exists
      const emailExists = await this.userService.emailExists(email);
      if (emailExists) {
        const registerError = 'Email already exists';
        res.render('auth/views/register', {
          error: registerError,
          email,
        });
        return;
      }

      // Create user
      const userId = await this.userService.createUser(email, password);

      // Set session (auto-login after registration)
      req.session.userId = userId;

      // Save session and redirect
      await new Promise<void>((resolve, reject) => {
        req.session.save((err) => {
          if (err !== undefined && err !== null) {
            reject(new Error(`Session save failed: ${String(err)}`));
          } else {
            resolve();
          }
        });
      });

      // Redirect to home or dashboard
      res.redirect('/');
    } catch (error) {
      const emailValue = getStringFromBody(req.body, 'email');
      const errorMessage: string =
        error instanceof Error ? error.message : 'An error occurred during registration';

      res.render('auth/views/register', {
        error: errorMessage,
        email: emailValue,
      });
    }
  };

  /**
   * GET /logout
   * Handle logout
   */
  logout = async (req: Request, res: Response): Promise<void> => {
    // Destroy session
    await new Promise<void>((resolve) => {
      req.session.destroy((err) => {
        if (err !== undefined && err !== null) {
          console.error('Session destruction error:', err);
        }
        resolve();
      });
    });

    // Clear cookie
    res.clearCookie('sid');

    // Redirect to login
    res.redirect('/login');
  };
}
