import { Router, type Router as RouterType } from 'express';
import { AuthController } from '../controllers';
import type { Services } from '../../../shared/services';

/**
 * Create Auth router with injected services
 * @param services - Application services
 * @returns Configured Auth router
 */
export function createAuthRouter(services: Services): RouterType {
  const { userService } = services;

  // Initialize controller with injected dependencies
  const authController = new AuthController(userService);

  const router: RouterType = Router();

  /**
   * GET /
   * Display home page (requires authentication)
   */
  router.get('/', authController.showHome);

  /**
   * GET /login
   * Display login page
   */
  router.get('/login', authController.showLogin);

  /**
   * POST /login
   * Handle login form submission
   */
  router.post('/login', authController.login);

  /**
   * GET /register
   * Display registration page
   */
  router.get('/register', authController.showRegister);

  /**
   * POST /register
   * Handle registration form submission
   */
  router.post('/register', authController.register);

  /**
   * GET /logout
   * Handle logout
   */
  router.get('/logout', authController.logout);

  return router;
}
