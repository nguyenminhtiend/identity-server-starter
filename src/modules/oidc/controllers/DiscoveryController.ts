import { type Request, type Response, type NextFunction } from 'express';
import { oidcService } from '../services/OIDCService.js';

/**
 * Discovery Controller
 * Handles OpenID Connect Discovery endpoints
 */
export class DiscoveryController {
  /**
   * GET /.well-known/openid-configuration
   * Returns the OpenID Connect Discovery Document
   */
  getDiscoveryDocument(_req: Request, res: Response, next: NextFunction): void {
    try {
      const discoveryDocument = oidcService.getDiscoveryDocument();

      res.json(discoveryDocument);
    } catch (error) {
      next(error);
    }
  }
}

export const discoveryController = new DiscoveryController();
