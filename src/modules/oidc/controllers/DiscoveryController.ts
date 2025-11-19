import { type Request, type Response } from 'express';
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
  getDiscoveryDocument(_req: Request, res: Response): void {
    const discoveryDocument = oidcService.getDiscoveryDocument();

    res.json(discoveryDocument);
  }
}

export const discoveryController = new DiscoveryController();
