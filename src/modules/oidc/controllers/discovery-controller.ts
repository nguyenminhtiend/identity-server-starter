import { type Request, type Response } from 'express';
import type { OIDCService } from '../services';

/**
 * Discovery Controller
 * Handles OpenID Connect Discovery endpoints
 */
export class DiscoveryController {
  private oidcService: OIDCService;

  constructor(oidcService: OIDCService) {
    this.oidcService = oidcService;
  }

  /**
   * GET /.well-known/openid-configuration
   * Returns the OpenID Connect Discovery Document
   */
  getDiscoveryDocument = (_req: Request, res: Response): void => {
    const discoveryDocument = this.oidcService.getDiscoveryDocument();

    res.json(discoveryDocument);
  };
}
