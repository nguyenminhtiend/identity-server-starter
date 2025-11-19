import { type Request, type Response, type NextFunction } from 'express';
import { KeyManagementService } from '../../key-management/services/KeyManagementService.js';
import { config } from '../../../shared/config/index.js';

/**
 * JWKS Controller
 * Handles JSON Web Key Set endpoints
 */
export class JWKSController {
  private keyManagementService: KeyManagementService;

  constructor() {
    this.keyManagementService = KeyManagementService.getInstance(config.keys.encryptionSecret);
  }

  /**
   * GET /.well-known/jwks.json
   * Returns the JSON Web Key Set containing all active public keys
   * This endpoint is used by clients to verify JWT signatures
   */
  async getJWKS(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // Get all active public keys from KeyManagementService
      const publicKeys = await this.keyManagementService.getPublicKeys();

      // Return in JWKS format
      res.json({
        keys: publicKeys,
      });
    } catch (error) {
      next(error);
    }
  }
}

export const jwksController = new JWKSController();
