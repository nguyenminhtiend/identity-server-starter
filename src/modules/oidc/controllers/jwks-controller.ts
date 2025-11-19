import { type Request, type Response } from 'express';
import type { IKeyManagementService } from '../../key-management/services/interfaces/key-management-service.interface.js';

/**
 * JWKS Controller
 * Handles JSON Web Key Set endpoints
 */
export class JWKSController {
  private keyManagementService: IKeyManagementService;

  constructor(keyManagementService: IKeyManagementService) {
    this.keyManagementService = keyManagementService;
  }

  /**
   * GET /.well-known/jwks.json
   * Returns the JSON Web Key Set containing all active public keys
   * This endpoint is used by clients to verify JWT signatures
   */
  async getJWKS(_req: Request, res: Response): Promise<void> {
    // Get all active public keys from KeyManagementService
    const publicKeys = await this.keyManagementService.getPublicKeys();

    // Return in JWKS format
    res.json({
      keys: publicKeys,
    });
  }
}
