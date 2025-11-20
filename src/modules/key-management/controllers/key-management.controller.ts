import { type Request, type Response } from 'express';
import type { IKeyManagementService } from '../services/interfaces';
import { logger } from '../../../shared/utils';

/**
 * Key Management Controller
 * Handles admin operations for cryptographic key management
 */
export class KeyManagementController {
  constructor(private keyManagementService: IKeyManagementService) {}

  /**
   * GET /admin/keys
   * List all signing keys (active and inactive)
   */
  listKeys = async (_req: Request, res: Response): Promise<void> => {
    try {
      const keys = await this.keyManagementService.listAllKeys();

      // Never return private keys, only metadata
      const safeKeys = keys.map((key) => ({
        id: key.id,
        keyId: key.keyId,
        algorithm: key.algorithm,
        isActive: key.isActive,
        isPrimary: key.isPrimary,
        createdAt: key.createdAt,
        expiresAt: key.expiresAt,
        rotatedAt: key.rotatedAt,
        nextRotationAt: key.nextRotationAt,
        // Include public key for verification purposes
        publicKeyPem: key.publicKeyPem,
      }));

      res.json({
        success: true,
        data: safeKeys,
        count: safeKeys.length,
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to list keys');
      const errorMessage = error instanceof Error ? error.message : 'Failed to list keys';
      res.status(500).json({
        success: false,
        error: 'key_list_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * POST /admin/keys/rotate
   * Manually trigger key rotation
   */
  rotateKeys = async (req: Request, res: Response): Promise<void> => {
    try {
      const { confirm } = req.body as { confirm?: boolean };

      if (confirm !== true) {
        res.status(400).json({
          success: false,
          error: 'confirmation_required',
          error_description: 'You must confirm key rotation',
        });
        return;
      }

      await this.keyManagementService.rotateKeys();

      logger.warn('Key rotation completed successfully');

      res.json({
        success: true,
        message: 'Key rotation completed successfully. New primary key is now active.',
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to rotate keys');
      const errorMessage = error instanceof Error ? error.message : 'Failed to rotate keys';
      res.status(500).json({
        success: false,
        error: 'key_rotation_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * GET /admin/keys/rotation-status
   * Check next scheduled rotation
   */
  getRotationStatus = async (_req: Request, res: Response): Promise<void> => {
    try {
      const status = await this.keyManagementService.getRotationStatus();

      res.json({
        success: true,
        data: status,
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to get rotation status');
      const errorMessage = error instanceof Error ? error.message : 'Failed to get rotation status';
      res.status(500).json({
        success: false,
        error: 'rotation_status_fetch_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * GET /admin/keys/primary
   * Get current primary signing key metadata
   */
  getPrimaryKey = async (_req: Request, res: Response): Promise<void> => {
    try {
      const primaryKey = await this.keyManagementService.getPrimarySigningKey();

      // Return only metadata, not the private key
      res.json({
        success: true,
        data: {
          id: primaryKey.id,
          keyId: primaryKey.keyId,
          algorithm: primaryKey.algorithm,
          isActive: primaryKey.isActive,
          isPrimary: primaryKey.isPrimary,
          createdAt: primaryKey.createdAt,
          nextRotationAt: primaryKey.nextRotationAt,
          publicKeyPem: primaryKey.publicKeyPem,
        },
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to get primary key');
      const errorMessage = error instanceof Error ? error.message : 'Failed to get primary key';
      res.status(500).json({
        success: false,
        error: 'primary_key_fetch_failed',
        error_description: errorMessage,
      });
    }
  };
}
