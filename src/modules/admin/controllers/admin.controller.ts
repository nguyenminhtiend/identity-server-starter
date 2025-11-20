import { type Request, type Response } from 'express';
import type { IClientService } from '../../client/services';
import { logger } from '../../../shared/utils';

/**
 * Admin Controller
 * Handles admin operations for client management
 */
export class AdminController {
  constructor(private clientService: IClientService) {}

  /**
   * POST /admin/clients
   * Create a new OAuth client
   */
  createClient = async (req: Request, res: Response): Promise<void> => {
    try {
      const input = req.body as {
        name: string;
        clientType: 'confidential' | 'public';
        redirectUris: string[];
        grantTypes: string[];
        allowedScopes: string;
        organizationId?: string;
        logoUrl?: string;
        allowedCorsOrigins?: string[];
        termsUrl?: string;
        privacyUrl?: string;
        homepageUrl?: string;
        contacts?: string[];
      };

      const result = await this.clientService.createClient(input);

      logger.info({ clientId: result.clientId }, 'Client created successfully');

      // Return client details including secret (only shown once)
      res.status(201).json({
        success: true,
        data: {
          id: result.id,
          clientId: result.clientId,
          clientSecret: result.clientSecret, // Only returned once!
          name: result.name,
          clientType: result.clientType,
          message:
            result.clientType === 'confidential'
              ? 'Client created successfully. Save the client_secret now - it will not be shown again!'
              : 'Client created successfully',
        },
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to create client');
      const errorMessage = error instanceof Error ? error.message : 'Failed to create client';
      res.status(400).json({
        success: false,
        error: 'client_creation_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * GET /admin/clients
   * List all clients with optional filters
   */
  listClients = async (req: Request, res: Response): Promise<void> => {
    try {
      let isActive: boolean | undefined;
      if (req.query.isActive === 'true') {
        isActive = true;
      } else if (req.query.isActive === 'false') {
        isActive = false;
      }

      const filters = {
        organizationId: req.query.organizationId as string | undefined,
        clientType: req.query.clientType as 'confidential' | 'public' | undefined,
        isActive,
        limit: req.query.limit !== undefined ? parseInt(req.query.limit as string, 10) : 20,
        offset: req.query.offset !== undefined ? parseInt(req.query.offset as string, 10) : 0,
      };

      const clients = await this.clientService.listClients(filters);

      res.json({
        success: true,
        data: clients,
        pagination: {
          limit: filters.limit,
          offset: filters.offset,
          count: clients.length,
        },
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to list clients');
      const errorMessage = error instanceof Error ? error.message : 'Failed to list clients';
      res.status(500).json({
        success: false,
        error: 'client_list_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * GET /admin/clients/:id
   * Get client details by ID
   */
  getClient = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: 'invalid_request',
          error_description: 'Client ID is required',
        });
        return;
      }

      const client = await this.clientService.getClientById(id);

      if (!client) {
        res.status(404).json({
          success: false,
          error: 'client_not_found',
          error_description: 'Client not found',
        });
        return;
      }

      res.json({
        success: true,
        data: client,
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to get client');
      const errorMessage = error instanceof Error ? error.message : 'Failed to get client';
      res.status(500).json({
        success: false,
        error: 'client_fetch_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * PUT /admin/clients/:id
   * Update client metadata
   */
  updateClient = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: 'invalid_request',
          error_description: 'Client ID is required',
        });
        return;
      }

      const input = req.body as {
        name?: string;
        redirectUris?: string[];
        logoUrl?: string;
        allowedCorsOrigins?: string[];
        termsUrl?: string;
        privacyUrl?: string;
        homepageUrl?: string;
        contacts?: string[];
        allowedScopes?: string;
        isActive?: boolean;
      };

      await this.clientService.updateClient(id, input);

      logger.info({ clientId: id }, 'Client updated successfully');

      res.json({
        success: true,
        message: 'Client updated successfully',
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to update client');
      const errorMessage = error instanceof Error ? error.message : 'Failed to update client';
      const statusCode = errorMessage.includes('not found') ? 404 : 400;
      res.status(statusCode).json({
        success: false,
        error: 'client_update_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * DELETE /admin/clients/:id
   * Delete or deactivate client
   */
  deleteClient = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: 'invalid_request',
          error_description: 'Client ID is required',
        });
        return;
      }

      const hard = req.query.hard === 'true';

      await this.clientService.deleteClient(id, hard);

      logger.info({ clientId: id, hard }, 'Client deleted successfully');

      res.json({
        success: true,
        message: hard ? 'Client permanently deleted' : 'Client deactivated',
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to delete client');
      const errorMessage = error instanceof Error ? error.message : 'Failed to delete client';
      const statusCode = errorMessage.includes('not found') ? 404 : 400;
      res.status(statusCode).json({
        success: false,
        error: 'client_deletion_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * POST /admin/clients/:id/secret
   * Regenerate client secret (confidential clients only)
   */
  regenerateSecret = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: 'invalid_request',
          error_description: 'Client ID is required',
        });
        return;
      }

      const { confirmRegenerate } = req.body as { confirmRegenerate?: boolean };

      if (confirmRegenerate !== true) {
        res.status(400).json({
          success: false,
          error: 'confirmation_required',
          error_description: 'You must confirm secret regeneration',
        });
        return;
      }

      const newSecret = await this.clientService.regenerateClientSecret(id);

      logger.warn({ clientId: id }, 'Client secret regenerated');

      res.json({
        success: true,
        data: {
          clientSecret: newSecret,
        },
        message:
          'Client secret regenerated successfully. Save it now - it will not be shown again! All existing refresh tokens have been revoked.',
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to regenerate client secret');
      const errorMessage =
        error instanceof Error ? error.message : 'Failed to regenerate client secret';
      let statusCode = 500;
      if (errorMessage.includes('not found')) {
        statusCode = 404;
      } else if (errorMessage.includes('confidential')) {
        statusCode = 400;
      }
      res.status(statusCode).json({
        success: false,
        error: 'secret_regeneration_failed',
        error_description: errorMessage,
      });
    }
  };
}
