import { type Request, type Response } from 'express';
import type { IOrganizationService } from '../services';
import { logger } from '../../../shared/utils';

/**
 * Organization Controller
 * Handles admin operations for organization management
 */
export class OrganizationController {
  constructor(private organizationService: IOrganizationService) {}

  /**
   * POST /admin/organizations
   * Create a new organization
   */
  createOrganization = async (req: Request, res: Response): Promise<void> => {
    try {
      const input = req.body as {
        name: string;
        slug: string;
        ownerUserId: string;
      };

      const result = await this.organizationService.createOrganization(input);

      logger.info(
        { organizationId: result.id, slug: result.slug },
        'Organization created successfully'
      );

      res.status(201).json({
        success: true,
        data: result,
        message: 'Organization created successfully',
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to create organization');
      const errorMessage = error instanceof Error ? error.message : 'Failed to create organization';
      const statusCode = errorMessage.includes('already exists') ? 409 : 400;
      res.status(statusCode).json({
        success: false,
        error: 'organization_creation_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * GET /admin/organizations
   * List all organizations with optional filters
   */
  listOrganizations = async (req: Request, res: Response): Promise<void> => {
    try {
      let isActive: boolean | undefined;
      if (req.query.isActive === 'true') {
        isActive = true;
      } else if (req.query.isActive === 'false') {
        isActive = false;
      }

      const filters = {
        isActive,
        limit: req.query.limit !== undefined ? parseInt(req.query.limit as string, 10) : 20,
        offset: req.query.offset !== undefined ? parseInt(req.query.offset as string, 10) : 0,
      };

      const organizations = await this.organizationService.listOrganizations(filters);

      res.json({
        success: true,
        data: organizations,
        pagination: {
          limit: filters.limit,
          offset: filters.offset,
          count: organizations.length,
        },
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to list organizations');
      const errorMessage = error instanceof Error ? error.message : 'Failed to list organizations';
      res.status(500).json({
        success: false,
        error: 'organization_list_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * GET /admin/organizations/:id
   * Get organization details by ID
   */
  getOrganization = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: 'invalid_request',
          error_description: 'Organization ID is required',
        });
        return;
      }

      const organization = await this.organizationService.getOrganizationById(id);

      if (!organization) {
        res.status(404).json({
          success: false,
          error: 'organization_not_found',
          error_description: 'Organization not found',
        });
        return;
      }

      res.json({
        success: true,
        data: organization,
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to get organization');
      const errorMessage = error instanceof Error ? error.message : 'Failed to get organization';
      res.status(500).json({
        success: false,
        error: 'organization_fetch_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * PUT /admin/organizations/:id
   * Update organization
   */
  updateOrganization = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: 'invalid_request',
          error_description: 'Organization ID is required',
        });
        return;
      }

      const input = req.body as {
        name?: string;
        slug?: string;
        isActive?: boolean;
      };

      await this.organizationService.updateOrganization(id, input);

      logger.info({ organizationId: id }, 'Organization updated successfully');

      res.json({
        success: true,
        message: 'Organization updated successfully',
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to update organization');
      const errorMessage = error instanceof Error ? error.message : 'Failed to update organization';
      let statusCode = 400;
      if (errorMessage.includes('not found')) {
        statusCode = 404;
      } else if (errorMessage.includes('already exists')) {
        statusCode = 409;
      }
      res.status(statusCode).json({
        success: false,
        error: 'organization_update_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * DELETE /admin/organizations/:id
   * Delete or deactivate organization
   */
  deleteOrganization = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: 'invalid_request',
          error_description: 'Organization ID is required',
        });
        return;
      }

      const hard = req.query.hard === 'true';

      await this.organizationService.deleteOrganization(id, hard);

      logger.info({ organizationId: id, hard }, 'Organization deleted successfully');

      res.json({
        success: true,
        message: hard ? 'Organization permanently deleted' : 'Organization deactivated',
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to delete organization');
      const errorMessage = error instanceof Error ? error.message : 'Failed to delete organization';
      const statusCode = errorMessage.includes('not found') ? 404 : 400;
      res.status(statusCode).json({
        success: false,
        error: 'organization_deletion_failed',
        error_description: errorMessage,
      });
    }
  };

  /**
   * GET /admin/organizations/:id/clients
   * Get all clients belonging to an organization
   */
  getOrganizationClients = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({
          success: false,
          error: 'invalid_request',
          error_description: 'Organization ID is required',
        });
        return;
      }

      // First check if organization exists
      const organization = await this.organizationService.getOrganizationById(id);

      if (!organization) {
        res.status(404).json({
          success: false,
          error: 'organization_not_found',
          error_description: 'Organization not found',
        });
        return;
      }

      const clientIds = await this.organizationService.getOrganizationClients(id);

      res.json({
        success: true,
        data: {
          organizationId: id,
          clientIds,
          count: clientIds.length,
        },
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to get organization clients');
      const errorMessage =
        error instanceof Error ? error.message : 'Failed to get organization clients';
      res.status(500).json({
        success: false,
        error: 'organization_clients_fetch_failed',
        error_description: errorMessage,
      });
    }
  };
}
