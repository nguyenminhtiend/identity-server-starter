import { Router, type Router as RouterType } from 'express';
import { AdminController } from '../controllers';
import { OrganizationController } from '../../organization/controllers';
import { KeyManagementController } from '../../key-management/controllers';
import { validateBody, validateParams, validateQuery } from '../../../shared/middleware';
import { requireAdmin } from '../../../shared/middleware/authenticate.middleware';
import {
  createClientRequestSchema,
  updateClientRequestSchema,
  clientIdParamSchema,
  clientListQuerySchema,
  regenerateSecretRequestSchema,
} from '../../client/validators';
import {
  createOrganizationSchema,
  updateOrganizationSchema,
  organizationIdParamSchema,
  listOrganizationsQuerySchema,
} from '../../organization/validators';
import { rotateKeysSchema } from '../../key-management/validators';
import type { Services } from '../../../shared/services';

/**
 * Create Admin router with injected services
 * @param services - Application services
 * @returns Configured Admin router
 */
export function createAdminRouter(services: Services): RouterType {
  const { clientService, organizationService, keyManagementService } = services;

  // Initialize controllers with injected dependencies
  const adminController = new AdminController(clientService);
  const organizationController = new OrganizationController(organizationService);
  const keyManagementController = new KeyManagementController(keyManagementService);

  const router: RouterType = Router();

  // All admin routes require admin authentication
  router.use(requireAdmin);

  /**
   * Client Management Endpoints
   */

  /**
   * POST /admin/clients
   * Create a new OAuth client
   */
  router.post('/clients', validateBody(createClientRequestSchema), adminController.createClient);

  /**
   * GET /admin/clients
   * List all clients with optional filters
   */
  router.get('/clients', validateQuery(clientListQuerySchema), adminController.listClients);

  /**
   * GET /admin/clients/:id
   * Get client details by ID
   */
  router.get('/clients/:id', validateParams(clientIdParamSchema), adminController.getClient);

  /**
   * PUT /admin/clients/:id
   * Update client metadata
   */
  router.put(
    '/clients/:id',
    validateParams(clientIdParamSchema),
    validateBody(updateClientRequestSchema),
    adminController.updateClient
  );

  /**
   * DELETE /admin/clients/:id
   * Delete or deactivate client
   * Query param: hard=true for permanent deletion
   */
  router.delete('/clients/:id', validateParams(clientIdParamSchema), adminController.deleteClient);

  /**
   * POST /admin/clients/:id/secret
   * Regenerate client secret (confidential clients only)
   */
  router.post(
    '/clients/:id/secret',
    validateParams(clientIdParamSchema),
    validateBody(regenerateSecretRequestSchema),
    adminController.regenerateSecret
  );

  /**
   * Organization Management Endpoints
   */

  /**
   * POST /admin/organizations
   * Create a new organization
   */
  router.post(
    '/organizations',
    validateBody(createOrganizationSchema),
    organizationController.createOrganization
  );

  /**
   * GET /admin/organizations
   * List all organizations with optional filters
   */
  router.get(
    '/organizations',
    validateQuery(listOrganizationsQuerySchema),
    organizationController.listOrganizations
  );

  /**
   * GET /admin/organizations/:id
   * Get organization details by ID
   */
  router.get(
    '/organizations/:id',
    validateParams(organizationIdParamSchema),
    organizationController.getOrganization
  );

  /**
   * PUT /admin/organizations/:id
   * Update organization
   */
  router.put(
    '/organizations/:id',
    validateParams(organizationIdParamSchema),
    validateBody(updateOrganizationSchema),
    organizationController.updateOrganization
  );

  /**
   * DELETE /admin/organizations/:id
   * Delete or deactivate organization
   * Query param: hard=true for permanent deletion
   */
  router.delete(
    '/organizations/:id',
    validateParams(organizationIdParamSchema),
    organizationController.deleteOrganization
  );

  /**
   * GET /admin/organizations/:id/clients
   * Get all clients belonging to an organization
   */
  router.get(
    '/organizations/:id/clients',
    validateParams(organizationIdParamSchema),
    organizationController.getOrganizationClients
  );

  /**
   * Key Management Endpoints
   */

  /**
   * GET /admin/keys
   * List all signing keys (active and inactive)
   */
  router.get('/keys', keyManagementController.listKeys);

  /**
   * GET /admin/keys/primary
   * Get current primary signing key metadata
   */
  router.get('/keys/primary', keyManagementController.getPrimaryKey);

  /**
   * GET /admin/keys/rotation-status
   * Check next scheduled rotation
   */
  router.get('/keys/rotation-status', keyManagementController.getRotationStatus);

  /**
   * POST /admin/keys/rotate
   * Manually trigger key rotation
   */
  router.post('/keys/rotate', validateBody(rotateKeysSchema), keyManagementController.rotateKeys);

  return router;
}
