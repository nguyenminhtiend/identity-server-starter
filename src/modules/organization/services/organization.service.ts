import { eq, and } from 'drizzle-orm';
import { db } from '../../../shared/database';
import { organizations, clients } from '../../../shared/database/schema';
import type {
  IOrganizationService,
  CreateOrganizationInput,
  UpdateOrganizationInput,
  OrganizationResponse,
  OrganizationListFilters,
} from './interfaces/organization-service.interface';

/**
 * Organization Service
 * Handles multi-tenant organization management
 */
export class OrganizationService implements IOrganizationService {
  /**
   * Create a new organization
   */
  async createOrganization(input: CreateOrganizationInput): Promise<OrganizationResponse> {
    // Check if slug is already taken
    const existingOrg = await db.query.organizations.findFirst({
      where: eq(organizations.slug, input.slug),
    });

    if (existingOrg) {
      throw new Error('Organization slug already exists');
    }

    // Create organization
    const [newOrg] = await db
      .insert(organizations)
      .values({
        name: input.name,
        slug: input.slug,
        ownerUserId: input.ownerUserId,
        isActive: true,
      })
      .returning();

    if (!newOrg) {
      throw new Error('Failed to create organization');
    }

    return this.mapToOrganizationResponse(newOrg);
  }

  /**
   * Get organization by ID
   */
  async getOrganizationById(id: string): Promise<OrganizationResponse | null> {
    const org = await db.query.organizations.findFirst({
      where: eq(organizations.id, id),
    });

    if (!org) {
      return null;
    }

    return this.mapToOrganizationResponse(org);
  }

  /**
   * Get organization by slug
   */
  async getOrganizationBySlug(slug: string): Promise<OrganizationResponse | null> {
    const org = await db.query.organizations.findFirst({
      where: eq(organizations.slug, slug),
    });

    if (!org) {
      return null;
    }

    return this.mapToOrganizationResponse(org);
  }

  /**
   * List all organizations with optional filters
   */
  async listOrganizations(filters?: OrganizationListFilters): Promise<OrganizationResponse[]> {
    const conditions = [];

    if (filters?.isActive !== undefined) {
      conditions.push(eq(organizations.isActive, filters.isActive));
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

    const orgList = await db.query.organizations.findMany({
      where: whereClause,
      limit: filters?.limit ?? 20,
      offset: filters?.offset ?? 0,
      orderBy: (organizations, { desc }) => [desc(organizations.createdAt)],
    });

    return orgList.map((org) => this.mapToOrganizationResponse(org));
  }

  /**
   * Update organization
   */
  async updateOrganization(id: string, input: UpdateOrganizationInput): Promise<void> {
    // Check if organization exists
    const existingOrg = await db.query.organizations.findFirst({
      where: eq(organizations.id, id),
    });

    if (!existingOrg) {
      throw new Error('Organization not found');
    }

    // If updating slug, check if new slug is available
    if (input.slug && input.slug !== existingOrg.slug) {
      const slugTaken = await db.query.organizations.findFirst({
        where: eq(organizations.slug, input.slug),
      });

      if (slugTaken) {
        throw new Error('Organization slug already exists');
      }
    }

    // Update organization
    await db
      .update(organizations)
      .set({
        ...input,
        updatedAt: new Date(),
      })
      .where(eq(organizations.id, id));
  }

  /**
   * Delete/deactivate organization
   */
  async deleteOrganization(id: string, hard = false): Promise<void> {
    // Check if organization exists
    const existingOrg = await db.query.organizations.findFirst({
      where: eq(organizations.id, id),
    });

    if (!existingOrg) {
      throw new Error('Organization not found');
    }

    if (hard) {
      // Hard delete: Check if organization has clients
      const orgClients = await db.query.clients.findMany({
        where: eq(clients.organizationId, id),
        columns: {
          id: true,
        },
      });

      if (orgClients.length > 0) {
        throw new Error(
          'Cannot delete organization with existing clients. Delete clients first or use soft delete.'
        );
      }

      // Delete organization
      await db.delete(organizations).where(eq(organizations.id, id));
    } else {
      // Soft delete: Set isActive to false
      await db
        .update(organizations)
        .set({
          isActive: false,
          updatedAt: new Date(),
        })
        .where(eq(organizations.id, id));

      // Also deactivate all clients in this organization
      await db
        .update(clients)
        .set({
          isActive: false,
          updatedAt: new Date(),
        })
        .where(eq(clients.organizationId, id));
    }
  }

  /**
   * Check if slug is available
   */
  async isSlugAvailable(slug: string): Promise<boolean> {
    const org = await db.query.organizations.findFirst({
      where: eq(organizations.slug, slug),
      columns: {
        id: true,
      },
    });

    return !org;
  }

  /**
   * Get clients belonging to an organization
   */
  async getOrganizationClients(organizationId: string): Promise<string[]> {
    const orgClients = await db.query.clients.findMany({
      where: eq(clients.organizationId, organizationId),
      columns: {
        id: true,
      },
    });

    return orgClients.map((client) => client.id);
  }

  /**
   * Map database organization to response object
   */
  private mapToOrganizationResponse(org: typeof organizations.$inferSelect): OrganizationResponse {
    return {
      id: org.id,
      name: org.name,
      slug: org.slug,
      ownerUserId: org.ownerUserId,
      isActive: org.isActive,
      createdAt: org.createdAt,
      updatedAt: org.updatedAt,
    };
  }
}
