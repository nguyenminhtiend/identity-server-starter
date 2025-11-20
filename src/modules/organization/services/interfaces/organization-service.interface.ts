/**
 * Organization Service Interface
 * Defines contract for multi-tenant organization management
 */

export interface CreateOrganizationInput {
  name: string;
  slug: string;
  ownerUserId: string;
}

export interface UpdateOrganizationInput {
  name?: string;
  slug?: string;
  isActive?: boolean;
}

export interface OrganizationResponse {
  id: string;
  name: string;
  slug: string;
  ownerUserId: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface OrganizationListFilters {
  isActive?: boolean;
  limit?: number;
  offset?: number;
}

export interface IOrganizationService {
  /**
   * Create a new organization
   * @param input - Organization creation data
   * @returns Created organization
   */
  createOrganization(input: CreateOrganizationInput): Promise<OrganizationResponse>;

  /**
   * Get organization by ID
   * @param id - Organization ID (UUID)
   * @returns Organization details or null
   */
  getOrganizationById(id: string): Promise<OrganizationResponse | null>;

  /**
   * Get organization by slug
   * @param slug - Organization slug (unique identifier)
   * @returns Organization details or null
   */
  getOrganizationBySlug(slug: string): Promise<OrganizationResponse | null>;

  /**
   * List all organizations with optional filters
   * @param filters - Optional filters
   * @returns Array of organizations
   */
  listOrganizations(filters?: OrganizationListFilters): Promise<OrganizationResponse[]>;

  /**
   * Update organization
   * @param id - Organization ID (UUID)
   * @param input - Fields to update
   */
  updateOrganization(id: string, input: UpdateOrganizationInput): Promise<void>;

  /**
   * Delete/deactivate organization
   * @param id - Organization ID (UUID)
   * @param hard - If true, permanently delete; if false, soft delete
   */
  deleteOrganization(id: string, hard?: boolean): Promise<void>;

  /**
   * Check if slug is available
   * @param slug - Organization slug
   * @returns True if available, false if taken
   */
  isSlugAvailable(slug: string): Promise<boolean>;

  /**
   * Get clients belonging to an organization
   * @param organizationId - Organization ID
   * @returns Array of client IDs
   */
  getOrganizationClients(organizationId: string): Promise<string[]>;
}
