/**
 * Client Service Interface
 * Defines contract for OAuth client management operations
 */

export interface CreateClientInput {
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
}

export interface UpdateClientInput {
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
}

export interface ClientResponse {
  id: string;
  clientId: string;
  clientSecretPreview?: string; // Only last 4 chars for confidential clients
  name: string;
  clientType: 'confidential' | 'public';
  organizationId: string | null;
  redirectUris: string[];
  grantTypes: string[];
  allowedScopes: string;
  logoUrl: string | null;
  allowedCorsOrigins: string[] | null;
  termsUrl: string | null;
  privacyUrl: string | null;
  homepageUrl: string | null;
  contacts: string[] | null;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateClientResult {
  id: string;
  clientId: string;
  clientSecret?: string; // Only returned once during creation for confidential clients
  name: string;
  clientType: 'confidential' | 'public';
}

export interface ClientListFilters {
  organizationId?: string;
  clientType?: 'confidential' | 'public';
  isActive?: boolean;
  limit?: number;
  offset?: number;
}

export interface IClientService {
  /**
   * Create a new OAuth client
   * @param input - Client creation data
   * @returns Client ID and secret (for confidential clients)
   */
  createClient(input: CreateClientInput): Promise<CreateClientResult>;

  /**
   * Get client by ID
   * @param clientId - Client database ID (UUID)
   * @returns Client details (without secret)
   */
  getClientById(clientId: string): Promise<ClientResponse | null>;

  /**
   * Get client by client_id
   * @param clientId - OAuth client_id
   * @returns Client details (without secret)
   */
  getClientByClientId(clientId: string): Promise<ClientResponse | null>;

  /**
   * List all clients with optional filters
   * @param filters - Optional filters for listing
   * @returns Array of clients
   */
  listClients(filters?: ClientListFilters): Promise<ClientResponse[]>;

  /**
   * Update client metadata
   * @param clientId - Client database ID (UUID)
   * @param input - Fields to update
   */
  updateClient(clientId: string, input: UpdateClientInput): Promise<void>;

  /**
   * Delete/deactivate client
   * @param clientId - Client database ID (UUID)
   * @param hard - If true, permanently delete; if false, soft delete (set isActive=false)
   */
  deleteClient(clientId: string, hard?: boolean): Promise<void>;

  /**
   * Regenerate client secret (confidential clients only)
   * @param clientId - Client database ID (UUID)
   * @returns New client secret (only returned once)
   */
  regenerateClientSecret(clientId: string): Promise<string>;

  /**
   * Check if client exists by client_id
   * @param clientId - OAuth client_id
   * @returns True if exists, false otherwise
   */
  clientExists(clientId: string): Promise<boolean>;
}
