import { eq, and } from 'drizzle-orm';
import { db } from '../../../shared/database';
import { clients, refreshTokens, authorizationCodes } from '../../../shared/database/schema';
import { generateRandomToken, hashPassword } from '../../../shared/utils/crypto.util';
import type {
  IClientService,
  CreateClientInput,
  UpdateClientInput,
  ClientResponse,
  CreateClientResult,
  ClientListFilters,
} from './interfaces/client-service.interface';

/**
 * Client Service
 * Handles OAuth client management operations
 */
export class ClientService implements IClientService {
  /**
   * Generate a unique client_id
   */
  private generateClientId(): string {
    // Format: client_<timestamp>_<random>
    const timestamp = Date.now().toString(36);
    const random = generateRandomToken(8);
    return `client_${timestamp}_${random}`;
  }

  /**
   * Generate a secure client secret (for confidential clients)
   */
  private generateClientSecret(): string {
    // Generate 48-character random string
    return generateRandomToken(48);
  }

  /**
   * Get last 4 characters of client secret for preview
   */
  private getSecretPreview(_secretHash: string): string {
    // We can't reverse the hash, so we store this during creation
    // For existing clients, we'll show placeholder
    return '****';
  }

  /**
   * Create a new OAuth client
   */
  async createClient(input: CreateClientInput): Promise<CreateClientResult> {
    // Validate client type and grant types compatibility
    if (input.clientType === 'public' && input.grantTypes.includes('client_credentials')) {
      throw new Error('Public clients cannot use client_credentials grant type');
    }

    // Generate client_id
    const clientId = this.generateClientId();

    // Generate and hash client_secret for confidential clients
    let clientSecret: string | undefined;
    let clientSecretHash: string | undefined;

    if (input.clientType === 'confidential') {
      clientSecret = this.generateClientSecret();
      clientSecretHash = await hashPassword(clientSecret);
    }

    // Create client record
    const [newClient] = await db
      .insert(clients)
      .values({
        clientId,
        clientSecretHash,
        name: input.name,
        clientType: input.clientType,
        organizationId: input.organizationId,
        redirectUris: input.redirectUris,
        grantTypes: input.grantTypes,
        allowedScopes: input.allowedScopes,
        logoUrl: input.logoUrl,
        allowedCorsOrigins: input.allowedCorsOrigins,
        termsUrl: input.termsUrl,
        privacyUrl: input.privacyUrl,
        homepageUrl: input.homepageUrl,
        contacts: input.contacts,
        isActive: true,
      })
      .returning({
        id: clients.id,
        clientId: clients.clientId,
        name: clients.name,
        clientType: clients.clientType,
      });

    if (!newClient) {
      throw new Error('Failed to create client');
    }

    return {
      id: newClient.id,
      clientId: newClient.clientId,
      clientSecret, // Only returned once, undefined for public clients
      name: newClient.name,
      clientType: newClient.clientType as 'confidential' | 'public',
    };
  }

  /**
   * Get client by ID (UUID)
   */
  async getClientById(id: string): Promise<ClientResponse | null> {
    const client = await db.query.clients.findFirst({
      where: eq(clients.id, id),
    });

    if (!client) {
      return null;
    }

    return this.mapToClientResponse(client);
  }

  /**
   * Get client by client_id
   */
  async getClientByClientId(clientId: string): Promise<ClientResponse | null> {
    const client = await db.query.clients.findFirst({
      where: eq(clients.clientId, clientId),
    });

    if (!client) {
      return null;
    }

    return this.mapToClientResponse(client);
  }

  /**
   * List all clients with optional filters
   */
  async listClients(filters?: ClientListFilters): Promise<ClientResponse[]> {
    const conditions = [];

    if (filters?.organizationId) {
      conditions.push(eq(clients.organizationId, filters.organizationId));
    }

    if (filters?.clientType) {
      conditions.push(eq(clients.clientType, filters.clientType));
    }

    if (filters?.isActive !== undefined) {
      conditions.push(eq(clients.isActive, filters.isActive));
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

    const clientList = await db.query.clients.findMany({
      where: whereClause,
      limit: filters?.limit ?? 20,
      offset: filters?.offset ?? 0,
      orderBy: (clients, { desc }) => [desc(clients.createdAt)],
    });

    return clientList.map((client) => this.mapToClientResponse(client));
  }

  /**
   * Update client metadata
   */
  async updateClient(id: string, input: UpdateClientInput): Promise<void> {
    // Check if client exists
    const existingClient = await db.query.clients.findFirst({
      where: eq(clients.id, id),
    });

    if (!existingClient) {
      throw new Error('Client not found');
    }

    // Update client
    await db
      .update(clients)
      .set({
        ...input,
        updatedAt: new Date(),
      })
      .where(eq(clients.id, id));
  }

  /**
   * Delete/deactivate client
   */
  async deleteClient(id: string, hard = false): Promise<void> {
    // Check if client exists
    const existingClient = await db.query.clients.findFirst({
      where: eq(clients.id, id),
      columns: {
        id: true,
        clientId: true,
      },
    });

    if (!existingClient) {
      throw new Error('Client not found');
    }

    if (hard) {
      // Hard delete: Remove client and all related data
      // First, delete related tokens and codes
      await db.delete(refreshTokens).where(eq(refreshTokens.clientId, existingClient.id));
      await db.delete(authorizationCodes).where(eq(authorizationCodes.clientId, existingClient.id));

      // Then delete the client
      await db.delete(clients).where(eq(clients.id, id));
    } else {
      // Soft delete: Set isActive to false
      await db
        .update(clients)
        .set({
          isActive: false,
          updatedAt: new Date(),
        })
        .where(eq(clients.id, id));

      // Optionally revoke all active tokens for this client
      await db
        .update(refreshTokens)
        .set({ revoked: true })
        .where(eq(refreshTokens.clientId, existingClient.id));
    }
  }

  /**
   * Regenerate client secret (confidential clients only)
   */
  async regenerateClientSecret(id: string): Promise<string> {
    // Get client
    const client = await db.query.clients.findFirst({
      where: eq(clients.id, id),
      columns: {
        id: true,
        clientType: true,
        clientId: true,
      },
    });

    if (!client) {
      throw new Error('Client not found');
    }

    if (client.clientType !== 'confidential') {
      throw new Error('Only confidential clients have secrets');
    }

    // Generate new secret
    const newSecret = this.generateClientSecret();
    const newSecretHash = await hashPassword(newSecret);

    // Update client
    await db
      .update(clients)
      .set({
        clientSecretHash: newSecretHash,
        updatedAt: new Date(),
      })
      .where(eq(clients.id, id));

    // Revoke all existing refresh tokens for security
    await db
      .update(refreshTokens)
      .set({ revoked: true })
      .where(eq(refreshTokens.clientId, client.id));

    return newSecret;
  }

  /**
   * Check if client exists by client_id
   */
  async clientExists(clientId: string): Promise<boolean> {
    const client = await db.query.clients.findFirst({
      where: eq(clients.clientId, clientId),
      columns: {
        id: true,
      },
    });

    return !!client;
  }

  /**
   * Map database client to response object
   */
  private mapToClientResponse(client: typeof clients.$inferSelect): ClientResponse {
    return {
      id: client.id,
      clientId: client.clientId,
      clientSecretPreview:
        client.clientType === 'confidential' && client.clientSecretHash
          ? this.getSecretPreview(client.clientSecretHash)
          : undefined,
      name: client.name,
      clientType: client.clientType as 'confidential' | 'public',
      organizationId: client.organizationId,
      redirectUris: client.redirectUris,
      grantTypes: client.grantTypes,
      allowedScopes: client.allowedScopes,
      logoUrl: client.logoUrl,
      allowedCorsOrigins: client.allowedCorsOrigins,
      termsUrl: client.termsUrl,
      privacyUrl: client.privacyUrl,
      homepageUrl: client.homepageUrl,
      contacts: client.contacts,
      isActive: client.isActive,
      createdAt: client.createdAt,
      updatedAt: client.updatedAt,
    };
  }
}
