import {
  pgTable,
  uuid,
  varchar,
  text,
  boolean,
  timestamp,
  jsonb,
  index,
} from 'drizzle-orm/pg-core';
import { organizations } from './organizations.schema';

/**
 * OAuth Clients table - stores OAuth 2.0 client applications
 */
export const clients = pgTable(
  'clients',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    clientId: varchar('client_id', { length: 255 }).notNull().unique(),
    clientSecretHash: varchar('client_secret_hash', { length: 255 }), // Nullable for public clients
    name: varchar('name', { length: 255 }).notNull(),
    clientType: varchar('client_type', { length: 20 }).notNull(), // 'confidential' | 'public'
    organizationId: uuid('organization_id').references(() => organizations.id), // Nullable for system-level clients
    redirectUris: jsonb('redirect_uris').notNull().$type<string[]>(),
    grantTypes: jsonb('grant_types').notNull().$type<string[]>(),
    allowedScopes: text('allowed_scopes').notNull(),
    logoUrl: text('logo_url'),
    allowedCorsOrigins: jsonb('allowed_cors_origins').$type<string[]>(),
    termsUrl: text('terms_url'),
    privacyUrl: text('privacy_url'),
    homepageUrl: text('homepage_url'),
    contacts: jsonb('contacts').$type<string[]>(),
    isActive: boolean('is_active').default(true).notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    clientIdIdx: index('clients_client_id_idx').on(table.clientId),
    organizationIdIdx: index('clients_organization_id_idx').on(table.organizationId),
  })
);
