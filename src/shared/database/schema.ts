import {
  pgTable,
  uuid,
  varchar,
  text,
  boolean,
  timestamp,
  jsonb,
  index,
  unique,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// Users table
export const users = pgTable(
  'users',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    email: varchar('email', { length: 255 }).notNull().unique(),
    passwordHash: varchar('password_hash', { length: 255 }).notNull(),
    emailVerified: boolean('email_verified').default(false).notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    emailIdx: index('users_email_idx').on(table.email),
  })
);

// Organizations table (for multi-tenant support)
export const organizations = pgTable(
  'organizations',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    name: varchar('name', { length: 255 }).notNull(),
    slug: varchar('slug', { length: 100 }).notNull().unique(),
    ownerUserId: uuid('owner_user_id')
      .references(() => users.id)
      .notNull(),
    isActive: boolean('is_active').default(true).notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  (table) => ({
    slugIdx: index('organizations_slug_idx').on(table.slug),
  })
);

// OAuth Clients table
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

// Authorization Codes table
export const authorizationCodes = pgTable(
  'authorization_codes',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    code: varchar('code', { length: 255 }).notNull().unique(),
    clientId: uuid('client_id')
      .references(() => clients.id)
      .notNull(),
    userId: uuid('user_id')
      .references(() => users.id)
      .notNull(),
    redirectUri: text('redirect_uri').notNull(),
    scope: text('scope').notNull(),
    codeChallenge: varchar('code_challenge', { length: 255 }).notNull(),
    codeChallengeMethod: varchar('code_challenge_method', { length: 10 }).notNull(),
    expiresAt: timestamp('expires_at').notNull(),
    usedAt: timestamp('used_at'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (table) => ({
    codeIdx: index('authorization_codes_code_idx').on(table.code),
    clientIdIdx: index('authorization_codes_client_id_idx').on(table.clientId),
    expiresAtIdx: index('authorization_codes_expires_at_idx').on(table.expiresAt),
  })
);

// Refresh Tokens table
export const refreshTokens = pgTable(
  'refresh_tokens',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    tokenHash: varchar('token_hash', { length: 255 }).notNull().unique(),
    clientId: uuid('client_id')
      .references(() => clients.id)
      .notNull(),
    userId: uuid('user_id')
      .references(() => users.id)
      .notNull(),
    scope: text('scope').notNull(),
    expiresAt: timestamp('expires_at').notNull(),
    revoked: boolean('revoked').default(false).notNull(),
    previousTokenHash: varchar('previous_token_hash', { length: 255 }),
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (table) => ({
    tokenHashIdx: index('refresh_tokens_token_hash_idx').on(table.tokenHash),
    clientIdIdx: index('refresh_tokens_client_id_idx').on(table.clientId),
    userIdIdx: index('refresh_tokens_user_id_idx').on(table.userId),
    expiresAtIdx: index('refresh_tokens_expires_at_idx').on(table.expiresAt),
  })
);

// Consents table
export const consents = pgTable(
  'consents',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: uuid('user_id')
      .references(() => users.id)
      .notNull(),
    clientId: uuid('client_id')
      .references(() => clients.id)
      .notNull(),
    scope: text('scope').notNull(),
    grantedAt: timestamp('granted_at').defaultNow().notNull(),
  },
  (table) => ({
    userClientUnique: unique('consents_user_client_unique').on(table.userId, table.clientId),
    userIdIdx: index('consents_user_id_idx').on(table.userId),
    clientIdIdx: index('consents_client_id_idx').on(table.clientId),
  })
);

// Signing Keys table (for cryptographic key management)
export const signingKeys = pgTable(
  'signing_keys',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    keyId: varchar('key_id', { length: 255 }).notNull().unique(),
    algorithm: varchar('algorithm', { length: 20 }).notNull().default('RS256'),
    publicKeyPem: text('public_key_pem').notNull(),
    privateKeyEncrypted: text('private_key_encrypted').notNull(),
    isActive: boolean('is_active').default(true).notNull(),
    isPrimary: boolean('is_primary').default(false).notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    expiresAt: timestamp('expires_at'),
    rotatedAt: timestamp('rotated_at'),
    nextRotationAt: timestamp('next_rotation_at'),
  },
  (table) => ({
    keyIdIdx: index('signing_keys_key_id_idx').on(table.keyId),
    isPrimaryIdx: index('signing_keys_is_primary_idx').on(table.isPrimary),
    isActiveIdx: index('signing_keys_is_active_idx').on(table.isActive),
  })
);

// Relations
export const usersRelations = relations(users, ({ many }) => ({
  organizations: many(organizations),
  authorizationCodes: many(authorizationCodes),
  refreshTokens: many(refreshTokens),
  consents: many(consents),
}));

export const organizationsRelations = relations(organizations, ({ one, many }) => ({
  owner: one(users, {
    fields: [organizations.ownerUserId],
    references: [users.id],
  }),
  clients: many(clients),
}));

export const clientsRelations = relations(clients, ({ one, many }) => ({
  organization: one(organizations, {
    fields: [clients.organizationId],
    references: [organizations.id],
  }),
  authorizationCodes: many(authorizationCodes),
  refreshTokens: many(refreshTokens),
  consents: many(consents),
}));

export const authorizationCodesRelations = relations(authorizationCodes, ({ one }) => ({
  client: one(clients, {
    fields: [authorizationCodes.clientId],
    references: [clients.id],
  }),
  user: one(users, {
    fields: [authorizationCodes.userId],
    references: [users.id],
  }),
}));

export const refreshTokensRelations = relations(refreshTokens, ({ one }) => ({
  client: one(clients, {
    fields: [refreshTokens.clientId],
    references: [clients.id],
  }),
  user: one(users, {
    fields: [refreshTokens.userId],
    references: [users.id],
  }),
}));

export const consentsRelations = relations(consents, ({ one }) => ({
  user: one(users, {
    fields: [consents.userId],
    references: [users.id],
  }),
  client: one(clients, {
    fields: [consents.clientId],
    references: [clients.id],
  }),
}));
