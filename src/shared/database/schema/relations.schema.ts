import { relations } from 'drizzle-orm';
import { users } from './users.schema';
import { organizations } from './organizations.schema';
import { clients } from './clients.schema';
import { authorizationCodes } from './authorization-codes.schema';
import { refreshTokens } from './refresh-tokens.schema';
import { consents } from './consents.schema';

/**
 * Database relations - defines relationships between tables
 * This file is separate from table definitions to avoid circular dependencies
 */

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
