import { pgTable, uuid, varchar, text, boolean, timestamp, index } from 'drizzle-orm/pg-core';
import { clients } from './clients.schema';
import { users } from './users.schema';

/**
 * Refresh Tokens table - stores OAuth 2.0 refresh tokens
 */
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
