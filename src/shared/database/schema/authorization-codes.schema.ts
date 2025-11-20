import { pgTable, uuid, varchar, text, timestamp, index } from 'drizzle-orm/pg-core';
import { clients } from './clients.schema';
import { users } from './users.schema';

/**
 * Authorization Codes table - stores OAuth 2.0 authorization codes
 */
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
