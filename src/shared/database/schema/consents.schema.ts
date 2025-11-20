import { pgTable, uuid, text, timestamp, index, unique } from 'drizzle-orm/pg-core';
import { users } from './users.schema';
import { clients } from './clients.schema';

/**
 * Consents table - stores user consent records for OAuth clients
 */
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
