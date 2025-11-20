import { pgTable, uuid, varchar, text, boolean, timestamp, index } from 'drizzle-orm/pg-core';

/**
 * Signing Keys table - stores cryptographic keys for JWT signing
 */
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
