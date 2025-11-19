import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema.js';

// Get DATABASE_URL from environment
const connectionString =
  process.env.DATABASE_URL ?? 'postgresql://admin:123456@127.0.0.1:5432/identity_db';

// Create postgres client
const client = postgres(connectionString, {
  max: 10,
  idle_timeout: 20,
  connect_timeout: 10,
});

// Create drizzle instance with schema
export const db = drizzle(client, { schema });

// Export schema for use in other modules
export * from './schema.js';

// Graceful shutdown
export const closeDatabase = async () => {
  await client.end();
};
