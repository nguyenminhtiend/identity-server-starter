import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { config } from '../config/index.js';
import * as schema from './schema';

// Get DATABASE_URL from config (will throw error if not set)
const connectionString = config.database.url;

// Create postgres client with configurable pool settings
const client = postgres(connectionString, {
  max: config.database.pool.max,
  idle_timeout: config.database.pool.idleTimeout,
  connect_timeout: config.database.pool.connectTimeout,
});

// Create drizzle instance with schema
export const db = drizzle(client, { schema });

// Export schema for use in other modules
export * from './schema';

// Graceful shutdown
export const closeDatabase = async () => {
  await client.end();
};
