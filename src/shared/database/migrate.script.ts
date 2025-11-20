import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import { logger } from '../utils';
import * as dotenv from 'dotenv';

dotenv.config();

/**
 * Run database migrations programmatically
 * This script should be used in production environments
 */
async function runMigrations() {
  logger.info('🔄 Starting database migrations...\n');

  const connectionString = process.env.DATABASE_URL;

  if (!connectionString) {
    logger.error('❌ DATABASE_URL environment variable is not set');
    process.exit(1);
  }

  // Create a postgres client specifically for migrations
  // Note: max: 1 is recommended for migration scripts
  const migrationClient = postgres(connectionString, {
    max: 1,
  });

  const db = drizzle(migrationClient);

  try {
    logger.info('📂 Reading migrations from ./migrations directory...');

    await migrate(db, {
      migrationsFolder: './src/shared/database/migrations',
    });

    logger.info('✅ Migrations completed successfully!\n');
  } catch (error) {
    logger.error({ err: error }, '❌ Migration failed');
    throw error;
  } finally {
    await migrationClient.end();
    logger.info('🔌 Database connection closed\n');
  }
}

// Run migrations
runMigrations()
  .then(() => {
    logger.info('✨ Migration script finished');
    process.exit(0);
  })
  .catch((error) => {
    logger.error({ err: error }, 'Fatal error during migration');
    process.exit(1);
  });
