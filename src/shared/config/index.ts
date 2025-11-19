import { z } from 'zod';
import * as dotenv from 'dotenv';

dotenv.config();

const configSchema = z.object({
  // Application
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z
    .string()
    .transform(Number)
    .pipe(z.number().min(1).max(65535))
    .default(() => 3000),

  // Database
  DATABASE_URL: z.string().url(),

  // Redis
  REDIS_URL: z.string().url(),

  // Session & Security
  SESSION_SECRET: z.string().min(32, 'Session secret must be at least 32 characters'),
  KEY_ENCRYPTION_SECRET: z.string().min(32, 'Key encryption secret must be at least 32 characters'),

  // Token Configuration
  ISSUER_URL: z.string().url(),
  ACCESS_TOKEN_TTL: z
    .string()
    .transform(Number)
    .pipe(z.number().positive())
    .default(() => 900),
  REFRESH_TOKEN_TTL: z
    .string()
    .transform(Number)
    .pipe(z.number().positive())
    .default(() => 2592000),

  // Key Management
  KEY_ROTATION_DAYS: z
    .string()
    .transform(Number)
    .pipe(z.number().positive())
    .default(() => 90),
  KMS_PROVIDER: z.enum(['local', 'aws', 'azure', 'gcp']).default('local'),
  AWS_KMS_KEY_ID: z.optional(z.string()),
  AZURE_KEY_VAULT_URL: z.union([z.optional(z.string().url()), z.literal('')]),
  GCP_KMS_KEY_NAME: z.optional(z.string()),

  // Multi-tenant
  ENABLE_MULTI_TENANT: z
    .string()
    .transform((val) => val.toLowerCase() === 'true')
    .pipe(z.boolean())
    .default(() => false),

  // CORS
  ALLOWED_ORIGINS: z
    .string()
    .transform((val) => val.split(',').map((origin) => origin.trim()))
    .default(() => ['http://localhost:3000']),

  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: z
    .string()
    .transform(Number)
    .pipe(z.number().positive())
    .default(() => 60000),
  RATE_LIMIT_MAX_REQUESTS: z
    .string()
    .transform(Number)
    .pipe(z.number().positive())
    .default(() => 100),
});

export type Config = z.infer<typeof configSchema>;

function validateConfig(): Config {
  try {
    return configSchema.parse(process.env);
  } catch (error) {
    if (error instanceof z.ZodError) {
      console.error('Configuration validation failed:');
      error.issues.forEach((err) => {
        console.error(`  - ${err.path.join('.')}: ${err.message}`);
      });
      process.exit(1);
    }
    throw error;
  }
}

const rawConfig = validateConfig();

// Export structured config
export const config = {
  env: rawConfig.NODE_ENV,
  port: rawConfig.PORT,
  issuer: rawConfig.ISSUER_URL,

  database: {
    url: rawConfig.DATABASE_URL,
  },

  redis: {
    url: rawConfig.REDIS_URL,
  },

  session: {
    secret: rawConfig.SESSION_SECRET,
  },

  keys: {
    encryptionSecret: rawConfig.KEY_ENCRYPTION_SECRET,
    rotationDays: rawConfig.KEY_ROTATION_DAYS,
  },

  tokens: {
    accessTokenTTL: rawConfig.ACCESS_TOKEN_TTL,
    refreshTokenTTL: rawConfig.REFRESH_TOKEN_TTL,
  },

  kms: {
    provider: rawConfig.KMS_PROVIDER,
    awsKeyId: rawConfig.AWS_KMS_KEY_ID,
    azureVaultUrl: rawConfig.AZURE_KEY_VAULT_URL,
    gcpKeyName: rawConfig.GCP_KMS_KEY_NAME,
  },

  multiTenant: rawConfig.ENABLE_MULTI_TENANT,

  cors: {
    allowedOrigins: rawConfig.ALLOWED_ORIGINS,
  },

  rateLimit: {
    windowMs: rawConfig.RATE_LIMIT_WINDOW_MS,
    maxRequests: rawConfig.RATE_LIMIT_MAX_REQUESTS,
  },
};

// Export individual config values for convenience (backward compatibility)
export const {
  NODE_ENV,
  PORT,
  DATABASE_URL,
  REDIS_URL,
  SESSION_SECRET,
  KEY_ENCRYPTION_SECRET,
  ISSUER_URL,
  ACCESS_TOKEN_TTL,
  REFRESH_TOKEN_TTL,
  KEY_ROTATION_DAYS,
  KMS_PROVIDER,
  AWS_KMS_KEY_ID,
  AZURE_KEY_VAULT_URL,
  GCP_KMS_KEY_NAME,
  ENABLE_MULTI_TENANT,
  ALLOWED_ORIGINS,
  RATE_LIMIT_WINDOW_MS,
  RATE_LIMIT_MAX_REQUESTS,
} = rawConfig;

// Helper functions
export const isDevelopment = () => config.env === 'development';
export const isProduction = () => config.env === 'production';
export const isTest = () => config.env === 'test';
