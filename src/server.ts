import express, { type Application } from 'express';
import session from 'express-session';
import { createClient } from 'redis';
import { RedisStore } from 'connect-redis';
import path from 'path';
import { fileURLToPath } from 'url';
import { config } from './shared/config';
import { errorHandler, helmetConfig, devCorsMiddleware } from './shared/middleware';
import { configureDIContainer } from './shared/di';
import { logger } from './shared/utils';

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function createServer(): Promise<Application> {
  // Initialize DI container before anything else
  configureDIContainer();
  logger.info('✅ DI Container configured');

  // Import routes AFTER DI container is configured
  // This ensures services are available when routes initialize
  const { default: oauthRoutes } = await import('./modules/oauth/routes');
  const { default: oidcRoutes } = await import('./modules/oidc/routes');

  const app = express();

  // View engine setup
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'modules'));

  // Security middleware
  app.use(helmetConfig);
  app.use(devCorsMiddleware);

  // Body parsers
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Redis client setup for sessions
  const redisClient = createClient({
    url: config.redis.url,
  });

  redisClient.on('error', (err) => {
    logger.error({ err }, 'Redis client error');
  });

  await redisClient.connect();
  logger.info('✅ Connected to Redis');

  // Session store
  const redisStore = new RedisStore({
    client: redisClient,
    prefix: 'sess:',
  });

  // Session configuration
  app.use(
    session({
      store: redisStore,
      secret: config.session.secret,
      resave: false,
      saveUninitialized: false,
      name: 'sid',
      cookie: {
        secure: config.env === 'production', // HTTPS only in production
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax',
      },
    })
  );

  // Health check endpoint
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Mount OAuth routes
  app.use('/oauth', oauthRoutes);

  // Mount OIDC routes (discovery and UserInfo)
  app.use(oidcRoutes);

  // TODO: Mount other routes
  // app.use('/login', authRoutes);
  // app.use('/admin', adminRoutes);

  // 404 handler
  app.use((req, res) => {
    res.status(404).json({
      error: 'not_found',
      error_description: 'The requested resource was not found',
      path: req.path,
    });
  });

  // Global error handler (must be last)
  app.use(errorHandler);

  return app;
}

async function startServer(): Promise<void> {
  try {
    const app = await createServer();
    const port = config.port;

    app.listen(port, () => {
      logger.info('🚀 Identity Server started');
      logger.info(`📍 Environment: ${config.env}`);
      logger.info(`🌐 Server running on port ${port}`);
      logger.info(`🔗 Issuer URL: ${config.issuer}`);
      logger.info('');
      logger.info('OAuth 2.0 Endpoints:');
      logger.info(`  - Authorization: ${config.issuer}/oauth/authorize`);
      logger.info(`  - Token: ${config.issuer}/oauth/token`);
      logger.info(`  - Revoke: ${config.issuer}/oauth/revoke`);
      logger.info(`  - Introspect: ${config.issuer}/oauth/introspect`);
      logger.info('');
      logger.info('OpenID Connect Endpoints:');
      logger.info(`  - Discovery: ${config.issuer}/.well-known/openid-configuration`);
      logger.info(`  - JWKS: ${config.issuer}/.well-known/jwks.json`);
      logger.info(`  - UserInfo: ${config.issuer}/oauth/userinfo`);
    });
  } catch (error) {
    logger.error({ err: error }, '❌ Failed to start server');
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT signal received: closing HTTP server');
  process.exit(0);
});

// Start the server
void startServer();

export { createServer };
