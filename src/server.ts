import express, { type Application } from 'express';
import session from 'express-session';
import { createClient } from 'redis';
import RedisStore from 'connect-redis';
import path from 'path';
import { config } from './shared/config';
import { errorHandler } from './shared/middleware/errorHandler';
import { securityMiddleware, corsMiddleware } from './shared/middleware/security';
import { rateLimiter } from './shared/middleware/rateLimiter';
import oauthRoutes from './modules/oauth/routes';
import oidcRoutes from './modules/oidc/routes';

async function createServer(): Promise<Application> {
  const app = express();

  // Trust proxy (important for rate limiting and secure cookies behind reverse proxy)
  app.set('trust proxy', 1);

  // View engine setup
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'modules'));

  // Security middleware
  app.use(securityMiddleware);
  app.use(corsMiddleware);

  // Body parsers
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Redis client setup for sessions
  const redisClient = createClient({
    url: config.redis.url,
  });

  redisClient.on('error', (err) => {
    console.error('Redis client error:', err);
  });

  await redisClient.connect();
  console.log('✅ Connected to Redis');

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

  // Rate limiting
  app.use(rateLimiter);

  // Health check endpoint
  app.get('/health', (req, res) => {
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
      console.log('🚀 Identity Server started');
      console.log(`📍 Environment: ${config.env}`);
      console.log(`🌐 Server running on port ${port}`);
      console.log(`🔗 Issuer URL: ${config.issuer}`);
      console.log('');
      console.log('OAuth 2.0 Endpoints:');
      console.log(`  - Authorization: ${config.issuer}/oauth/authorize`);
      console.log(`  - Token: ${config.issuer}/oauth/token`);
      console.log(`  - Revoke: ${config.issuer}/oauth/revoke`);
      console.log(`  - Introspect: ${config.issuer}/oauth/introspect`);
      console.log('');
      console.log('OpenID Connect Endpoints:');
      console.log(`  - Discovery: ${config.issuer}/.well-known/openid-configuration`);
      console.log(`  - JWKS: ${config.issuer}/.well-known/jwks.json`);
      console.log(`  - UserInfo: ${config.issuer}/oauth/userinfo`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  process.exit(0);
});

// Start the server
void startServer();

export { createServer };
