# Project Structure

## Module-Based Architecture

This project follows a **domain-driven design** with feature modules:

```
identity-server-starter/
├── src/
│   ├── modules/                         # Feature modules (domain-driven)
│   │   ├── auth/                        # Authentication module
│   │   │   ├── controllers/             # Handle HTTP requests
│   │   │   ├── services/                # Business logic (AuthService)
│   │   │   ├── routes/                  # Route definitions
│   │   │   ├── validators/              # Zod schemas for validation
│   │   │   └── views/                   # EJS templates (login, register, consent)
│   │   │
│   │   ├── oauth/                       # OAuth 2.0 module
│   │   │   ├── controllers/             # OAuth endpoints handlers
│   │   │   ├── services/                # OAuthService, PKCEService, TokenService
│   │   │   ├── routes/                  # /oauth/authorize, /oauth/token, etc.
│   │   │   ├── validators/              # OAuth parameter validation
│   │   │   └── views/                   # OAuth UI templates
│   │   │
│   │   ├── oidc/                        # OpenID Connect module
│   │   │   ├── controllers/             # OIDC endpoints (.well-known, userinfo)
│   │   │   ├── services/                # OIDC-specific logic
│   │   │   └── routes/                  # OIDC discovery, JWKS
│   │   │
│   │   ├── user/                        # User management module
│   │   │   ├── controllers/             # User CRUD operations
│   │   │   ├── services/                # UserService
│   │   │   ├── routes/                  # User endpoints
│   │   │   └── validators/              # User input validation
│   │   │
│   │   ├── client/                      # OAuth client management module
│   │   │   ├── controllers/             # Client CRUD handlers
│   │   │   ├── services/                # ClientService
│   │   │   ├── routes/                  # Client endpoints
│   │   │   └── validators/              # Client validation (types, CORS)
│   │   │
│   │   ├── organization/                # Multi-tenant organization module
│   │   │   ├── controllers/             # Organization CRUD
│   │   │   ├── services/                # OrganizationService
│   │   │   ├── routes/                  # Organization endpoints
│   │   │   └── validators/              # Organization validation
│   │   │
│   │   ├── session/                     # Session management module
│   │   │   ├── services/                # Session handling
│   │   │   └── routes/                  # Session-related endpoints
│   │   │
│   │   ├── key-management/              # Cryptographic key management
│   │   │   ├── controllers/             # Key admin endpoints
│   │   │   ├── services/                # KeyManagementService, KeyGenerationService
│   │   │   ├── routes/                  # Key rotation endpoints
│   │   │   └── validators/              # Key validation
│   │   │
│   │   └── admin/                       # Admin panel module
│   │       ├── controllers/             # Admin dashboard handlers
│   │       ├── services/                # Admin operations
│   │       ├── routes/                  # Admin endpoints
│   │       ├── validators/              # Admin input validation
│   │       └── views/                   # Admin UI templates
│   │
│   ├── shared/                          # Shared resources across modules
│   │   ├── config/                      # Configuration loader (zod validation)
│   │   │   ├── index.ts                 # Main config loader
│   │   │   └── session.ts               # Redis session configuration
│   │   │
│   │   ├── database/                    # Database layer
│   │   │   ├── schema.ts                # Drizzle ORM schemas (all tables)
│   │   │   ├── migrations/              # Database migration files
│   │   │   ├── index.ts                 # Database connection
│   │   │   └── seed.ts                  # Seed script
│   │   │
│   │   ├── middleware/                  # Global middleware
│   │   │   ├── errorHandler.ts          # OAuth error responses
│   │   │   ├── authenticate.ts          # Session + JWT auth
│   │   │   ├── rateLimiter.ts           # Rate limiting
│   │   │   ├── security.ts              # Helmet + CORS
│   │   │   └── validator.ts             # Request validation
│   │   │
│   │   ├── utils/                       # Utility functions
│   │   │   ├── crypto.ts                # bcrypt, AES, SHA256, random tokens
│   │   │   └── validation.ts            # Common validation utilities
│   │   │
│   │   └── types/                       # TypeScript type definitions
│   │       └── index.ts                 # Global types, interfaces
│   │
│   └── server.ts                        # Main application entry point
│
├── tests/                               # Test files
│   ├── unit/                            # Unit tests for services
│   ├── integration/                     # Integration tests for OAuth flows
│   └── e2e/                             # End-to-end tests
│
├── drizzle.config.ts                    # Drizzle ORM configuration
├── tsconfig.json                        # TypeScript configuration
├── package.json                         # Dependencies & scripts
├── .env.example                         # Environment variable template
├── .gitignore                           # Git ignore rules
└── plan.md                              # Full implementation plan
```

## Key Design Principles

### 1. **Module Isolation**

- Each module is self-contained with its own controllers, services, routes, validators, and views
- Modules can be developed, tested, and maintained independently
- Clear boundaries between domains (auth, oauth, oidc, etc.)

### 2. **Shared Resources**

- Common code lives in `src/shared/`
- Database schemas centralized in `src/shared/database/schema.ts`
- Global middleware and utilities available to all modules

### 3. **Service Layer**

- Business logic isolated in service classes
- Services are the only layer that interacts with the database
- Controllers are thin and delegate to services

### 4. **Database-First Key Management**

- **No filesystem key storage** - keys stored in database from the start
- Keys encrypted at rest using `KEY_ENCRYPTION_SECRET`
- Support for multiple concurrent keys (rotation without downtime)
- JWKS endpoint exposes all active public keys

### 5. **Scalability**

- Module structure allows easy addition of new features
- Clear separation of concerns
- Easy to split into microservices if needed

## Module Responsibilities

| Module             | Purpose                                                   |
| ------------------ | --------------------------------------------------------- |
| **auth**           | User login, registration, consent screens                 |
| **oauth**          | OAuth 2.0 flows (authorization code, refresh token, PKCE) |
| **oidc**           | OpenID Connect (discovery, JWKS, userinfo)                |
| **user**           | User management and profile operations                    |
| **client**         | OAuth client registration and management                  |
| **organization**   | Multi-tenant organization support                         |
| **session**        | Redis-based session management                            |
| **key-management** | Cryptographic key lifecycle (generation, rotation)        |
| **admin**          | Admin dashboard and operations                            |

## Technology Stack

- **Runtime**: Node.js v22 + TypeScript 5.x
- **Framework**: Express 5.x
- **Database**: PostgreSQL 18 + Drizzle ORM
- **Caching**: Redis 7.x
- **JWT**: jose library (RS256 signing)
- **Security**: helmet, bcrypt, PKCE, rate-limiting
- **Validation**: zod
- **Templates**: EJS

## Next Steps

1. Follow `plan.md` to implement Phase 1 (Foundation & Setup)
2. Each phase builds on the previous one
3. Start with shared utilities, then database layer, then services, then endpoints
