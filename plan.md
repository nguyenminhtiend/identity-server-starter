# OAuth 2.0 + OIDC Identity Server - Implementation Plan

## Prerequisites & Tech Stack

**Required Versions:**

- Node.js v22 (latest LTS)
- pnpm v10
- PostgreSQL 18
- Redis 7.x

**Core Technologies (all latest versions):**

- TypeScript 5.x
- Express 5.x
- Drizzle ORM (latest)
- jose (latest - JWT handling)
- bcrypt (latest)
- zod (latest - validation)
- EJS (latest - templating)
- helmet (latest - security)
- express-rate-limit (latest)

**Note**: All packages will be installed with `@latest` tag to ensure 2025 industry standards.

## Architecture Overview

**Multi-Tenant & Client Strategy:**

- Support for multiple organizations/tenants (optional, can be single-tenant)
- Client types: Confidential (backend apps) vs Public (SPAs, mobile apps)
- Per-client CORS configuration for public clients
- Client metadata: Terms, privacy policy, homepage URLs

**Token Strategy:**

- JWT Access Tokens: Stateless, RS256 signed, 15 min TTL, includes `kid` header
- Refresh Tokens: Database-stored with rotation, 30 days TTL
- Authorization Codes: Database-stored, single-use, 10 min TTL

**Key Management Strategy:**

- Database-stored signing keys with versioning (support multiple concurrent keys)
- Primary key for signing new tokens, older keys for verification during rotation
- Automatic key rotation support (configurable interval, default 90 days)
- JWKS endpoint returns array of all active public keys
- Support for future KMS integration (AWS KMS, Azure Key Vault, etc.)

**Security Features:**

- PKCE mandatory for all authorization code flows
- Refresh token rotation on each use
- Rate limiting on all endpoints
- Bcrypt password hashing (12 rounds)
- Session management via Redis
- HTTPS enforcement in production
- Key rotation without service downtime

## Phase 1: Foundation & Setup

### 1.1 Project Initialization & Structure

**Initialize Project:**

- Run `pnpm init` to create package.json
- Setup TypeScript config (strict mode, ESNext target)
- Setup environment files (.env.example, .env)
- Create `.gitignore` file

**Module-Based Directory Structure:**

```
identity-server-starter/
├── src/
│   ├── modules/                    # Feature modules (domain-driven design)
│   │   ├── auth/                   # Authentication module
│   │   │   ├── controllers/        # Request handlers
│   │   │   ├── services/           # Business logic
│   │   │   ├── routes/             # Route definitions
│   │   │   ├── validators/         # Input validation schemas
│   │   │   └── views/              # EJS templates
│   │   ├── oauth/                  # OAuth 2.0 module
│   │   │   ├── controllers/
│   │   │   ├── services/           # OAuthService, PKCEService
│   │   │   ├── routes/
│   │   │   ├── validators/
│   │   │   └── views/
│   │   ├── oidc/                   # OpenID Connect module
│   │   │   ├── controllers/
│   │   │   ├── services/
│   │   │   └── routes/
│   │   ├── user/                   # User management module
│   │   │   ├── controllers/
│   │   │   ├── services/
│   │   │   ├── routes/
│   │   │   └── validators/
│   │   ├── client/                 # OAuth client management module
│   │   │   ├── controllers/
│   │   │   ├── services/
│   │   │   ├── routes/
│   │   │   └── validators/
│   │   ├── organization/           # Multi-tenant organization module
│   │   │   ├── controllers/
│   │   │   ├── services/
│   │   │   ├── routes/
│   │   │   └── validators/
│   │   ├── session/                # Session management module
│   │   │   ├── services/
│   │   │   └── routes/
│   │   ├── key-management/         # Cryptographic key management module
│   │   │   ├── controllers/
│   │   │   ├── services/           # KeyManagementService
│   │   │   ├── routes/
│   │   │   └── validators/
│   │   └── admin/                  # Admin panel module
│   │       ├── controllers/
│   │       ├── services/
│   │       ├── routes/
│   │       ├── validators/
│   │       └── views/
│   ├── shared/                     # Shared resources across modules
│   │   ├── config/                 # Configuration loader with zod
│   │   ├── database/               # Database connection and schemas
│   │   │   ├── schema.ts           # Drizzle ORM schemas
│   │   │   ├── migrations/         # Database migration files
│   │   │   └── index.ts            # Database connection
│   │   ├── middleware/             # Global middleware
│   │   ├── utils/                  # Utility functions (crypto, etc.)
│   │   └── types/                  # TypeScript type definitions
│   └── server.ts                   # Main server entry point
├── tests/
│   ├── unit/                       # Unit tests
│   ├── integration/                # Integration tests
│   └── e2e/                        # End-to-end tests
├── drizzle.config.ts               # Drizzle ORM configuration
├── tsconfig.json                   # TypeScript configuration
├── .env.example                    # Environment variable template
└── .gitignore                      # Git ignore rules
```

**Module Design Principles:**

- Each module is self-contained with its own controllers, services, routes, validators
- Modules communicate through well-defined service interfaces
- Shared code lives in `src/shared/`
- Database schemas are centralized in `src/shared/database/schema.ts`
- Each module handles a specific domain (auth, oauth, oidc, etc.)

### 1.2 Dependencies Installation

Install with `pnpm add @latest`:

**Production:**

- express, @types/express
- drizzle-orm, drizzle-kit, postgres
- redis, @types/redis
- express-session, connect-redis, @types/express-session
- bcrypt, @types/bcrypt
- jose (for JWT)
- helmet, cors, @types/cors
- express-rate-limit
- dotenv
- zod
- ejs

**Development:**

- typescript
- tsx (TypeScript executor)
- nodemon
- @types/node

### 1.3 Configuration

Files to create:

- `tsconfig.json`: Strict TypeScript config
- `drizzle.config.ts`: Drizzle ORM config
- `.env.example`: Template for environment variables
- `src/shared/config/index.ts`: Config loader with zod validation

Environment variables:

```
NODE_ENV=development
PORT=3000
DATABASE_URL=postgresql://user:pass@localhost:5432/identity_db
REDIS_URL=redis://localhost:6379

# Session & Security
SESSION_SECRET=<random-string-64-chars>
KEY_ENCRYPTION_SECRET=<master-key-for-encrypting-db-stored-keys>

# Token Configuration
ISSUER_URL=http://localhost:3000
ACCESS_TOKEN_TTL=900
REFRESH_TOKEN_TTL=2592000

# Key Management
KEY_ROTATION_DAYS=90
KMS_PROVIDER=local  # Options: local, aws, azure, gcp
AWS_KMS_KEY_ID=     # Optional: for AWS KMS integration
AZURE_KEY_VAULT_URL= # Optional: for Azure Key Vault

# Multi-tenant (optional, set to false for single-tenant mode)
ENABLE_MULTI_TENANT=false
```

## Phase 2: Database Layer

### 2.1 Drizzle Schema Definition

File: `src/shared/database/schema.ts`

Tables to define:

```typescript
// users: id (uuid), email, password_hash, email_verified, created_at, updated_at

// organizations (optional, for multi-tenant support):
//   id (uuid), name, slug (unique), owner_user_id (fk to users),
//   is_active (boolean), created_at, updated_at

// clients: id (uuid), client_id (unique), client_secret_hash, name,
//          client_type ('confidential' | 'public'),
//          organization_id (nullable fk, null = system-level client),
//          redirect_uris (json array), grant_types (json array),
//          allowed_scopes (text), logo_url (text),
//          allowed_cors_origins (json array, for public clients),
//          terms_url (text), privacy_url (text), homepage_url (text),
//          contacts (json array of emails),
//          is_active (boolean), created_at, updated_at

// authorization_codes: id (uuid), code (unique), client_id (fk), user_id (fk),
//                      redirect_uri, scope, code_challenge, code_challenge_method,
//                      expires_at, used_at (nullable)

// refresh_tokens: id (uuid), token_hash (unique, indexed), client_id (fk),
//                 user_id (fk), scope, expires_at, revoked (boolean),
//                 previous_token_hash (nullable, for rotation tracking),
//                 created_at

// consents: id (uuid), user_id (fk), client_id (fk), scope,
//           granted_at, unique(user_id, client_id)

// signing_keys (for key management):
//   id (uuid), key_id (unique string, e.g., "2025-01-v1"),
//   algorithm (text, default 'RS256'),
//   public_key_pem (text), private_key_encrypted (text),
//   is_active (boolean), is_primary (boolean),
//   created_at, expires_at (nullable),
//   rotated_at (nullable), next_rotation_at (nullable)
```

### 2.2 Database Connection & Migrations

Files:

- `src/shared/database/index.ts`: Database connection setup
- `src/shared/database/migrations/`: Generated migration files
- Create migration: `pnpm db:generate`
- Apply migration: `pnpm db:push`

### 2.3 Initial Key Generation Utility

File: `src/modules/key-management/services/KeyGenerationService.ts`

Purpose: Generate and store cryptographic keys directly in database

- Generate RSA key pair (2048-bit) for JWT signing
- Encrypt private key using KEY_ENCRYPTION_SECRET
- Generate key_id (e.g., timestamp-based: "2025-01-19-v1")
- Insert into `signing_keys` table with is_primary=true, is_active=true
- Set next_rotation_at based on KEY_ROTATION_DAYS
- Run via seed script or CLI command: `pnpm keys:generate`

**Note**: Keys are stored in database from the start, no filesystem storage needed

### 2.4 Seed Data Script

File: `src/shared/database/seed.ts`

- Generate and store initial signing key in database (using KeyGenerationService)
- Create test user (test@example.com / Test123456!)
- Create sample OAuth clients:
  - Confidential client (backend web app with client_secret)
  - Public client (SPA with PKCE, CORS configured)
  - Mobile app client (public with custom redirect URIs)
- Create test organization (if multi-tenant enabled)
- Run with: `pnpm db:seed`

## Phase 3: Core Services & Utilities

### 3.1 Crypto Utilities

File: `src/shared/utils/crypto.ts`

- bcrypt password hashing/verification
- Random token generation (crypto.randomBytes)
- SHA256 hashing for refresh tokens
- AES encryption/decryption for private keys

### 3.2 PKCE Service

File: `src/modules/oauth/services/PKCEService.ts`

- Validate code_challenge_method (S256 only)
- Verify code_verifier against code_challenge
- Generate PKCE challenge for testing

### 3.3 Token Service

File: `src/modules/oauth/services/TokenService.ts`

- Generate JWT access tokens (RS256, 15 min)
- Generate ID tokens (OIDC)
- Verify JWT signatures
- Parse and validate token claims
- Extract user info from tokens

### 3.4 OAuth Service

File: `src/modules/oauth/services/OAuthService.ts`

- Create authorization code
- Exchange code for tokens
- Generate refresh token
- Rotate refresh token
- Revoke tokens
- Validate client credentials
- Validate redirect URIs
- Check consent grants

### 3.5 Validation Schemas

Files in each module's `validators/` directory:

- `src/modules/oauth/validators/`: OAuth parameters, redirect URIs, scopes
- `src/modules/auth/validators/`: Email/password validation
- `src/modules/client/validators/`: Client type, CORS origins
- `src/shared/utils/validation.ts`: Common validation utilities

### 3.6 Key Management Service

File: `src/modules/key-management/services/KeyManagementService.ts`

**Purpose**: Centralized cryptographic key lifecycle management

**Core Functionality**:

- Load all active signing keys from database on service initialization
- Cache keys in memory for performance (refresh periodically)
- Get primary signing key for creating new JWTs
- Get all active public keys for JWKS endpoint
- Verify JWT signatures using appropriate key (based on `kid` header)
- Encrypt/decrypt private keys using KEY_ENCRYPTION_SECRET
- Generate new key pairs and store in database

**Key Rotation Features**:

- `rotateKeys()`: Generate new key pair, mark as primary, deactivate old primary
- Check `next_rotation_at` and trigger rotation automatically (via cron or startup check)
- Support configurable overlap period (old keys stay active for JWT verification)
- Update JWTs to include `kid` (key ID) in header

**Key ID Format**: `YYYY-MM-DD-vN` (e.g., "2025-01-19-v1")

**Future KMS Integration** (Phase 11):

- Abstract interface for KMS providers
- Implementations for AWS KMS, Azure Key Vault, GCP KMS
- Fallback to database storage for local/development

**Methods**:

```typescript
class KeyManagementService {
  async initialize(): Promise<void>;
  async getPrimarySigningKey(): Promise<SigningKey>;
  async getPublicKeys(): Promise<PublicKey[]>;
  async verifyToken(token: string): Promise<JWTPayload>;
  async rotateKeys(): Promise<void>;
  async generateKeyPair(): Promise<{ publicKey: string; privateKey: string }>;
  async encryptPrivateKey(privateKey: string): Promise<string>;
  async decryptPrivateKey(encrypted: string): Promise<string>;
  async checkRotationSchedule(): Promise<void>;
}
```

## Phase 4: Middleware

Files to create in `src/shared/middleware/`:

### 4.1 Error Handler

`errorHandler.ts`: Global error handling with proper OAuth error responses

### 4.2 Authentication

`authenticate.ts`:

- Session authentication (for UI)
- JWT bearer token authentication (for APIs)
- Extract user from access token

### 4.3 Rate Limiting

`rateLimiter.ts`:

- Token endpoint: 10 requests/min per IP
- Auth endpoint: 20 requests/min per IP
- General API: 100 requests/min per IP

### 4.4 Security Headers

`security.ts`: Helmet configuration, CORS setup

### 4.5 Request Validation

`validator.ts`: Middleware to validate requests using zod schemas

## Phase 5: OAuth 2.0 Endpoints

Files:

- Routes: `src/modules/oauth/routes/index.ts`
- Controllers: `src/modules/oauth/controllers/`

### 5.1 Authorization Endpoint

`GET /oauth/authorize`

- Validate client_id, redirect_uri, response_type
- Check PKCE parameters (code_challenge, code_challenge_method)
- Authenticate user (redirect to login if needed)
- Show consent screen (if not previously granted)
- Generate authorization code
- Redirect with code

### 5.2 Token Endpoint

`POST /oauth/token`

Grant types:

- `authorization_code`: Exchange code for tokens (with PKCE verification)
- `refresh_token`: Exchange refresh token for new tokens (with rotation)
- `client_credentials`: Client-only access (no user context)

Response:

```json
{
  "access_token": "eyJhbG...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "rt_...",
  "id_token": "eyJhbG..." // OIDC only
}
```

### 5.3 Token Revocation

`POST /oauth/revoke`

- Revoke access or refresh tokens
- Support token_type_hint parameter

### 5.4 Token Introspection

`POST /oauth/introspect`

- Check token validity
- Return token metadata
- Client authentication required

## Phase 6: OpenID Connect (OIDC)

Files:

- Routes: `src/modules/oidc/routes/index.ts`
- Controllers: `src/modules/oidc/controllers/`

### 6.1 Discovery Document

`GET /.well-known/openid-configuration`

Returns:

```json
{
  "issuer": "http://localhost:3000",
  "authorization_endpoint": "http://localhost:3000/oauth/authorize",
  "token_endpoint": "http://localhost:3000/oauth/token",
  "userinfo_endpoint": "http://localhost:3000/oauth/userinfo",
  "jwks_uri": "http://localhost:3000/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_post"],
  "claims_supported": ["sub", "email", "email_verified"]
}
```

### 6.2 JSON Web Key Set

`GET /.well-known/jwks.json`

- Expose all active public keys for JWT verification
- Support multiple concurrent keys for rotation
- Return array of JWK objects with key IDs

Response format:

```json
{
  "keys": [
    {
      "kid": "2025-01-19-v1",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "<base64url-encoded-modulus>",
      "e": "AQAB"
    },
    {
      "kid": "2024-10-15-v1",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "<base64url-encoded-modulus>",
      "e": "AQAB"
    }
  ]
}
```

**Implementation**: Use KeyManagementService.getPublicKeys() and convert to JWK format using `jose` library

### 6.3 UserInfo Endpoint

`GET /oauth/userinfo`

- Requires valid access token
- Return user claims based on scope
- Support `openid`, `profile`, `email` scopes

## Phase 7: User Interface

Files in `src/modules/auth/views/`:

### 7.1 Login Page

`login.ejs`:

- Email/password form
- CSRF protection
- Error messages
- "Remember me" checkbox
- Link to registration

### 7.2 Registration Page

`register.ejs`:

- Email/password/confirm password
- Email validation
- Password strength indicator
- Terms of service checkbox

### 7.3 Consent Screen

`consent.ejs`:

- Client information (name, logo)
- Requested scopes with descriptions
- Allow/Deny buttons
- Remember decision checkbox

### 7.4 Error Pages

`error.ejs`:

- OAuth error display
- User-friendly messages
- Back to client button

### 7.5 Routes

Files:

- `src/modules/auth/routes/index.ts`
- Controllers: `src/modules/auth/controllers/`

Endpoints:

- `GET /login`
- `POST /login`
- `GET /register`
- `POST /register`
- `GET /logout`
- `GET /consent`
- `POST /consent`

## Phase 8: Client Management

Files:

- Routes: `src/modules/admin/routes/index.ts`
- Controllers: `src/modules/admin/controllers/`
- Services: `src/modules/client/services/ClientService.ts`

Admin endpoints (protected by admin authentication):

### 8.1 Client CRUD Operations

- `POST /admin/clients`: Create OAuth client
  - Required: name, client_type, redirect_uris, grant_types
  - Optional: organization_id, logo_url, allowed_cors_origins, terms_url, privacy_url, etc.
  - Auto-generate client_id and client_secret (for confidential clients)
  - Validate client_type and grant_types compatibility
  - Public clients: PKCE mandatory, no client_secret

- `GET /admin/clients`: List all clients
  - Support filtering by organization_id, client_type, is_active
  - Pagination support
  - Never return client_secret in list view

- `GET /admin/clients/:id`: Get client details
  - Return full client metadata
  - Never return client_secret (only show last 4 chars)

- `PUT /admin/clients/:id`: Update client
  - Allow updating: name, redirect_uris, logo_url, CORS origins, metadata URLs
  - Prevent changing: client_id, client_type, organization_id
  - Require re-authentication for sensitive changes

- `DELETE /admin/clients/:id`: Delete/deactivate client
  - Soft delete: set is_active=false
  - Revoke all active tokens for this client
  - Prevent deletion if active sessions exist (or force flag)

- `POST /admin/clients/:id/secret`: Regenerate client secret
  - Only for confidential clients
  - Invalidate old secret immediately
  - Return new secret only once (not stored in plain text)
  - Audit log the regeneration event

### 8.2 Organization Management (if multi-tenant enabled)

Files:

- Routes: `src/modules/organization/routes/index.ts`
- Controllers: `src/modules/organization/controllers/`
- Services: `src/modules/organization/services/OrganizationService.ts`

Endpoints:

- `POST /admin/organizations`: Create organization
- `GET /admin/organizations`: List organizations
- `GET /admin/organizations/:id`: Get organization details
- `PUT /admin/organizations/:id`: Update organization
- `GET /admin/organizations/:id/clients`: List clients in organization

### 8.3 Key Management Admin Endpoints

Files:

- Routes: `src/modules/key-management/routes/index.ts`
- Controllers: `src/modules/key-management/controllers/`

Endpoints:

- `GET /admin/keys`: List all signing keys (active and inactive)
  - Never return private keys, only metadata
- `POST /admin/keys/rotate`: Manually trigger key rotation
  - Admin-only operation
  - Creates new primary key, deactivates old primary
- `GET /admin/keys/rotation-status`: Check next scheduled rotation

## Phase 9: Session Management

File: `src/shared/config/session.ts`

Setup:

- Redis session store with connect-redis
- Session TTL: 24 hours
- Secure cookie config
- Session regeneration on login
- CSRF protection

## Phase 10: Testing & Documentation

### 10.1 Testing

- Install vitest or jest
- Unit tests for services
- Integration tests for OAuth flows
- Security tests

### 10.2 Documentation

`README.md`:

- Setup instructions
- Environment variables
- API documentation
- OAuth flow examples
- Client integration guide
- Deployment guide

### 10.3 Scripts

Update `package.json`:

```json
{
  "scripts": {
    "dev": "nodemon --exec tsx src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js",
    "db:generate": "drizzle-kit generate",
    "db:push": "drizzle-kit push",
    "db:migrate": "drizzle-kit migrate",
    "db:seed": "tsx src/shared/database/seed.ts",
    "db:studio": "drizzle-kit studio",
    "keys:generate": "tsx src/modules/key-management/services/KeyGenerationService.ts",
    "keys:rotate": "tsx src/modules/key-management/services/KeyRotationService.ts"
  }
}
```

## Security Checklist (2025 Standards)

- [x] PKCE mandatory for authorization code flow (especially public clients)
- [x] Refresh token rotation with revocation
- [x] Rate limiting on all endpoints
- [x] HTTPS only in production
- [x] Secure session cookies (httpOnly, secure, sameSite)
- [x] CORS with per-client origin whitelist
- [x] Helmet.js for security headers
- [x] Input validation with zod
- [x] SQL injection protection (Drizzle parameterized queries)
- [x] XSS protection (EJS auto-escaping)
- [x] CSRF protection on forms
- [x] Bcrypt for passwords (12 rounds minimum)
- [x] RS256 JWT signing (2048-bit keys minimum)
- [x] Password complexity requirements
- [x] Audit logging for security events
- [x] Token expiry enforcement
- [x] Client authentication on token endpoint (confidential clients)
- [x] Key rotation support without downtime
- [x] Private key encryption at rest (database storage)
- [x] Client type enforcement (public vs confidential)
- [x] JWT kid (key ID) header for key rotation
- [x] Soft delete for clients (maintain audit trail)

## OAuth 2.0 Compliance

Standards implemented:

- RFC 6749: OAuth 2.0 Authorization Framework
- RFC 7636: PKCE for OAuth Public Clients
- RFC 7009: Token Revocation
- RFC 7662: Token Introspection
- RFC 8252: OAuth 2.0 for Native Apps
- OpenID Connect Core 1.0
- OpenID Connect Discovery 1.0

## Phase 11: Advanced Features (Future Enhancements)

### 11.1 External KMS Integration

Files: `src/services/kms/`

- Abstract KMS provider interface
- AWS KMS implementation
- Azure Key Vault implementation
- GCP Cloud KMS implementation
- Migration utility from database keys to KMS

### 11.2 Multi-Factor Authentication (MFA)

- TOTP (Time-based One-Time Password) support
- SMS/Email verification codes
- Backup codes
- MFA enrollment flow

### 11.3 Social Login Integration

- OAuth 2.0 federation (Login with Google, GitHub, etc.)
- SAML 2.0 support for enterprise SSO
- Account linking

### 11.4 Advanced Monitoring

- Prometheus metrics endpoint
- Failed login attempt tracking
- Token usage analytics
- Key rotation audit logs

### 11.5 User Management UI

- Admin dashboard for user/client/organization management
- User self-service portal
- Consent management interface

---

## Implementation Checklist

### Phase 1: Foundation

- [ ] Initialize project with package.json, tsconfig.json
- [ ] Create module-based directory structure
- [ ] Install dependencies (express, drizzle, redis, jose, bcrypt, etc.)
- [ ] Setup environment config with zod validation in `src/shared/config/`
- [ ] Create .gitignore file

### Phase 2: Database Layer

- [ ] Define Drizzle schemas in `src/shared/database/schema.ts`: users, organizations, clients, auth codes, refresh tokens, consents, signing_keys
- [ ] Add client_type, CORS origins, metadata URLs to clients table
- [ ] Setup database connection in `src/shared/database/index.ts`
- [ ] Create database migrations
- [ ] Build KeyGenerationService for direct database key storage
- [ ] Create seed script with initial key generation and sample clients (confidential, public, mobile)

### Phase 3: Core Services

- [ ] Implement crypto utilities in `src/shared/utils/crypto.ts` (bcrypt, random tokens, SHA256, AES encryption)
- [ ] Build PKCEService in `src/modules/oauth/services/` with S256 validation
- [ ] Create KeyManagementService in `src/modules/key-management/services/` for database-stored keys with rotation
- [ ] Build TokenService in `src/modules/oauth/services/` with kid header support for key rotation
- [ ] Implement OAuthService in `src/modules/oauth/services/` with client type awareness
- [ ] Create validation schemas in each module's validators directory

### Phase 4: Middleware

- [ ] Build error handler with OAuth error responses in `src/shared/middleware/`
- [ ] Create authentication middleware (session + JWT)
- [ ] Implement rate limiting for all endpoints
- [ ] Setup security headers with Helmet and per-client CORS
- [ ] Create request validation middleware

### Phase 5: OAuth 2.0 Endpoints

- [ ] Implement /oauth/authorize with PKCE enforcement in `src/modules/oauth/`
- [ ] Build /oauth/token with client type validation
- [ ] Create /oauth/revoke endpoint
- [ ] Implement /oauth/introspect endpoint

### Phase 6: OIDC Endpoints

- [ ] Build OIDC discovery document endpoint in `src/modules/oidc/`
- [ ] Implement JWKS endpoint with multi-key support
- [ ] Create /oauth/userinfo endpoint

### Phase 7: User Interface

- [ ] Create login, registration, consent, and error EJS templates in `src/modules/auth/views/`
- [ ] Build authentication routes and controllers in `src/modules/auth/`

### Phase 8: Admin & Client Management

- [ ] Implement client CRUD endpoints in `src/modules/admin/` and `src/modules/client/`
- [ ] Build client secret regeneration endpoint
- [ ] Create organization management in `src/modules/organization/` (if multi-tenant)
- [ ] Implement key rotation admin endpoints in `src/modules/key-management/`

### Phase 9: Session Management

- [ ] Setup Redis session store with connect-redis in `src/shared/config/session.ts`
- [ ] Configure secure session cookies
- [ ] Implement CSRF protection in `src/modules/session/`

### Phase 10: Testing & Documentation

- [ ] Write unit tests for services (KeyManagementService, TokenService, OAuthService)
- [ ] Create integration tests for OAuth flows (authorization code, refresh token, PKCE)
- [ ] Write comprehensive README with setup, API docs, client integration guide
- [ ] Document key rotation procedures
- [ ] Create deployment guide with KMS recommendations
