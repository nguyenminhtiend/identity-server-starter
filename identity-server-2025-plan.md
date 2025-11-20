# OAuth 2.0 + OIDC Identity Server - 2025 Industry Standard Implementation Plan

## Overview

**Enterprise-grade Identity & Access Management (IAM) system** following 2025 best practices with:

- OAuth 2.0 & OpenID Connect (OIDC) compliance
- Multi-factor Authentication (2FA/MFA) as core feature
- Social & Enterprise SSO integration
- Passwordless authentication options
- Zero-trust security architecture
- Production-ready monitoring & observability

---

## Prerequisites & Tech Stack

**Required Versions:**

- Node.js v22 (latest LTS)
- pnpm v10
- PostgreSQL 16+
- Redis 7.x
- Docker & Docker Compose (for local development)

**Core Technologies (2025 standards):**

- **TypeScript 5.x** - Strict mode, latest ES features
- **Express 5.x** - Latest async error handling
- **Drizzle ORM** - Type-safe SQL with migrations
- **jose** - Modern JWT/JWK handling (replaces jsonwebtoken)
- **@node-rs/argon2** - Argon2id password hashing (replaces bcrypt for 2025)
- **@simplewebauthn/server** - WebAuthn/Passkeys support
- **otpauth** - TOTP for 2FA
- **zod** - Runtime type validation
- **Arctic** - OAuth provider integrations (Google, GitHub, etc.)
- **bullmq** - Background job processing
- **pino** - Structured logging
- **opentelemetry** - Distributed tracing
- **prometheus-client** - Metrics collection

**Security Stack:**

- helmet (CSP, XSS protection)
- express-rate-limit + rate-limit-redis
- csurf (CSRF protection)
- zxcvbn (password strength estimation)
- Rate limiting with sliding window

---

## Architecture Decisions (2025 Standards)

### 1. **Password Hashing: Argon2id over Bcrypt**

- **Why**: Argon2id won the Password Hashing Competition (2015) and is now the OWASP recommendation
- **Config**: memory=64MB, iterations=3, parallelism=4
- **Migration**: Bcrypt hashes can coexist; upgrade on next login

### 2. **Key Management: Database-first with KMS abstraction**

- Primary: Database-stored encrypted keys (AES-256-GCM)
- Future: AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault
- Automatic rotation every 90 days with zero downtime
- Multiple concurrent keys for gradual rollover

### 3. **Token Strategy**

- **Access Tokens**: JWT RS256, 15min TTL, stateless
- **Refresh Tokens**: Opaque tokens, database-stored, 30-day TTL with rotation
- **ID Tokens**: OIDC compliant, same key as access tokens
- **Authorization Codes**: Single-use, 10min TTL
- **Device Codes**: For TV/IoT flows (RFC 8628)
- All tokens include `jti` (JWT ID) for revocation

### 4. **Session Management**

- Redis-backed sessions with sliding expiration
- Session fixation protection
- Concurrent session limits per user
- Device fingerprinting (optional, privacy-conscious)

### 5. **Multi-Factor Authentication (2FA/MFA)**

- **TOTP** (Time-based OTP): Authenticator apps (Google, Authy, 1Password)
- **WebAuthn/FIDO2**: Passkeys, YubiKey, biometric
- **SMS OTP**: Via Twilio/SNS (fallback, not recommended as primary)
- **Email OTP**: Backup codes
- **Recovery codes**: One-time use backup codes (10 generated)
- Enforced at authorization time, not just login

### 6. **Passwordless Options**

- **Magic Links**: Time-limited email links
- **WebAuthn**: Platform authenticators (Touch ID, Face ID, Windows Hello)
- **Passkeys**: FIDO2 resident keys (synced via iCloud/Google Password Manager)

### 7. **Social & Enterprise Federation**

- **Social Providers**: Google, GitHub, Microsoft, Apple, Facebook, Discord
- **Enterprise SSO**: SAML 2.0, Azure AD, Okta, Auth0
- **Account Linking**: Link multiple providers to one identity
- **JIT Provisioning**: Auto-create users on first SSO login

### 8. **Client Types & Security**

- **Confidential Clients**: Backend apps with client_secret
- **Public Clients**: SPAs, mobile apps (PKCE mandatory)
- **First-Party vs Third-Party**: Different consent flows
- **DPoP** (Demonstrating Proof-of-Possession): For public clients (RFC 9449)
- **PAR** (Pushed Authorization Requests): For high-security flows (RFC 9126)

### 9. **Observability & Monitoring**

- Structured logging with pino (JSON logs)
- OpenTelemetry traces & spans
- Prometheus metrics (token issue rate, latency, error rate)
- Grafana dashboards
- Alert rules for security events

### 10. **Rate Limiting Strategy**

- Token endpoint: 10 req/min per IP (sliding window)
- Auth endpoint: 20 req/min per user
- Registration: 5 req/hour per IP
- Password reset: 3 req/hour per email
- 2FA verification: 5 attempts then lockout
- Distributed rate limiting via Redis

---

## Database Schema (2025 Enhanced)

### Core Tables

```typescript
// users
{
  id: uuid (PK),
  email: text (unique, indexed),
  email_verified: boolean,
  password_hash: text (nullable, argon2id format),
  password_algorithm: 'argon2id' | 'bcrypt', // for migration

  // Profile
  name: text,
  given_name: text,
  family_name: text,
  picture_url: text,
  locale: text,
  timezone: text,

  // Security
  mfa_enabled: boolean,
  mfa_methods: jsonb[], // ['totp', 'webauthn', 'sms']
  backup_codes_hash: text[],
  account_locked: boolean,
  locked_until: timestamp,
  failed_login_attempts: integer,
  password_changed_at: timestamp,

  // Privacy
  consent_marketing: boolean,
  consent_analytics: boolean,

  // Metadata
  created_at: timestamp,
  updated_at: timestamp,
  last_login_at: timestamp,
  deleted_at: timestamp (soft delete)
}

// mfa_totp
{
  id: uuid (PK),
  user_id: uuid (FK, unique),
  secret_encrypted: text, // AES-256-GCM encrypted
  verified: boolean,
  created_at: timestamp,
  last_used_at: timestamp
}

// mfa_webauthn_credentials
{
  id: uuid (PK),
  user_id: uuid (FK),
  credential_id: text (unique),
  public_key: text,
  counter: bigint,
  device_name: text,
  transports: text[], // ['usb', 'nfc', 'ble', 'internal']
  backup_eligible: boolean, // passkey sync
  backup_state: boolean,
  created_at: timestamp,
  last_used_at: timestamp
}

// federated_identities (social login)
{
  id: uuid (PK),
  user_id: uuid (FK),
  provider: text, // 'google', 'github', 'microsoft', etc.
  provider_user_id: text, // subject from provider
  provider_email: text,
  provider_data: jsonb, // raw profile data
  access_token_encrypted: text (nullable),
  refresh_token_encrypted: text (nullable),
  token_expires_at: timestamp,
  created_at: timestamp,
  updated_at: timestamp,
  unique(provider, provider_user_id)
}

// organizations (multi-tenant)
{
  id: uuid (PK),
  slug: text (unique, indexed),
  name: text,
  display_name: text,
  logo_url: text,

  // SSO Configuration
  sso_enabled: boolean,
  saml_metadata_url: text,
  oidc_issuer: text,
  sso_domain: text, // enforce SSO for @company.com emails

  // Billing
  plan: 'free' | 'pro' | 'enterprise',
  seats_limit: integer,

  // Security Policies
  require_mfa: boolean,
  password_policy: jsonb,
  session_timeout_minutes: integer,

  owner_user_id: uuid (FK),
  is_active: boolean,
  created_at: timestamp,
  updated_at: timestamp
}

// organization_members
{
  id: uuid (PK),
  organization_id: uuid (FK),
  user_id: uuid (FK),
  role: 'owner' | 'admin' | 'member',
  invited_by: uuid (FK, nullable),
  joined_at: timestamp,
  unique(organization_id, user_id)
}

// clients (OAuth clients)
{
  id: uuid (PK),
  client_id: text (unique, indexed),
  client_secret_hash: text (nullable), // argon2id
  name: text,
  description: text,

  // Client Type
  client_type: 'confidential' | 'public',
  is_first_party: boolean, // skip consent if true

  // OAuth Config
  redirect_uris: text[],
  post_logout_redirect_uris: text[],
  grant_types: text[], // ['authorization_code', 'refresh_token', 'client_credentials']
  response_types: text[], // ['code', 'token', 'id_token']
  allowed_scopes: text[],

  // PKCE & Security
  require_pkce: boolean (default true for public),
  require_pushed_authorization_requests: boolean, // PAR
  require_dpop: boolean, // DPoP

  // Token Settings
  access_token_ttl_seconds: integer (default 900),
  refresh_token_ttl_seconds: integer (default 2592000),
  id_token_ttl_seconds: integer (default 3600),

  // CORS (for public clients)
  allowed_cors_origins: text[],

  // Client Metadata
  logo_uri: text,
  client_uri: text (homepage),
  policy_uri: text (privacy),
  tos_uri: text (terms),
  contacts: text[] (emails),

  // Organization
  organization_id: uuid (FK, nullable),

  // Status
  is_active: boolean,
  created_at: timestamp,
  updated_at: timestamp
}

// authorization_codes
{
  id: uuid (PK),
  code: text (unique, indexed),
  client_id: uuid (FK),
  user_id: uuid (FK),
  redirect_uri: text,
  scope: text,
  nonce: text (nullable), // OIDC

  // PKCE
  code_challenge: text,
  code_challenge_method: 'S256',

  // PAR
  pushed_at: timestamp (nullable),

  // MFA
  acr_values: text, // authentication context (mfa level)
  amr_values: text[], // auth methods used ['pwd', 'totp', 'webauthn']

  expires_at: timestamp,
  used_at: timestamp (nullable),
  created_at: timestamp,
  index(code, used_at)
}

// refresh_tokens
{
  id: uuid (PK),
  token_hash: text (unique, indexed), // SHA-256
  jti: text (unique), // JWT ID for revocation
  client_id: uuid (FK),
  user_id: uuid (FK),
  scope: text,

  // Rotation Chain
  previous_token_id: uuid (FK, nullable),
  rotation_count: integer,

  // Device Info
  device_fingerprint: text,
  user_agent: text,
  ip_address: inet,

  // Status
  expires_at: timestamp,
  revoked: boolean,
  revoked_at: timestamp,
  revoked_reason: text,

  created_at: timestamp,
  last_used_at: timestamp,

  index(token_hash, revoked),
  index(user_id, client_id, revoked)
}

// consents
{
  id: uuid (PK),
  user_id: uuid (FK),
  client_id: uuid (FK),
  scope: text,
  granted_at: timestamp,
  expires_at: timestamp (nullable),
  remember_consent: boolean,
  unique(user_id, client_id)
}

// signing_keys
{
  id: uuid (PK),
  key_id: text (unique), // kid in JWT header, format: "2025-01-v1"
  algorithm: text, // 'RS256', 'ES256'
  key_type: 'RSA' | 'EC',

  // Key Material (encrypted with KEY_ENCRYPTION_SECRET)
  public_key_pem: text,
  private_key_encrypted: text,

  // Rotation
  is_active: boolean, // can verify tokens
  is_primary: boolean, // signs new tokens (only one primary)
  created_at: timestamp,
  expires_at: timestamp (nullable),
  rotated_at: timestamp (nullable),
  next_rotation_at: timestamp,

  // KMS (future)
  kms_provider: text (nullable), // 'aws', 'azure', 'gcp', 'vault'
  kms_key_id: text (nullable),

  index(is_active, is_primary)
}

// sessions (Redis primary, Postgres backup)
{
  id: uuid (PK),
  session_id: text (unique, indexed),
  user_id: uuid (FK),
  data: jsonb,

  // Device
  user_agent: text,
  ip_address: inet,

  expires_at: timestamp,
  created_at: timestamp,
  last_activity_at: timestamp,

  index(user_id, expires_at)
}

// audit_logs (security events)
{
  id: uuid (PK),
  event_type: text, // 'login', 'logout', 'mfa_enabled', 'token_issued', etc.
  actor_user_id: uuid (FK, nullable),
  target_user_id: uuid (FK, nullable),
  client_id: uuid (FK, nullable),

  // Request Context
  ip_address: inet,
  user_agent: text,

  // Event Data
  event_data: jsonb,
  severity: 'info' | 'warning' | 'critical',

  // Result
  success: boolean,
  error_message: text,

  created_at: timestamp,

  index(event_type, created_at),
  index(actor_user_id, created_at),
  index(ip_address, created_at)
}

// magic_links (passwordless)
{
  id: uuid (PK),
  token: text (unique, indexed),
  email: text,
  user_id: uuid (FK, nullable),
  expires_at: timestamp,
  used_at: timestamp (nullable),
  ip_address: inet,
  created_at: timestamp
}

// device_codes (RFC 8628 - for TV/IoT)
{
  id: uuid (PK),
  device_code: text (unique, indexed),
  user_code: text (unique), // short code for user entry
  client_id: uuid (FK),
  scope: text,
  expires_at: timestamp,
  interval: integer, // polling interval in seconds
  verified_at: timestamp (nullable),
  user_id: uuid (FK, nullable),
  created_at: timestamp
}

// rate_limits (persistent tracking)
{
  id: uuid (PK),
  key: text (unique), // 'ip:123.45.67.89' or 'user:uuid'
  endpoint: text,
  count: integer,
  window_start: timestamp,
  blocked_until: timestamp (nullable),
  created_at: timestamp,
  updated_at: timestamp
}
```

---

## Phase 1: Foundation & Modern Setup

### 1.1 Project Initialization

```bash
pnpm init
pnpm add express@latest @types/express
pnpm add typescript@latest tsx nodemon -D
pnpm add drizzle-orm@latest drizzle-kit@latest postgres
pnpm add redis@latest ioredis@latest @types/ioredis
pnpm add jose@latest
pnpm add @node-rs/argon2@latest
pnpm add zod@latest
pnpm add helmet@latest cors@latest @types/cors
pnpm add express-rate-limit@latest rate-limit-redis@latest
pnpm add express-session@latest connect-redis@latest @types/express-session
pnpm add ejs@latest
pnpm add dotenv@latest
pnpm add pino@latest pino-pretty@latest
pnpm add bullmq@latest
pnpm add otpauth@latest qrcode@latest @types/qrcode
pnpm add @simplewebauthn/server@latest
pnpm add arctic@latest # OAuth providers
pnpm add twilio@latest @aws-sdk/client-sns # SMS (optional)
pnpm add nodemailer@latest @types/nodemailer
pnpm add zxcvbn@latest @types/zxcvbn
pnpm add csurf@latest @types/csurf
pnpm add prom-client@latest # Prometheus metrics
pnpm add @opentelemetry/api@latest @opentelemetry/sdk-node@latest
```

### 1.2 TypeScript Configuration (2025)

`tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2023",
    "module": "Node16",
    "moduleResolution": "Node16",
    "lib": ["ES2023"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "allowUnreachableCode": false,
    "exactOptionalPropertyTypes": true,
    "noUncheckedIndexedAccess": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

### 1.3 Environment Configuration

`.env.example`:

```bash
# Environment
NODE_ENV=development
PORT=3000
LOG_LEVEL=debug

# Database
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/identity_db
DATABASE_POOL_SIZE=20

# Redis
REDIS_URL=redis://localhost:6379
REDIS_KEY_PREFIX=idp:

# Security Keys
SESSION_SECRET=<generate-64-char-random-string>
KEY_ENCRYPTION_SECRET=<generate-32-byte-base64-encoded-key>
CSRF_SECRET=<generate-32-char-random-string>

# JWT Configuration
ISSUER_URL=http://localhost:3000
ACCESS_TOKEN_TTL=900
REFRESH_TOKEN_TTL=2592000
ID_TOKEN_TTL=3600
AUTHORIZATION_CODE_TTL=600

# Key Rotation
KEY_ROTATION_DAYS=90
KEY_ALGORITHM=RS256
KEY_SIZE=2048

# MFA/2FA
TOTP_ISSUER=MyIdentityServer
TOTP_WINDOW=1
WEBAUTHN_RP_NAME=MyIdentityServer
WEBAUTHN_RP_ID=localhost
WEBAUTHN_ORIGIN=http://localhost:3000

# SMS Provider (optional)
SMS_PROVIDER=twilio
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_PHONE_NUMBER=

# Email
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.mailtrap.io
SMTP_PORT=2525
SMTP_USER=
SMTP_PASSWORD=
EMAIL_FROM=noreply@identityserver.local

# Social Login (OAuth Providers)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google/callback

GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_REDIRECT_URI=http://localhost:3000/auth/github/callback

MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
MICROSOFT_TENANT_ID=common
MICROSOFT_REDIRECT_URI=http://localhost:3000/auth/microsoft/callback

# Apple Sign In
APPLE_CLIENT_ID=
APPLE_TEAM_ID=
APPLE_KEY_ID=
APPLE_PRIVATE_KEY=

# Rate Limiting
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=100

# Multi-tenant
ENABLE_MULTI_TENANT=false

# Monitoring
METRICS_ENABLED=true
METRICS_PORT=9090
TRACING_ENABLED=true
JAEGER_ENDPOINT=http://localhost:14268/api/traces

# Feature Flags
ENABLE_PASSWORDLESS=true
ENABLE_WEBAUTHN=true
ENABLE_MAGIC_LINK=true
ENABLE_DEVICE_FLOW=false
ENABLE_PAR=false
ENABLE_DPOP=false
```

### 1.4 Configuration Loader with Validation

`src/shared/config/index.ts`:

```typescript
import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const configSchema = z.object({
  node_env: z.enum(['development', 'production', 'test']),
  port: z.coerce.number().default(3000),
  log_level: z.enum(['debug', 'info', 'warn', 'error']).default('info'),

  database_url: z.string().url(),
  redis_url: z.string().url(),

  session_secret: z.string().min(32),
  key_encryption_secret: z.string().min(32),
  csrf_secret: z.string().min(32),

  issuer_url: z.string().url(),
  access_token_ttl: z.coerce.number().default(900),
  refresh_token_ttl: z.coerce.number().default(2592000),

  // MFA
  totp_issuer: z.string().default('IdentityServer'),
  webauthn_rp_name: z.string().default('IdentityServer'),
  webauthn_rp_id: z.string(),
  webauthn_origin: z.string().url(),

  // Social OAuth
  google_client_id: z.string().optional(),
  google_client_secret: z.string().optional(),
  github_client_id: z.string().optional(),
  github_client_secret: z.string().optional(),

  // Feature flags
  enable_multi_tenant: z.coerce.boolean().default(false),
  enable_passwordless: z.coerce.boolean().default(true),
  enable_webauthn: z.coerce.boolean().default(true),
});

export const config = configSchema.parse({
  node_env: process.env.NODE_ENV,
  port: process.env.PORT,
  log_level: process.env.LOG_LEVEL,
  database_url: process.env.DATABASE_URL,
  redis_url: process.env.REDIS_URL,
  session_secret: process.env.SESSION_SECRET,
  key_encryption_secret: process.env.KEY_ENCRYPTION_SECRET,
  csrf_secret: process.env.CSRF_SECRET,
  issuer_url: process.env.ISSUER_URL,
  access_token_ttl: process.env.ACCESS_TOKEN_TTL,
  refresh_token_ttl: process.env.REFRESH_TOKEN_TTL,
  totp_issuer: process.env.TOTP_ISSUER,
  webauthn_rp_name: process.env.WEBAUTHN_RP_NAME,
  webauthn_rp_id: process.env.WEBAUTHN_RP_ID,
  webauthn_origin: process.env.WEBAUTHN_ORIGIN,
  google_client_id: process.env.GOOGLE_CLIENT_ID,
  google_client_secret: process.env.GOOGLE_CLIENT_SECRET,
  github_client_id: process.env.GITHUB_CLIENT_ID,
  github_client_secret: process.env.GITHUB_CLIENT_SECRET,
  enable_multi_tenant: process.env.ENABLE_MULTI_TENANT,
  enable_passwordless: process.env.ENABLE_PASSWORDLESS,
  enable_webauthn: process.env.ENABLE_WEBAUTHN,
});

export type Config = z.infer<typeof configSchema>;
```

---

## Phase 2: Enhanced Database Layer

### 2.1 Drizzle Schema (All Tables)

Create complete schema with all tables listed in Database Schema section above.

### 2.2 Migrations

```bash
pnpm db:generate  # Generate migration from schema
pnpm db:migrate   # Apply migration
```

### 2.3 Seed Script (2025 Enhanced)

`src/shared/database/seed.ts`:

- Generate initial RSA signing key pair
- Create test users with different MFA setups:
  - user1: password + TOTP enabled
  - user2: password + WebAuthn registered
  - user3: passwordless (WebAuthn only)
- Create OAuth clients:
  - Web app (confidential, backend)
  - SPA (public, PKCE required)
  - Mobile app (public, PKCE + DPoP)
  - First-party admin app (skip consent)
- Create test organization
- Generate sample audit logs

---

## Phase 3: Core Security Services

### 3.1 Crypto Service (Argon2id)

`src/shared/utils/crypto.ts`:

```typescript
import { hash, verify } from '@node-rs/argon2';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

export class CryptoService {
  // Argon2id - 2025 standard
  async hashPassword(password: string): Promise<string> {
    return hash(password, {
      memoryCost: 65536, // 64 MB
      timeCost: 3,
      parallelism: 4,
      outputLen: 32,
    });
  }

  async verifyPassword(hash: string, password: string): Promise<boolean> {
    return verify(hash, password);
  }

  // Backward compat for bcrypt migration
  async verifyLegacyBcrypt(hash: string, password: string): Promise<boolean> {
    // Use bcrypt.compare() for old hashes
  }

  // Token generation
  generateSecureToken(bytes: number = 32): string {
    return randomBytes(bytes).toString('base64url');
  }

  // AES-256-GCM encryption for private keys
  async encryptPrivateKey(privateKey: string, secret: string): Promise<string> {
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(secret, 'base64'), iv);
    // ... implementation
  }

  async decryptPrivateKey(encrypted: string, secret: string): Promise<string> {
    // ... implementation
  }

  // SHA-256 for refresh tokens
  hashRefreshToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
}
```

### 3.2 Logger Service (Pino)

`src/shared/utils/logger.ts`:

```typescript
import pino from 'pino';

export const logger = pino({
  level: config.log_level,
  transport:
    config.node_env === 'development'
      ? {
          target: 'pino-pretty',
          options: { colorize: true },
        }
      : undefined,
  redact: ['req.headers.authorization', 'password', 'client_secret'],
  serializers: {
    req: pino.stdSerializers.req,
    res: pino.stdSerializers.res,
    err: pino.stdSerializers.err,
  },
});
```

### 3.3 PKCE Service (Enhanced)

`src/modules/oauth/services/pkce.service.ts`:

- Validate code_challenge_method (only S256 allowed in 2025)
- Verify code_verifier against challenge
- Generate challenge for testing

### 3.4 Key Management Service (Database + KMS Ready)

`src/modules/key-management/services/key-management.service.ts`:

```typescript
export interface KeyManagementService {
  initialize(): Promise<void>;
  getPrimarySigningKey(): Promise<SigningKey>;
  getPublicKeys(): Promise<PublicKey[]>; // For JWKS endpoint
  verifyToken(token: string): Promise<JWTPayload>;
  rotateKeys(): Promise<void>;
  generateKeyPair(algorithm: 'RS256' | 'ES256'): Promise<KeyPair>;
  checkRotationSchedule(): Promise<void>;

  // KMS abstraction (Phase 12)
  migrateToKMS(provider: 'aws' | 'azure' | 'gcp'): Promise<void>;
}
```

Features:

- In-memory cache with periodic refresh
- Support multiple active keys (for rotation overlap)
- Automatic rotation check on startup
- Background job for scheduled rotation
- Export public keys in JWK format for JWKS endpoint

### 3.5 Token Service (JWT with kid)

`src/modules/oauth/services/token.service.ts`:

```typescript
export class TokenService {
  async generateAccessToken(payload: AccessTokenPayload): Promise<string> {
    const key = await this.keyManager.getPrimarySigningKey();

    return new jose.SignJWT(payload)
      .setProtectedHeader({
        alg: 'RS256',
        kid: key.keyId, // Critical for key rotation
        typ: 'at+jwt', // RFC 9068
      })
      .setIssuedAt()
      .setIssuer(config.issuer_url)
      .setAudience(payload.aud)
      .setExpirationTime('15m')
      .setJti(generateJti()) // For revocation tracking
      .sign(key.privateKey);
  }

  async generateIdToken(payload: IdTokenPayload): Promise<string> {
    // OIDC ID Token with nonce, amr, acr claims
  }

  async verifyToken(token: string): Promise<JWTPayload> {
    // Auto-select key based on kid header
    const keys = await this.keyManager.getPublicKeys();
    // Use jose.jwtVerify with JWKS
  }
}
```

---

## Phase 4: Multi-Factor Authentication (2FA/MFA)

### 4.1 TOTP Service (Authenticator Apps)

`src/modules/mfa/services/totp.service.ts`:

```typescript
import { TOTP } from 'otpauth';
import QRCode from 'qrcode';

export class TOTPService {
  async generateSecret(
    userId: string,
    email: string
  ): Promise<{
    secret: string;
    qrCode: string; // data URL
    backupCodes: string[];
  }> {
    const totp = new TOTP({
      issuer: config.totp_issuer,
      label: email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
    });

    const qrCode = await QRCode.toDataURL(totp.toString());
    const backupCodes = this.generateBackupCodes(10);

    return { secret: totp.secret.base32, qrCode, backupCodes };
  }

  async verifyToken(secret: string, token: string): Promise<boolean> {
    const totp = new TOTP({ secret });
    const delta = totp.validate({ token, window: 1 });
    return delta !== null;
  }

  private generateBackupCodes(count: number): string[] {
    // Generate 10 one-time use codes
    return Array.from({ length: count }, () => randomBytes(4).toString('hex').toUpperCase());
  }
}
```

### 4.2 WebAuthn/Passkey Service

`src/modules/mfa/services/webauthn.service.ts`:

```typescript
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

export class WebAuthnService {
  async generateRegistrationOptions(userId: string, email: string) {
    return generateRegistrationOptions({
      rpName: config.webauthn_rp_name,
      rpID: config.webauthn_rp_id,
      userID: userId,
      userName: email,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred', // Enable passkeys
        userVerification: 'preferred',
      },
      supportedAlgorithmIDs: [-7, -257], // ES256, RS256
    });
  }

  async verifyRegistration(userId: string, response: any) {
    // Verify and store credential
  }

  async generateAuthenticationOptions(userId: string) {
    const credentials = await db.query.webauthnCredentials.findMany({
      where: eq(schema.webauthnCredentials.userId, userId),
    });

    return generateAuthenticationOptions({
      rpID: config.webauthn_rp_id,
      allowCredentials: credentials.map((c) => ({
        id: c.credentialId,
        type: 'public-key',
        transports: c.transports,
      })),
    });
  }

  async verifyAuthentication(credentialId: string, response: any) {
    // Verify assertion and update counter
  }
}
```

### 4.3 SMS OTP Service (Optional)

`src/modules/mfa/services/sms-otp.service.ts`:

- Integration with Twilio or AWS SNS
- Generate 6-digit OTP
- Rate limiting (3 SMS per hour per phone)
- Verify OTP with expiry (5 minutes)

### 4.4 MFA Middleware

`src/shared/middleware/mfa.middleware.ts`:

```typescript
export const requireMFA = async (req, res, next) => {
  const user = req.user;
  const session = req.session;

  if (!user.mfa_enabled) {
    return next(); // MFA not configured
  }

  if (session.mfa_verified && Date.now() < session.mfa_expires_at) {
    return next(); // Already verified in this session
  }

  // Redirect to MFA challenge
  session.mfa_required = true;
  session.mfa_return_to = req.originalUrl;
  return res.redirect('/mfa/challenge');
};
```

### 4.5 MFA Enrollment Flow

Routes in `src/modules/mfa/routes/index.ts`:

- `GET /mfa/enroll` - Choose MFA method
- `POST /mfa/enroll/totp` - Setup authenticator app
- `POST /mfa/enroll/webauthn` - Register passkey/security key
- `POST /mfa/enroll/sms` - Add phone number
- `GET /mfa/recovery-codes` - View/regenerate backup codes
- `POST /mfa/verify` - Verify MFA code during enrollment
- `DELETE /mfa/methods/:id` - Remove MFA method

### 4.6 MFA Challenge Flow

- `GET /mfa/challenge` - Show available MFA methods
- `POST /mfa/challenge/totp` - Verify TOTP code
- `POST /mfa/challenge/webauthn` - Verify WebAuthn assertion
- `POST /mfa/challenge/sms` - Request SMS OTP
- `POST /mfa/challenge/recovery` - Use backup code

---

## Phase 5: Social & Federated Login

### 5.1 OAuth Provider Integrations (Arctic)

`src/modules/federation/services/provider.service.ts`:

```typescript
import { Google, GitHub, Microsoft, Apple, Facebook } from 'arctic';

export class OAuthProviderService {
  private providers = {
    google: new Google(
      config.google_client_id,
      config.google_client_secret,
      config.google_redirect_uri
    ),
    github: new GitHub(config.github_client_id, config.github_client_secret),
    microsoft: new Microsoft(
      config.microsoft_client_id,
      config.microsoft_client_secret,
      config.microsoft_redirect_uri
    ),
    // ... Apple, Facebook, Discord, etc.
  };

  async getAuthorizationUrl(provider: string, state: string, scopes: string[]): Promise<string> {
    return this.providers[provider].createAuthorizationURL(state, scopes);
  }

  async exchangeCode(
    provider: string,
    code: string
  ): Promise<{ accessToken: string; refreshToken?: string }> {
    return this.providers[provider].validateAuthorizationCode(code);
  }

  async getUserProfile(provider: string, accessToken: string): Promise<FederatedProfile> {
    // Provider-specific API calls to get user profile
  }
}
```

### 5.2 Account Linking Service

`src/modules/federation/services/account-linking.service.ts`:

```typescript
export class AccountLinkingService {
  async linkProvider(
    userId: string,
    provider: string,
    providerUserId: string,
    profile: FederatedProfile
  ): Promise<void> {
    // Check if provider account already linked to different user
    const existing = await db.query.federatedIdentities.findFirst({
      where: and(
        eq(schema.federatedIdentities.provider, provider),
        eq(schema.federatedIdentities.providerUserId, providerUserId)
      ),
    });

    if (existing && existing.userId !== userId) {
      throw new Error('Provider account already linked to another user');
    }

    // Create or update federated identity
    await db
      .insert(schema.federatedIdentities)
      .values({
        userId,
        provider,
        providerUserId,
        providerEmail: profile.email,
        providerData: profile,
      })
      .onConflictDoUpdate({
        target: [schema.federatedIdentities.provider, schema.federatedIdentities.providerUserId],
        set: { providerData: profile, updatedAt: new Date() },
      });
  }

  async unlinkProvider(userId: string, provider: string): Promise<void> {
    // Ensure user has another login method before unlinking
    const user = await this.userService.getUser(userId);
    const identities = await this.getUserProviders(userId);

    if (!user.password_hash && identities.length === 1) {
      throw new Error('Cannot unlink last login method');
    }

    await db
      .delete(schema.federatedIdentities)
      .where(
        and(
          eq(schema.federatedIdentities.userId, userId),
          eq(schema.federatedIdentities.provider, provider)
        )
      );
  }

  async getUserProviders(userId: string): Promise<FederatedIdentity[]> {
    return db.query.federatedIdentities.findMany({
      where: eq(schema.federatedIdentities.userId, userId),
    });
  }
}
```

### 5.3 Social Login Routes

`src/modules/federation/routes/index.ts`:

```typescript
// Initiate OAuth flow
router.get('/auth/:provider', async (req, res) => {
  const { provider } = req.params;
  const state = generateState();
  const codeVerifier = generateCodeVerifier(); // PKCE for OAuth

  req.session.oauth_state = state;
  req.session.oauth_code_verifier = codeVerifier;

  const url = await providerService.getAuthorizationUrl(provider, state, [
    'openid',
    'profile',
    'email',
  ]);

  res.redirect(url);
});

// OAuth callback
router.get('/auth/:provider/callback', async (req, res) => {
  const { provider } = req.params;
  const { code, state } = req.query;

  // Verify state
  if (state !== req.session.oauth_state) {
    throw new Error('Invalid state');
  }

  // Exchange code for tokens
  const tokens = await providerService.exchangeCode(provider, code);
  const profile = await providerService.getUserProfile(provider, tokens.accessToken);

  // Find or create user
  let user = await userService.findByProviderIdentity(provider, profile.id);

  if (!user) {
    // Check if email exists (account linking opportunity)
    user = await userService.findByEmail(profile.email);

    if (user) {
      // Email exists - link provider
      await accountLinkingService.linkProvider(user.id, provider, profile.id, profile);
    } else {
      // Create new user (JIT provisioning)
      user = await userService.createFromProvider(provider, profile);
    }
  }

  // Create session
  req.session.userId = user.id;
  req.session.mfa_verified = true; // Trust provider MFA

  // If OAuth flow, continue authorization
  if (req.session.oauth_client_id) {
    return res.redirect('/oauth/authorize');
  }

  res.redirect('/dashboard');
});

// Link provider to existing account
router.post('/account/link/:provider', authenticate, async (req, res) => {
  // Same OAuth flow but links to req.user instead of creating new
});

// Unlink provider
router.delete('/account/link/:provider', authenticate, async (req, res) => {
  await accountLinkingService.unlinkProvider(req.user.id, req.params.provider);
  res.json({ success: true });
});
```

### 5.4 SAML 2.0 Support (Enterprise SSO)

`src/modules/federation/services/saml.service.ts`:

- Parse SAML metadata from enterprise IdP (Okta, Azure AD, etc.)
- Handle SAML assertion validation
- Map SAML attributes to user profile
- Support IdP-initiated and SP-initiated flows

Routes:

- `GET /saml/metadata` - SP metadata
- `POST /saml/acs` - Assertion Consumer Service
- `GET /auth/saml/:orgSlug` - Initiate SAML auth for organization

---

## Phase 6: Passwordless Authentication

### 6.1 Magic Link Service

`src/modules/auth/services/magic-link.service.ts`:

```typescript
export class MagicLinkService {
  async sendMagicLink(email: string): Promise<void> {
    const token = generateSecureToken(32);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 min

    await db.insert(schema.magicLinks).values({
      token,
      email,
      expiresAt,
      ipAddress: req.ip,
    });

    const link = `${config.issuer_url}/auth/magic-link/verify?token=${token}`;

    await emailService.send({
      to: email,
      subject: 'Sign in to IdentityServer',
      template: 'magic-link',
      data: { link, expiresIn: '15 minutes' },
    });
  }

  async verifyMagicLink(token: string): Promise<User> {
    const magicLink = await db.query.magicLinks.findFirst({
      where: and(
        eq(schema.magicLinks.token, token),
        isNull(schema.magicLinks.usedAt),
        gt(schema.magicLinks.expiresAt, new Date())
      ),
    });

    if (!magicLink) {
      throw new Error('Invalid or expired magic link');
    }

    // Mark as used
    await db
      .update(schema.magicLinks)
      .set({ usedAt: new Date() })
      .where(eq(schema.magicLinks.id, magicLink.id));

    // Find or create user
    let user = await userService.findByEmail(magicLink.email);
    if (!user) {
      user = await userService.create({
        email: magicLink.email,
        emailVerified: true,
      });
    }

    return user;
  }
}
```

Routes:

- `POST /auth/magic-link` - Request magic link
- `GET /auth/magic-link/verify` - Verify and login

### 6.2 Passkey-Only Authentication

Allow users to register/login with passkeys only (no password):

- WebAuthn registration flow without password
- Discoverable credentials (resident keys)
- Platform authenticators preferred (Touch ID, Face ID, Windows Hello)

---

## Phase 7: Enhanced OAuth 2.0 Endpoints

### 7.1 Authorization Endpoint (Enhanced)

`GET /oauth/authorize`:

- Validate client_id, redirect_uri, response_type
- **PKCE mandatory** for public clients
- Check authentication state:
  - Not authenticated → redirect to login with `?return_to=`
  - Authenticated but MFA required → redirect to MFA challenge
  - Authenticated → proceed to consent
- Check consent (skip for first-party clients)
- Generate authorization code with MFA claims (acr, amr)
- Support PAR (Pushed Authorization Requests) if enabled

### 7.2 Token Endpoint (Enhanced)

`POST /oauth/token`:

**Grant Types:**

1. `authorization_code` - Exchange code + PKCE verifier
2. `refresh_token` - Rotate refresh token
3. `client_credentials` - Machine-to-machine
4. `urn:ietf:params:oauth:grant-type:device_code` - Device flow (RFC 8628)

**Response (with MFA claims):**

```json
{
  "access_token": "eyJhbG...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "rt_abc123...",
  "id_token": "eyJhbG...",
  "scope": "openid profile email",
  "mfa_authenticated": true
}
```

ID Token claims include:

```json
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "email_verified": true,
  "amr": ["pwd", "totp"], // Authentication methods
  "acr": "2", // Level 2 = MFA
  "auth_time": 1735689600
}
```

### 7.3 Device Authorization Flow (RFC 8628)

For TVs, IoT devices, CLI tools:

`POST /oauth/device`:

```json
{
  "client_id": "cli-app"
}
```

Response:

```json
{
  "device_code": "GmRh...JHk",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://identity.example.com/device",
  "verification_uri_complete": "https://identity.example.com/device?user_code=WDJB-MJHT",
  "expires_in": 900,
  "interval": 5
}
```

User visits `verification_uri`, enters `user_code`, and approves.

Device polls `POST /oauth/token` with `device_code` grant.

### 7.4 Pushed Authorization Requests (PAR - RFC 9126)

For high-security clients:

`POST /oauth/par`:

```json
{
  "client_id": "confidential-app",
  "client_secret": "secret",
  "response_type": "code",
  "redirect_uri": "https://app.example.com/callback",
  "scope": "openid profile",
  "code_challenge": "...",
  "code_challenge_method": "S256"
}
```

Response:

```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:abcd1234",
  "expires_in": 90
}
```

Then use in authorization:

```
GET /oauth/authorize?client_id=...&request_uri=urn:ietf:params:oauth:request_uri:abcd1234
```

### 7.5 Token Revocation & Introspection

`POST /oauth/revoke`:

- Revoke access or refresh tokens
- Cascade revoke entire refresh token chain

`POST /oauth/introspect`:

- Check token validity
- Return MFA claims (acr, amr)

---

## Phase 8: Enhanced OIDC Endpoints

### 8.1 Discovery Document (Enhanced)

`GET /.well-known/openid-configuration`:

```json
{
  "issuer": "https://identity.example.com",
  "authorization_endpoint": "https://identity.example.com/oauth/authorize",
  "token_endpoint": "https://identity.example.com/oauth/token",
  "userinfo_endpoint": "https://identity.example.com/oauth/userinfo",
  "jwks_uri": "https://identity.example.com/.well-known/jwks.json",
  "device_authorization_endpoint": "https://identity.example.com/oauth/device",
  "revocation_endpoint": "https://identity.example.com/oauth/revoke",
  "introspection_endpoint": "https://identity.example.com/oauth/introspect",

  "response_types_supported": ["code"],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "ES256"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "claims_supported": [
    "sub",
    "email",
    "email_verified",
    "name",
    "given_name",
    "family_name",
    "picture",
    "locale",
    "amr",
    "acr"
  ],
  "acr_values_supported": ["0", "1", "2"], // 0=none, 1=pwd, 2=mfa
  "code_challenge_methods_supported": ["S256"],

  "dpop_signing_alg_values_supported": ["RS256", "ES256"],
  "pushed_authorization_request_endpoint": "https://identity.example.com/oauth/par"
}
```

### 8.2 JWKS Endpoint (Multi-key)

`GET /.well-known/jwks.json`:

```json
{
  "keys": [
    {
      "kid": "2025-01-v1",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    },
    {
      "kid": "2024-10-v1",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### 8.3 UserInfo Endpoint (Enhanced)

`GET /oauth/userinfo`:

```json
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "picture": "https://...",
  "locale": "en-US",
  "updated_at": 1735689600,

  "amr": ["pwd", "totp"],
  "acr": "2",

  "identities": [
    { "provider": "google", "email": "john@gmail.com" },
    { "provider": "github", "username": "johndoe" }
  ]
}
```

---

## Phase 9: Modern UI/UX

### 9.1 Login Page (Multi-option)

`src/modules/auth/views/login.ejs`:

- Email/password form
- Social login buttons (Google, GitHub, Microsoft, Apple)
- "Continue with passkey" button (WebAuthn)
- "Send magic link" option
- "Don't have an account? Sign up"
- Remember device checkbox
- Modern, responsive design (Tailwind CSS)

### 9.2 MFA Challenge Page

`src/modules/mfa/views/challenge.ejs`:

- Tabs for different MFA methods (TOTP, WebAuthn, SMS)
- "Trust this device for 30 days" checkbox
- Link to use recovery code
- QR code for mobile auth apps

### 9.3 Account Settings

`src/modules/user/views/settings.ejs`:

- Profile management
- Connected accounts (social logins)
- Security settings:
  - Change password
  - Enable/disable MFA methods
  - Manage passkeys
  - Active sessions
  - Recovery codes
- Privacy settings
- Delete account

### 9.4 Admin Dashboard

`src/modules/admin/views/`:

- OAuth client management
- User management (search, view, disable)
- Organization management
- Audit logs viewer
- Metrics dashboard
- Key rotation status

---

## Phase 10: Rate Limiting & Anti-Abuse

### 10.1 Multi-layer Rate Limiting

`src/shared/middleware/rate-limit.ts`:

```typescript
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';

export const createRateLimiter = (options: {
  windowMs: number;
  max: number;
  keyGenerator?: (req) => string;
}) => {
  return rateLimit({
    store: new RedisStore({ client: redis }),
    windowMs: options.windowMs,
    max: options.max,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: options.keyGenerator || ((req) => req.ip),
    handler: (req, res) => {
      logger.warn({ ip: req.ip, path: req.path }, 'Rate limit exceeded');
      res.status(429).json({ error: 'too_many_requests' });
    },
  });
};

// Per-endpoint limits
export const tokenEndpointLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
});

export const authEndpointLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 20,
});

export const registrationLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
});

export const mfaVerifyLimiter = createRateLimiter({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5,
  keyGenerator: (req) => `${req.ip}:${req.user?.id}`,
});
```

### 10.2 Account Lockout

`src/modules/auth/services/lockout.service.ts`:

- Track failed login attempts (in Redis)
- Lock account after 5 failed attempts
- Exponential backoff (1 min → 5 min → 15 min → 1 hour)
- Email notification on lockout
- Admin unlock capability

### 10.3 Anomaly Detection

- Detect login from new IP/location
- Flag suspicious device changes
- Email verification for risky actions
- Optional: IP geolocation check

---

## Phase 11: Background Jobs (BullMQ)

### 11.1 Job Queue Setup

`src/shared/queue/index.ts`:

```typescript
import { Queue, Worker } from 'bullmq';

export const emailQueue = new Queue('email', { connection: redis });
export const keyRotationQueue = new Queue('key-rotation', { connection: redis });
export const cleanupQueue = new Queue('cleanup', { connection: redis });

// Workers
new Worker(
  'email',
  async (job) => {
    await emailService.send(job.data);
  },
  { connection: redis }
);

new Worker(
  'key-rotation',
  async (job) => {
    await keyManagementService.rotateKeys();
  },
  { connection: redis }
);

new Worker(
  'cleanup',
  async (job) => {
    await cleanupService.run();
  },
  { connection: redis }
);
```

### 11.2 Scheduled Jobs

- Key rotation check (daily)
- Cleanup expired codes/tokens (hourly)
- Session cleanup (every 6 hours)
- Audit log retention (weekly)
- Send metrics to monitoring (every 5 min)

---

## Phase 12: Monitoring & Observability

### 12.1 Prometheus Metrics

`src/shared/monitoring/metrics.ts`:

```typescript
import client from 'prom-client';

export const register = new client.Registry();

// Default metrics (CPU, memory, etc.)
client.collectDefaultMetrics({ register });

// Custom metrics
export const tokenIssuedCounter = new client.Counter({
  name: 'idp_tokens_issued_total',
  help: 'Total number of tokens issued',
  labelNames: ['grant_type', 'client_id'],
});

export const loginAttempts = new client.Counter({
  name: 'idp_login_attempts_total',
  help: 'Login attempts',
  labelNames: ['method', 'status'], // method: password|totp|webauthn, status: success|failure
});

export const mfaEnrollments = new client.Gauge({
  name: 'idp_mfa_enrollments',
  help: 'Users with MFA enabled',
  labelNames: ['method'],
});

export const tokenVerifyDuration = new client.Histogram({
  name: 'idp_token_verify_duration_seconds',
  help: 'Token verification duration',
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
});

register.registerMetric(tokenIssuedCounter);
register.registerMetric(loginAttempts);
register.registerMetric(mfaEnrollments);
register.registerMetric(tokenVerifyDuration);
```

Metrics endpoint:

```typescript
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});
```

### 12.2 OpenTelemetry Tracing

`src/shared/monitoring/tracing.ts`:

- Instrument Express with OTEL
- Trace OAuth flows end-to-end
- Export to Jaeger/Zipkin
- Custom spans for key operations

### 12.3 Audit Logging

Log all security-relevant events:

- User registration/login/logout
- MFA enrollment/removal
- Password changes
- Token issuance/revocation
- Client creation/modification
- Admin actions
- Failed auth attempts
- Account lockouts

Query interface for audit logs in admin panel.

---

## Phase 13: Testing Strategy

### 13.1 Unit Tests

- All services (TokenService, OAuthService, MFA services)
- Crypto utilities
- Validation schemas
- Middleware

### 13.2 Integration Tests

- OAuth flows (authorization code, refresh token, client credentials)
- OIDC discovery and userinfo
- MFA enrollment and challenge
- Social login flows
- Key rotation scenarios

### 13.3 E2E Tests

- Full user journey (register → login → consent → get tokens)
- MFA flows (TOTP, WebAuthn)
- Passwordless flows (magic link, passkey)
- Social login integration
- Admin workflows

### 13.4 Security Tests

- PKCE bypass attempts
- Token replay attacks
- CSRF protection
- Rate limit enforcement
- SQL injection (Drizzle protects but verify)
- XSS attempts

Tools: Vitest, Playwright, OWASP ZAP

---

## Phase 14: Deployment & DevOps

### 14.1 Docker Setup

`Dockerfile`:

```dockerfile
FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable pnpm && pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM node:22-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
USER node
EXPOSE 3000
CMD ["node", "dist/server.js"]
```

`docker-compose.yml`:

```yaml
version: '3.9'
services:
  app:
    build: .
    ports:
      - '3000:3000'
    environment:
      - DATABASE_URL=postgresql://postgres:postgres@postgres:5432/identity_db
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: identity_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - '9090:9090'

  grafana:
    image: grafana/grafana:latest
    ports:
      - '3001:3000'
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  postgres_data:
  redis_data:
  grafana_data:
```

### 14.2 CI/CD Pipeline

GitHub Actions workflow:

- Run tests on PR
- Build Docker image
- Security scan (Snyk, Trivy)
- Deploy to staging
- Run E2E tests
- Deploy to production (manual approval)

### 14.3 Production Checklist

- [ ] HTTPS only (reverse proxy with Let's Encrypt)
- [ ] Environment secrets in vault (not .env files)
- [ ] Database backups (automated daily)
- [ ] Redis persistence (AOF + RDB)
- [ ] Log aggregation (ELK stack or cloud service)
- [ ] Monitoring alerts (PagerDuty, Opsgenie)
- [ ] CDN for static assets
- [ ] DDoS protection (Cloudflare)
- [ ] Regular security audits
- [ ] Disaster recovery plan

---

## Security Compliance Checklist (2025 Standards)

- [x] **Argon2id** password hashing (OWASP #1 recommendation)
- [x] **PKCE mandatory** for all public clients
- [x] **Refresh token rotation** with revocation on reuse detection
- [x] **MFA support** (TOTP, WebAuthn/FIDO2, SMS backup)
- [x] **Passwordless options** (magic links, passkeys)
- [x] **Social login** with secure account linking
- [x] **Rate limiting** (per IP, per user, per endpoint)
- [x] **Account lockout** on brute force attempts
- [x] **Session fixation** protection
- [x] **CSRF protection** on all state-changing operations
- [x] **XSS protection** (CSP headers, input sanitization)
- [x] **SQL injection** protection (Drizzle parameterized queries)
- [x] **Key rotation** without downtime (multi-key JWKS)
- [x] **Private key encryption** at rest (AES-256-GCM)
- [x] **JWT kid header** for key versioning
- [x] **JWT jti claim** for token revocation tracking
- [x] **Audit logging** for all security events
- [x] **Structured logging** with sensitive data redaction
- [x] **Monitoring & alerting** (Prometheus, OpenTelemetry)
- [x] **HTTPS enforcement** in production
- [x] **Secure cookies** (httpOnly, secure, sameSite)
- [x] **CORS** with per-client origin whitelist
- [x] **Helmet.js** security headers
- [x] **Content Security Policy** (CSP)
- [x] **Subresource Integrity** (SRI) for CDN assets
- [x] **DPoP support** for public client token binding (optional)
- [x] **PAR support** for high-security flows (optional)
- [x] **Soft delete** for users/clients (audit trail)
- [x] **GDPR compliance** considerations (data export/deletion)

---

## Standards Compliance

### OAuth 2.0 & Extensions

- **RFC 6749** - OAuth 2.0 Authorization Framework
- **RFC 7636** - PKCE for OAuth Public Clients
- **RFC 7009** - Token Revocation
- **RFC 7662** - Token Introspection
- **RFC 8252** - OAuth 2.0 for Native Apps
- **RFC 8628** - OAuth 2.0 Device Authorization Grant
- **RFC 9068** - JWT Profile for Access Tokens
- **RFC 9126** - Pushed Authorization Requests (PAR)
- **RFC 9449** - DPoP (Demonstrating Proof-of-Possession)

### OpenID Connect

- **OpenID Connect Core 1.0**
- **OpenID Connect Discovery 1.0**
- **OpenID Connect Session Management 1.0**

### Authentication Standards

- **FIDO2 / WebAuthn** - W3C Web Authentication
- **TOTP (RFC 6238)** - Time-Based One-Time Password
- **SAML 2.0** - Enterprise SSO

### Security Best Practices

- **OWASP Top 10** (2025)
- **NIST SP 800-63B** - Digital Identity Guidelines
- **CWE Top 25** - Common Weakness Enumeration

---

## Implementation Roadmap

### Sprint 1-2: Foundation (2 weeks)

- [x] Project setup, dependencies, TypeScript config
- [x] Database schema design & migrations
- [x] Core crypto utilities (Argon2id, AES encryption)
- [x] Configuration loader with validation
- [x] Logger setup (Pino)

### Sprint 3-4: Authentication Core (2 weeks)

- [ ] User registration & login (password-based)
- [ ] Session management (Redis)
- [ ] Password reset flow
- [ ] Email verification
- [ ] Basic UI (login, register pages)

### Sprint 5-6: OAuth 2.0 Core (2 weeks)

- [ ] Key management service (database storage)
- [ ] Token service (JWT with RS256)
- [ ] OAuth authorization endpoint
- [ ] OAuth token endpoint (authorization_code, refresh_token)
- [ ] PKCE implementation

### Sprint 7-8: OIDC (2 weeks)

- [ ] ID token generation
- [ ] OIDC discovery document
- [ ] JWKS endpoint (multi-key support)
- [ ] UserInfo endpoint
- [ ] Consent screen

### Sprint 9-10: Multi-Factor Authentication (2 weeks)

- [ ] TOTP service (authenticator apps)
- [ ] WebAuthn/Passkey service
- [ ] SMS OTP (Twilio integration)
- [ ] Recovery codes
- [ ] MFA enrollment UI
- [ ] MFA challenge UI
- [ ] MFA enforcement in auth flow

### Sprint 11-12: Social & Federated Login (2 weeks)

- [ ] OAuth provider service (Arctic integration)
- [ ] Google login
- [ ] GitHub login
- [ ] Microsoft login
- [ ] Apple Sign In
- [ ] Account linking service
- [ ] Social login UI

### Sprint 13-14: Passwordless (2 weeks)

- [ ] Magic link service
- [ ] WebAuthn-only registration
- [ ] Passkey support (resident keys)
- [ ] Device flow (RFC 8628)
- [ ] Passwordless UI

### Sprint 15-16: Client & Admin Management (2 weeks)

- [ ] Client CRUD endpoints
- [ ] Client secret regeneration
- [ ] Organization management (if multi-tenant)
- [ ] Key rotation admin panel
- [ ] Admin dashboard UI

### Sprint 17-18: Advanced Features (2 weeks)

- [ ] Pushed Authorization Requests (PAR)
- [ ] DPoP support
- [ ] SAML 2.0 integration
- [ ] Rate limiting (all endpoints)
- [ ] Account lockout logic
- [ ] Audit logging

### Sprint 19-20: Monitoring & DevOps (2 weeks)

- [ ] Prometheus metrics
- [ ] OpenTelemetry tracing
- [ ] Background jobs (BullMQ)
- [ ] Docker setup
- [ ] CI/CD pipeline
- [ ] Grafana dashboards

### Sprint 21-22: Testing & Hardening (2 weeks)

- [ ] Unit tests (80%+ coverage)
- [ ] Integration tests (OAuth flows, MFA)
- [ ] E2E tests (Playwright)
- [ ] Security tests (OWASP ZAP)
- [ ] Performance testing (load tests)
- [ ] Security audit

### Sprint 23-24: Documentation & Launch Prep (2 weeks)

- [ ] API documentation (OpenAPI/Swagger)
- [ ] Integration guides for clients
- [ ] Admin documentation
- [ ] Deployment guide
- [ ] Security best practices guide
- [ ] Migration guides (from other providers)
- [ ] Production readiness review

**Total: ~6 months for full implementation**

---

## 2025 Industry Standards Review

### ✅ What's Industry Standard in 2025

1. **Argon2id** over bcrypt for password hashing
2. **Passwordless authentication** (WebAuthn/passkeys, magic links)
3. **PKCE mandatory** for all authorization code flows
4. **MFA as core feature**, not optional
5. **Social login integration** (not just username/password)
6. **JWT with RS256** (ES256 also acceptable)
7. **Structured JSON logging** (not plaintext logs)
8. **Observability tracing** (OpenTelemetry)
9. **Metrics-driven monitoring** (Prometheus, Grafana)
10. **Rate limiting** at multiple layers
11. **Background job processing** (not synchronous email/cleanup)
12. **Refresh token rotation** with security guarantees
13. **Audit logging** for compliance
14. **Container-first deployment** (Docker, K8s)
15. **CI/CD pipelines** with automated security scanning
16. **Multi-key JWKS** for zero-downtime rotation
17. **Device authorization flow** for IoT/CLI apps
18. **Account linking** for federated identities
19. **Privacy-conscious** (GDPR, data minimization)
20. **Soft deletes** for audit trail preservation

### ❌ What's Outdated in Your Original Plan

1. ~~bcrypt~~ → Use Argon2id
2. No MFA/2FA mentioned → Core requirement now
3. No social login → Expected in 2025
4. No passwordless options → Users expect this
5. No structured logging → JSON logs with tracing
6. No monitoring/metrics → Observability is critical
7. No background jobs → Email/cleanup should be async
8. No device flow → Needed for modern IoT/CLI
9. Limited rate limiting → Need multi-layer approach
10. No account linking → Essential for social login

### 🚀 Advanced Features for 2025

- **Passkeys** (FIDO2 resident keys with sync)
- **DPoP** for public client security
- **PAR** for high-security flows
- **Device authorization grant** for TVs/IoT
- **OpenTelemetry** distributed tracing
- **Prometheus** metrics with Grafana dashboards
- **BullMQ** for background processing
- **Arctic** for modern OAuth provider integration
- **SAML 2.0** for enterprise customers
- **Account recovery** (backup codes, trusted contacts)

---

## Summary

This plan brings your identity server to **2025 industry standards** by:

1. **Upgrading security** (Argon2id, enhanced PKCE, token binding)
2. **Adding MFA/2FA** as a core feature (TOTP, WebAuthn, SMS)
3. **Integrating social login** (Google, GitHub, Microsoft, Apple)
4. **Enabling passwordless** (magic links, passkeys)
5. **Implementing observability** (structured logging, metrics, tracing)
6. **Modern DevOps** (Docker, CI/CD, monitoring)
7. **Compliance readiness** (GDPR, audit logs, security standards)

The implementation is broken into **24 sprints (~6 months)** with clear deliverables.

You now have an **enterprise-grade, production-ready** identity server that competes with Auth0, Okta, and Keycloak while being self-hosted and fully customizable.
