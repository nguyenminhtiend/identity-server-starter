# Database Schema - OAuth 2.0 + OIDC Identity Server

## Entity Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RELATIONAL SCHEMA                                  │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────┐
│      organizations       │
│─────────────────────────│
│ PK  id (uuid)           │
│     name (text)          │
│ UK  slug (text)          │
│ FK  owner_user_id (uuid) │───┐
│     is_active (boolean)  │   │
│     created_at (ts)      │   │
│     updated_at (ts)      │   │
└──────────────────────────┘   │
         ▲                      │
         │                      │
         │                      │
         │ 1:N                  │
         │                      │
┌────────┴──────────────────────┴─────┐
│            users                     │
│──────────────────────────────────────│
│ PK  id (uuid)                        │
│ UK  email (text)                     │
│     password_hash (text)             │
│     email_verified (boolean)         │
│     created_at (timestamp)           │
│     updated_at (timestamp)           │
└──────────────────────────────────────┘
         ▲                      ▲
         │                      │
         │ 1:N                  │ 1:N
         │                      │
         │              ┌───────┴──────────────────────┐
         │              │      consents                │
         │              │──────────────────────────────│
         │              │ PK  id (uuid)                │
         │              │ FK  user_id (uuid)           │
         │              │ FK  client_id (uuid)         │───┐
         │              │     scope (text)             │   │
         │              │     granted_at (timestamp)   │   │
         │              │ UNQ (user_id, client_id)     │   │
         │              └──────────────────────────────┘   │
         │                                                  │
         │                                                  │
         │              ┌───────────────────────────────┐  │
         │              │   authorization_codes         │  │
         │              │───────────────────────────────│  │
         │              │ PK  id (uuid)                 │  │
         │              │ UK  code (text)               │  │
         │              │ FK  client_id (uuid)          │──┤
         │              │ FK  user_id (uuid)            │──┘
         │              │     redirect_uri (text)       │
         │              │     scope (text)              │
         │              │     code_challenge (text)     │
         │              │     code_challenge_method     │
         │              │     expires_at (timestamp)    │
         │              │     used_at (timestamp, null) │
         │              │ IDX (code, expires_at)        │
         │              └───────────────────────────────┘
         │                                 ▲
         │                                 │
         │                                 │
         │              ┌──────────────────┴────────────┐
         │              │     refresh_tokens            │
         │              │───────────────────────────────│
         │              │ PK  id (uuid)                 │
         │              │ UK  token_hash (text)         │
         │              │ FK  client_id (uuid)          │──┐
         │              │ FK  user_id (uuid)            │──┘
         │              │     scope (text)              │
         │              │     expires_at (timestamp)    │
         │              │     revoked (boolean)         │
         │              │     previous_token_hash (text)│
         │              │     created_at (timestamp)    │
         │              │ IDX (token_hash, revoked)     │
         │              └───────────────────────────────┘
         │
         │
         │
         │              ┌───────────────────────────────────────────────┐
         └──────────────│              clients                          │
                        │───────────────────────────────────────────────│
                        │ PK  id (uuid)                                 │
                        │ UK  client_id (text)                          │
                        │     client_secret_hash (text, nullable)       │
                        │     name (text)                               │
                        │     client_type (enum: confidential|public)   │
                        │ FK  organization_id (uuid, nullable)          │──┐
                        │     redirect_uris (jsonb array)               │  │
                        │     grant_types (jsonb array)                 │  │
                        │     allowed_scopes (text)                     │  │
                        │     logo_url (text, nullable)                 │  │
                        │     allowed_cors_origins (jsonb array)        │  │
                        │     terms_url (text, nullable)                │  │
                        │     privacy_url (text, nullable)              │  │
                        │     homepage_url (text, nullable)             │  │
                        │     contacts (jsonb array)                    │  │
                        │     is_active (boolean)                       │  │
                        │     created_at (timestamp)                    │  │
                        │     updated_at (timestamp)                    │  │
                        │ IDX (organization_id, is_active)              │  │
                        │ IDX (client_type)                             │  │
                        └───────────────────────────────────────────────┘  │
                                                                            │
                                                                            │
                        ┌───────────────────────────────────────────────┐  │
                        │           signing_keys                        │  │
                        │───────────────────────────────────────────────│  │
                        │ PK  id (uuid)                                 │  │
                        │ UK  key_id (text, e.g., "2025-01-19-v1")     │  │
                        │     algorithm (text, default 'RS256')         │  │
                        │     public_key_pem (text)                     │  │
                        │     private_key_encrypted (text)              │  │
                        │     is_active (boolean)                       │  │
                        │     is_primary (boolean)                      │  │
                        │     created_at (timestamp)                    │  │
                        │     expires_at (timestamp, nullable)          │  │
                        │     rotated_at (timestamp, nullable)          │  │
                        │     next_rotation_at (timestamp, nullable)    │  │
                        │ IDX (is_active, is_primary)                   │  │
                        │ CHECK: Only one is_primary=true at a time     │  │
                        └───────────────────────────────────────────────┘  │
                                                                            │
                        ┌───────────────────────────────────────────────┐  │
                        │      organizations (repeated)                 │◄─┘
                        │───────────────────────────────────────────────│
                        │ (See above for full schema)                   │
                        └───────────────────────────────────────────────┘
```

## Detailed Table Specifications

### 1. **users**

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  email_verified BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
```

**Relationships:**

- 1:N → organizations (as owner)
- 1:N → authorization_codes
- 1:N → refresh_tokens
- 1:N → consents

---

### 2. **organizations** (Optional - for multi-tenant)

```sql
CREATE TABLE organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_organizations_slug ON organizations(slug);
CREATE INDEX idx_organizations_owner ON organizations(owner_user_id);
```

**Relationships:**

- N:1 → users (owner)
- 1:N → clients

**Business Rules:**

- Cannot delete organization if active clients exist
- Owner must be an active user
- Slug used for vanity URLs (e.g., `acme-corp`)

---

### 3. **clients**

```sql
CREATE TABLE clients (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id TEXT UNIQUE NOT NULL,
  client_secret_hash TEXT,  -- NULL for public clients
  name TEXT NOT NULL,
  client_type TEXT NOT NULL CHECK (client_type IN ('confidential', 'public')),
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  redirect_uris JSONB NOT NULL DEFAULT '[]',
  grant_types JSONB NOT NULL DEFAULT '["authorization_code"]',
  allowed_scopes TEXT NOT NULL DEFAULT 'openid profile email',
  logo_url TEXT,
  allowed_cors_origins JSONB DEFAULT '[]',
  terms_url TEXT,
  privacy_url TEXT,
  homepage_url TEXT,
  contacts JSONB DEFAULT '[]',
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),

  CONSTRAINT public_client_no_secret CHECK (
    (client_type = 'public' AND client_secret_hash IS NULL) OR
    (client_type = 'confidential' AND client_secret_hash IS NOT NULL)
  )
);

CREATE INDEX idx_clients_org ON clients(organization_id, is_active);
CREATE INDEX idx_clients_type ON clients(client_type);
CREATE INDEX idx_clients_client_id ON clients(client_id);
```

**Relationships:**

- N:1 → organizations (nullable for system-level clients)
- 1:N → authorization_codes
- 1:N → refresh_tokens
- 1:N → consents

**Business Rules:**

- Public clients MUST NOT have client_secret
- Confidential clients MUST have client_secret
- Public clients MUST use PKCE (enforced in application logic)
- redirect_uris must be valid URLs
- At least one redirect_uri required

**Client Types:**

- `confidential`: Backend apps (can keep secrets) - SaaS platforms, server-side apps
- `public`: SPAs, mobile apps (cannot keep secrets) - React/Vue apps, iOS/Android

---

### 4. **authorization_codes**

```sql
CREATE TABLE authorization_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code TEXT UNIQUE NOT NULL,
  client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  code_challenge TEXT,  -- PKCE challenge
  code_challenge_method TEXT CHECK (code_challenge_method IN ('S256', 'plain')),
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,  -- NULL = not used yet

  CONSTRAINT code_used_once CHECK (used_at IS NULL OR used_at <= NOW())
);

CREATE INDEX idx_authz_code ON authorization_codes(code, expires_at);
CREATE INDEX idx_authz_client ON authorization_codes(client_id);
CREATE INDEX idx_authz_user ON authorization_codes(user_id);
```

**Relationships:**

- N:1 → clients
- N:1 → users

**Business Rules:**

- Single-use only (checked via `used_at`)
- Short TTL (10 minutes default)
- Must match original redirect_uri on token exchange
- PKCE required for public clients (code_challenge must be present)
- Delete after successful exchange or expiry

---

### 5. **refresh_tokens**

```sql
CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash TEXT UNIQUE NOT NULL,  -- SHA256 hash of actual token
  client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  revoked BOOLEAN DEFAULT FALSE,
  previous_token_hash TEXT,  -- For rotation tracking
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_refresh_token ON refresh_tokens(token_hash, revoked);
CREATE INDEX idx_refresh_client ON refresh_tokens(client_id, revoked);
CREATE INDEX idx_refresh_user ON refresh_tokens(user_id, revoked);
CREATE INDEX idx_refresh_expires ON refresh_tokens(expires_at) WHERE NOT revoked;
```

**Relationships:**

- N:1 → clients
- N:1 → users

**Business Rules:**

- Token rotation: On use, create new token and revoke old one
- Long TTL (30 days default)
- Store only SHA256 hash, never plain text
- `previous_token_hash` tracks rotation chain (detect reuse attacks)
- Revoke all tokens when password changes

---

### 6. **consents** (User Authorization Grants)

**Purpose**: Stores user's explicit permission for third-party applications to access their data. This is the "Allow/Deny" screen you see when logging into apps via Google/Facebook/etc.

```sql
CREATE TABLE consents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  scope TEXT NOT NULL,  -- What permissions were granted (e.g., "openid profile email")
  granted_at TIMESTAMP DEFAULT NOW(),

  UNIQUE (user_id, client_id)
);

CREATE INDEX idx_consent_user ON consents(user_id);
CREATE INDEX idx_consent_client ON consents(client_id);
```

**Relationships:**

- N:1 → users
- N:1 → clients

**Why This Table Exists:**

When a user logs into a third-party app (client) using your OAuth server, they must **explicitly authorize** what data the app can access. The consent table tracks these authorizations.

**User Experience Flow:**

1. User clicks "Login with [Your Service]" on third-party app
2. Redirected to your OAuth server (`/oauth/authorize`)
3. User logs in (authenticates)
4. **System checks `consents` table**: Has this user previously authorized this client?
   - **YES** → Skip consent screen, proceed with authorization code
   - **NO** → Show consent screen: "App X wants to access your email and profile. Allow?"
5. User clicks "Allow" → Insert into `consents` table
6. User clicks "Deny" → Redirect with error, no consent stored

**Real-World Example:**

```
User: john@example.com
Client: "Acme Analytics Dashboard"
Scopes Requested: "openid profile email read:analytics"

First login:
  → Show consent: "Acme Analytics wants to: View your profile, View your email, Read your analytics"
  → User clicks Allow
  → INSERT INTO consents (user_id, client_id, scope) VALUES (...)

Second login (next week):
  → Check consents: Found existing consent for john@acme
  → Skip consent screen, auto-authorize
```

**Business Rules:**

- One consent per user-client pair (prevents duplicate consent screens)
- Scope can be updated if client requests NEW scopes (show consent screen again)
- Deleted when client is deleted (cascade)
- Skip consent screen if matching consent exists with **equal or greater scopes**
- Users can revoke consents via account settings (future feature)

**Privacy & Security:**

- GDPR compliance: Users must explicitly consent to data sharing
- Scope limitation: Only grant what user approved
- Revocable: Users can withdraw consent anytime
- Audit trail: `granted_at` tracks when permission was given

---

### 7. **signing_keys** (JWT Signing Keys)

**Purpose**: Stores cryptographic keys used to sign and verify JWT access tokens and ID tokens. These are **system-wide** keys used by the OAuth server itself, NOT per-client keys.

```sql
CREATE TABLE signing_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_id TEXT UNIQUE NOT NULL,  -- e.g., "2025-01-19-v1"
  algorithm TEXT NOT NULL DEFAULT 'RS256',
  public_key_pem TEXT NOT NULL,
  private_key_encrypted TEXT NOT NULL,  -- Encrypted with KEY_ENCRYPTION_SECRET
  is_active BOOLEAN DEFAULT TRUE,
  is_primary BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP,
  rotated_at TIMESTAMP,
  next_rotation_at TIMESTAMP,

  CONSTRAINT one_primary CHECK (
    (SELECT COUNT(*) FROM signing_keys WHERE is_primary = TRUE) <= 1
  )
);

CREATE INDEX idx_keys_active ON signing_keys(is_active, is_primary);
CREATE INDEX idx_keys_rotation ON signing_keys(next_rotation_at) WHERE is_active;
```

**Relationships:**

- **NONE** - Intentionally standalone (system-wide, not per-client)

**Why No Relationship to `clients`?**

This is **CORRECT BY DESIGN**. Here's why:

**System-Wide vs Per-Client Keys:**

In OAuth 2.0 / OIDC, the **Authorization Server** (your identity server) signs all JWTs using its **own private keys**. Clients do NOT have their own signing keys—they only **verify** tokens using the server's **public keys** (from JWKS endpoint).

**Architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│         OAuth Server (Identity Server)                      │
│                                                              │
│  ┌──────────────┐                                           │
│  │ signing_keys │  ← System-wide keys                       │
│  │ (1-5 keys)   │                                           │
│  └──────────────┘                                           │
│         │                                                    │
│         │ Signs ALL JWTs                                    │
│         ▼                                                    │
│  ┌────────────────────────────────────┐                     │
│  │  TokenService.generateAccessToken() │                    │
│  │  - Uses PRIMARY signing_key         │                    │
│  │  - Signs JWT for ANY client         │                    │
│  └────────────────────────────────────┘                     │
│         │                                                    │
│         │ Issues tokens to clients                          │
│         ▼                                                    │
└─────────────────────────────────────────────────────────────┘
         │                           │
         ▼                           ▼
┌──────────────┐            ┌──────────────┐
│  Client A    │            │  Client B    │
│  (Web App)   │            │  (Mobile App)│
│              │            │              │
│ Receives JWT │            │ Receives JWT │
│ signed with  │            │ signed with  │
│ SAME key     │            │ SAME key     │
│              │            │              │
│ Verifies via │            │ Verifies via │
│ JWKS endpoint│            │ JWKS endpoint│
└──────────────┘            └──────────────┘
```

**How Clients Verify Tokens:**

1. Client receives JWT access token
2. Client fetches public keys from `GET /.well-known/jwks.json`
3. JWKS returns ALL active public keys from `signing_keys` table
4. Client uses JWT's `kid` header to select correct public key
5. Client verifies JWT signature using public key

**Example JWT Header:**

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "2025-01-19-v1"  ← References signing_keys.key_id
}
```

**Why This Design?**

1. **Centralized Security**: One set of keys to manage, rotate, and secure
2. **Simplified Key Rotation**: Rotate once, affects all clients simultaneously
3. **Standard OAuth 2.0**: This is the RFC-compliant approach
4. **Trust Model**: Clients trust the Authorization Server's signatures
5. **Scalability**: No need to manage N keys for N clients

**Business Rules:**

- Only ONE `is_primary=true` key at any time
- Primary key used for signing ALL new JWTs (regardless of client)
- All active keys used for JWT verification (during rotation overlap)
- Private keys encrypted at rest using AES-256
- Automatic rotation based on `next_rotation_at`
- Old keys kept for verification but marked inactive after grace period

**Key Lifecycle:**

1. Generate new key pair
2. Insert with `is_active=true, is_primary=false`
3. Promote to primary (demote old primary)
4. After grace period, mark old primary as `is_active=false`
5. Keep inactive keys for audit/verification

---

### **Alternative Design: Per-Client Keys** (NOT RECOMMENDED)

**IF** you wanted per-client signing keys (non-standard), you would add:

```sql
ALTER TABLE signing_keys ADD COLUMN client_id UUID REFERENCES clients(id);
```

**Use Cases for Per-Client Keys:**

- Multi-tenant SaaS where each organization wants their own keys
- Regulatory requirements for key isolation
- Advanced security: compromised client doesn't affect others

**Drawbacks:**

- Much more complex key management
- Harder rotation (rotate N keys instead of 1)
- Non-standard OAuth 2.0 implementation
- JWKS endpoint must be client-specific

**Our Recommendation**: Stick with system-wide keys (current design) unless you have specific requirements for per-client keys.

---

## Key Concepts Summary

### **Consents Table - Why It Matters**

Think of it like app permissions on your phone:

- First time you use an app with Google login → "Allow Google Calendar access?" → Store consent
- Next time → No prompt, auto-authorized (consent exists)

**Database Check:**

```sql
-- On OAuth authorize endpoint:
SELECT * FROM consents
WHERE user_id = 'john-uuid'
  AND client_id = 'acme-app-uuid';

-- If found → Skip consent screen
-- If not found → Show consent screen
```

### **Signing Keys - No Client Relationship**

**Common Misconception**: "Each client has its own signing key"
**Reality**: All clients share the same system-wide signing keys

**Analogy**:

- **Government Passport Office** (OAuth Server) stamps all passports (JWTs) with the same official seal (signing key)
- **Airlines** (Clients) verify the seal using public verification methods
- Airlines don't have their own seals—they trust the government's seal

**What Clients DO Have**: `client_secret` (stored in `clients.client_secret_hash`)

- Used for client authentication on `/oauth/token` endpoint
- NOT used for signing JWTs
- Only for confidential clients (backend apps)

**Relationship Summary:**

```
signing_keys → NO FK → (system-wide, used by OAuth server itself)
clients.client_secret_hash → (per-client, for authenticating TO the OAuth server)
```

---

## Data Flow Examples

### Authorization Code Flow (Confidential Client)

```
1. User clicks "Login with OAuth Provider"
2. Client redirects to /oauth/authorize
3. User authenticates (creates session)
4. Check consents table → show consent screen if needed
5. Insert into authorization_codes (with PKCE challenge)
6. Redirect to client with code
7. Client POST /oauth/token with code + code_verifier
8. Verify PKCE, mark code as used (used_at = NOW())
9. Insert into refresh_tokens
10. Generate JWT access token (signed with primary signing_key)
11. Return tokens to client
```

### Token Refresh Flow

```
1. Client POST /oauth/token with refresh_token
2. Hash token, lookup in refresh_tokens (check not revoked)
3. Validate expires_at, client_id, user_id
4. Mark old token as revoked
5. Insert new refresh_token (with previous_token_hash)
6. Generate new JWT access token
7. Return new tokens
```

### Key Rotation Flow

```
1. Cron job checks signing_keys.next_rotation_at
2. Generate new RSA key pair
3. Encrypt private key with KEY_ENCRYPTION_SECRET
4. Insert with key_id="2025-01-19-v2", is_active=true, is_primary=false
5. Update old primary: is_primary=false
6. Update new key: is_primary=true
7. Set new key next_rotation_at = NOW() + 90 days
8. Keep old key active for 7 days (grace period)
9. After grace period: Update old key is_active=false
10. JWKS endpoint now returns both keys
11. New JWTs signed with new key (kid="2025-01-19-v2")
12. Old JWTs verified with old key until expiry
```

---

## Indexes Summary

### Critical Indexes (Performance)

- `users.email` - Login lookups
- `clients.client_id` - OAuth flow lookups
- `authorization_codes.code` - Code exchange
- `refresh_tokens.token_hash` - Token refresh
- `signing_keys(is_active, is_primary)` - Token signing

### Optimization Indexes

- `authorization_codes(expires_at)` - Cleanup jobs
- `refresh_tokens(expires_at) WHERE NOT revoked` - Cleanup jobs
- `clients(organization_id, is_active)` - Multi-tenant queries

---

## Storage Estimates (1 million users)

| Table               | Rows Estimate | Size per Row | Total Size   |
| ------------------- | ------------- | ------------ | ------------ |
| users               | 1,000,000     | ~200 bytes   | 200 MB       |
| organizations       | 10,000        | ~150 bytes   | 1.5 MB       |
| clients             | 50,000        | ~1 KB        | 50 MB        |
| authorization_codes | 100,000\*     | ~500 bytes   | 50 MB        |
| refresh_tokens      | 2,000,000     | ~300 bytes   | 600 MB       |
| consents            | 5,000,000     | ~150 bytes   | 750 MB       |
| signing_keys        | 20            | ~4 KB        | 80 KB        |
| **TOTAL**           |               |              | **~1.65 GB** |

\*Authorization codes cleaned up after 10 minutes

---

## Cleanup Jobs Required

```sql
-- Run every hour: Delete expired authorization codes
DELETE FROM authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour';

-- Run daily: Delete expired and revoked refresh tokens
DELETE FROM refresh_tokens WHERE (expires_at < NOW() OR revoked = TRUE)
  AND created_at < NOW() - INTERVAL '30 days';

-- Run weekly: Deactivate old signing keys after grace period
UPDATE signing_keys SET is_active = FALSE
  WHERE is_active = TRUE
  AND is_primary = FALSE
  AND rotated_at < NOW() - INTERVAL '7 days';
```

---

## Security Considerations

1. **No Plain Text Secrets**: Client secrets and refresh tokens stored as hashes only
2. **Encrypted Private Keys**: Signing keys encrypted at rest
3. **Soft Deletes**: Clients use `is_active=false` for audit trail
4. **Token Rotation**: Refresh tokens rotated on every use
5. **PKCE Enforcement**: Public clients must use code_challenge
6. **Scope Limitation**: Clients have allowed_scopes whitelist
7. **CORS Restrictions**: Public clients have allowed_cors_origins whitelist
8. **Unique Constraints**: Prevent duplicate emails, client_ids, tokens
9. **Cascade Deletes**: Cleanup tokens when clients/users deleted
10. **Audit Trail**: created_at timestamps on all tables
