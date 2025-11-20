# API Testing Guide - Postman

Complete guide for testing the Identity Server API using Postman.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Setup Instructions](#setup-instructions)
3. [Testing Workflow](#testing-workflow)
4. [Collection 01: Admin & Setup](#collection-01-admin--setup)
5. [Collection 02: OAuth 2.0 Flows](#collection-02-oauth-20-flows)
6. [Collection 03: User Authentication](#collection-03-user-authentication)
7. [Troubleshooting](#troubleshooting)
8. [API Reference](#api-reference)

---

## Prerequisites

### Required Software

- **Postman** (Desktop or Web) - Download from https://www.postman.com/downloads/
- **Server running** at `http://localhost:3000`
- **Database seeded** with admin user (`admin@example.com` / `Admin123!`)

### Verify Server

```bash
# Start server
pnpm dev

# Test health endpoint
curl http://localhost:3000/health
# Expected: {"status":"ok"}
```

---

## Setup Instructions

### Step 1: Import Collections

1. Open Postman
2. Click **Import** button (top left)
3. Click **Upload Files**
4. Navigate to `postman/` directory
5. Select all 4 JSON files:
   - `environment.json`
   - `01-admin-collection.json`
   - `02-oauth-flow-collection.json`
   - `03-user-auth-collection.json`
6. Click **Open** then **Import**

### Step 2: Configure Environment

1. Click environment dropdown (top right corner)
2. Select **"Identity Server Environment"**
3. Click the eye icon to view variables
4. Verify these values:

```
baseUrl: http://localhost:3000
adminEmail: admin@example.com
adminPassword: Admin123!
testUserEmail: testuser@example.com
testUserPassword: TestUser123!
```

### Step 3: Verify Import

You should see 3 collections in the sidebar:

- ✅ 01 - Admin & Setup (21 requests)
- ✅ 02 - OAuth 2.0 & OIDC Flows (11 requests)
- ✅ 03 - User Authentication (6 requests)

**Total: 38 API requests**

---

## Testing Workflow

### Quick Start (5 minutes)

Run these 4 requests to set up your test environment:

1. **01.1 - Health Check** → Verify server is running
2. **01.2 - Admin Login** → Get admin session (auto-saves cookie)
3. **01.3 - Create Organization** → Create test org (auto-saves ID)
4. **01.6 - Create Confidential Client** → Create OAuth client (auto-saves credentials)

✅ **After this, you're ready to test OAuth flows!**

### Full Test Suite (15 minutes)

Run all requests in numerical order:

- 01.1 → 01.21 (Admin operations)
- 02.1 → 02.11 (OAuth flows)
- 03.1 → 03.6 (User auth)

---

## Collection 01: Admin & Setup

**Purpose:** Set up test environment with organizations, clients, and manage keys.

**Requirements:** Admin session (request 01.2)

### 01.1 - Health Check ✅

**Purpose:** Verify server is running

**Request:**

```http
GET {{baseUrl}}/health
```

**Expected Response:**

```json
{
  "status": "ok"
}
```

**Status Code:** `200 OK`

---

### 01.2 - Admin Login (Get Session) 🔑

**Purpose:** Authenticate as admin to access admin endpoints

**Request:**

```http
POST {{baseUrl}}/login
Content-Type: application/x-www-form-urlencoded

email={{adminEmail}}&password={{adminPassword}}&rememberMe=on
```

**Expected Response:**

- Status: `302 Found` or `200 OK`
- Cookie: `connect.sid=...` (auto-saved to `sessionCookie`)

**Auto-saves:**

- ✅ `sessionCookie` → Used for all admin requests

**Troubleshooting:**

- If 401: Check admin credentials in database
- If 500: Verify Redis is running

---

### 01.3 - Create Organization 🏢

**Purpose:** Create a test organization

**Request:**

```http
POST {{baseUrl}}/admin/organizations
Cookie: {{sessionCookie}}
Content-Type: application/json

{
  "name": "Test Organization",
  "slug": "test-org",
  "ownerUserId": "admin-user-id"
}
```

**Expected Response:**

```json
{
  "id": "cm4g9...",
  "name": "Test Organization",
  "slug": "test-org",
  "ownerUserId": "admin-user-id",
  "isActive": true,
  "createdAt": "2025-11-20T10:30:00.000Z",
  "updatedAt": "2025-11-20T10:30:00.000Z"
}
```

**Status Code:** `201 Created`

**Auto-saves:**

- ✅ `organizationId` → Used for creating clients

---

### 01.4 - List Organizations 📋

**Purpose:** View all organizations with pagination

**Request:**

```http
GET {{baseUrl}}/admin/organizations?limit=20&offset=0
Cookie: {{sessionCookie}}
```

**Query Parameters:**

- `limit` (optional): Results per page (default: 20)
- `offset` (optional): Pagination offset (default: 0)
- `isActive` (optional): Filter by active status (true/false)

**Expected Response:**

```json
{
  "organizations": [
    {
      "id": "cm4g9...",
      "name": "Test Organization",
      "slug": "test-org",
      "isActive": true,
      "createdAt": "2025-11-20T10:30:00.000Z"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

**Status Code:** `200 OK`

---

### 01.5 - Get Organization Details 🔍

**Purpose:** Get specific organization information

**Request:**

```http
GET {{baseUrl}}/admin/organizations/{{organizationId}}
Cookie: {{sessionCookie}}
```

**Expected Response:**

```json
{
  "id": "cm4g9...",
  "name": "Test Organization",
  "slug": "test-org",
  "ownerUserId": "admin-user-id",
  "isActive": true,
  "createdAt": "2025-11-20T10:30:00.000Z",
  "updatedAt": "2025-11-20T10:30:00.000Z"
}
```

**Status Code:** `200 OK`

---

### 01.6 - Create Confidential Client ⭐ CRITICAL

**Purpose:** Create OAuth 2.0 confidential client with secret

**Request:**

```http
POST {{baseUrl}}/admin/clients
Cookie: {{sessionCookie}}
Content-Type: application/json

{
  "name": "Test Confidential Client",
  "clientType": "confidential",
  "redirectUris": ["http://localhost:4000/callback"],
  "grantTypes": ["authorization_code", "refresh_token", "client_credentials"],
  "allowedScopes": "openid email profile",
  "organizationId": "{{organizationId}}",
  "logoUrl": "https://example.com/logo.png",
  "homepageUrl": "https://example.com",
  "privacyUrl": "https://example.com/privacy",
  "termsUrl": "https://example.com/terms"
}
```

**Expected Response:**

```json
{
  "clientId": "cm4ga...",
  "clientSecret": "cs_abc123xyz...",
  "name": "Test Confidential Client",
  "clientType": "confidential",
  "redirectUris": ["http://localhost:4000/callback"],
  "grantTypes": ["authorization_code", "refresh_token", "client_credentials"],
  "allowedScopes": "openid email profile",
  "organizationId": "cm4g9...",
  "isActive": true,
  "createdAt": "2025-11-20T10:35:00.000Z"
}
```

**Status Code:** `201 Created`

**Auto-saves:**

- ✅ `clientId` → Used for OAuth flows
- ✅ `clientSecret` → Used for token exchange

**⚠️ IMPORTANT:**

- Client secret is **ONLY shown once**
- Save it securely
- Cannot be retrieved later (only regenerated)

---

### 01.7 - Create Public Client 📱

**Purpose:** Create OAuth 2.0 public client (for SPAs/mobile apps)

**Request:**

```http
POST {{baseUrl}}/admin/clients
Cookie: {{sessionCookie}}
Content-Type: application/json

{
  "name": "Test Public Client (SPA)",
  "clientType": "public",
  "redirectUris": ["http://localhost:5000/callback"],
  "grantTypes": ["authorization_code", "refresh_token"],
  "allowedScopes": "openid email profile"
}
```

**Expected Response:**

```json
{
  "clientId": "cm4gb...",
  "name": "Test Public Client (SPA)",
  "clientType": "public",
  "redirectUris": ["http://localhost:5000/callback"],
  "grantTypes": ["authorization_code", "refresh_token"],
  "allowedScopes": "openid email profile",
  "isActive": true,
  "createdAt": "2025-11-20T10:36:00.000Z"
}
```

**Status Code:** `201 Created`

**Auto-saves:**

- ✅ `publicClientId`

**Note:** Public clients do NOT receive a secret

---

### 01.8 - List All Clients 📋

**Purpose:** View all OAuth clients with filters

**Request:**

```http
GET {{baseUrl}}/admin/clients?limit=20&offset=0
Cookie: {{sessionCookie}}
```

**Query Parameters:**

- `limit` (optional): Results per page (default: 20)
- `offset` (optional): Pagination offset (default: 0)
- `organizationId` (optional): Filter by organization
- `clientType` (optional): Filter by type (confidential/public)
- `isActive` (optional): Filter by active status (true/false)

**Expected Response:**

```json
{
  "clients": [
    {
      "clientId": "cm4ga...",
      "name": "Test Confidential Client",
      "clientType": "confidential",
      "isActive": true,
      "createdAt": "2025-11-20T10:35:00.000Z"
    }
  ],
  "total": 2,
  "limit": 20,
  "offset": 0
}
```

**Status Code:** `200 OK`

---

### 01.9 - Get Client Details 🔍

**Purpose:** View specific client configuration

**Request:**

```http
GET {{baseUrl}}/admin/clients/{{clientId}}
Cookie: {{sessionCookie}}
```

**Expected Response:**

```json
{
  "clientId": "cm4ga...",
  "name": "Test Confidential Client",
  "clientType": "confidential",
  "redirectUris": ["http://localhost:4000/callback"],
  "grantTypes": ["authorization_code", "refresh_token", "client_credentials"],
  "allowedScopes": "openid email profile",
  "organizationId": "cm4g9...",
  "logoUrl": "https://example.com/logo.png",
  "homepageUrl": "https://example.com",
  "isActive": true,
  "createdAt": "2025-11-20T10:35:00.000Z",
  "updatedAt": "2025-11-20T10:35:00.000Z"
}
```

**Status Code:** `200 OK`

**Note:** Client secret is NEVER returned in this response

---

### 01.10 - Update Client ✏️

**Purpose:** Modify client configuration

**Request:**

```http
PUT {{baseUrl}}/admin/clients/{{clientId}}
Cookie: {{sessionCookie}}
Content-Type: application/json

{
  "name": "Updated Client Name",
  "redirectUris": ["http://localhost:4000/callback", "http://localhost:4001/callback"],
  "allowedScopes": "openid email profile"
}
```

**Updatable Fields:**

- `name`
- `redirectUris`
- `grantTypes`
- `allowedScopes`
- `organizationId`
- `logoUrl`, `homepageUrl`, `privacyUrl`, `termsUrl`, `contacts`

**Expected Response:**

```json
{
  "clientId": "cm4ga...",
  "name": "Updated Client Name",
  "redirectUris": ["http://localhost:4000/callback", "http://localhost:4001/callback"],
  "allowedScopes": "openid email profile",
  "updatedAt": "2025-11-20T10:40:00.000Z"
}
```

**Status Code:** `200 OK`

**Note:** Cannot change `clientType` or `clientId`

---

### 01.11 - Regenerate Client Secret 🔄

**Purpose:** Generate new client secret (invalidates old one)

**Request:**

```http
POST {{baseUrl}}/admin/clients/{{clientId}}/secret
Cookie: {{sessionCookie}}
```

**Expected Response:**

```json
{
  "clientId": "cm4ga...",
  "clientSecret": "cs_new_secret_xyz...",
  "regeneratedAt": "2025-11-20T10:45:00.000Z"
}
```

**Status Code:** `200 OK`

**Auto-saves:**

- ✅ `clientSecret` → Replaces old secret

**⚠️ WARNINGS:**

- Old secret is **immediately invalidated**
- All applications using old secret will fail
- Only works for **confidential** clients
- New secret shown **only once**

---

### 01.12 - Get Organization Clients 📋

**Purpose:** List all clients in a specific organization

**Request:**

```http
GET {{baseUrl}}/admin/organizations/{{organizationId}}/clients
Cookie: {{sessionCookie}}
```

**Expected Response:**

```json
{
  "organizationId": "cm4g9...",
  "clients": [
    {
      "clientId": "cm4ga...",
      "name": "Test Confidential Client",
      "clientType": "confidential",
      "isActive": true
    }
  ],
  "total": 1
}
```

**Status Code:** `200 OK`

---

### 01.13 - List All Keys 🔑

**Purpose:** View all JWT signing keys (active and inactive)

**Request:**

```http
GET {{baseUrl}}/admin/keys
Cookie: {{sessionCookie}}
```

**Expected Response:**

```json
{
  "keys": [
    {
      "id": "key_123",
      "keyId": "kid_abc",
      "algorithm": "RS256",
      "isActive": true,
      "isPrimary": true,
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
      "createdAt": "2025-11-01T00:00:00.000Z",
      "expiresAt": "2026-11-01T00:00:00.000Z",
      "nextRotationAt": "2025-12-01T00:00:00.000Z"
    },
    {
      "id": "key_456",
      "keyId": "kid_xyz",
      "algorithm": "RS256",
      "isActive": true,
      "isPrimary": false,
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
      "createdAt": "2025-10-01T00:00:00.000Z",
      "expiresAt": "2026-10-01T00:00:00.000Z"
    }
  ],
  "total": 2
}
```

**Status Code:** `200 OK`

**Key Properties:**

- `isPrimary: true` → Currently used for signing new tokens
- `isActive: true` → Can verify existing tokens
- Private keys are **NEVER** returned via API

---

### 01.14 - Get Primary Key 🔑

**Purpose:** Get current primary signing key

**Request:**

```http
GET {{baseUrl}}/admin/keys/primary
Cookie: {{sessionCookie}}
```

**Expected Response:**

```json
{
  "id": "key_123",
  "keyId": "kid_abc",
  "algorithm": "RS256",
  "isPrimary": true,
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
  "createdAt": "2025-11-01T00:00:00.000Z",
  "nextRotationAt": "2025-12-01T00:00:00.000Z"
}
```

**Status Code:** `200 OK`

---

### 01.15 - Get Key Rotation Status ⏰

**Purpose:** Check when next key rotation is scheduled

**Request:**

```http
GET {{baseUrl}}/admin/keys/rotation-status
Cookie: {{sessionCookie}}
```

**Expected Response:**

```json
{
  "nextRotationAt": "2025-12-01T00:00:00.000Z",
  "rotationIntervalDays": 30,
  "currentPrimaryKeyId": "kid_abc",
  "currentPrimaryKeyAge": 20
}
```

**Status Code:** `200 OK`

---

### 01.16 - Trigger Key Rotation 🔄

**Purpose:** Manually rotate signing keys

**Request:**

```http
POST {{baseUrl}}/admin/keys/rotate
Cookie: {{sessionCookie}}
Content-Type: application/json

{
  "confirm": true
}
```

**Expected Response:**

```json
{
  "message": "Key rotation successful",
  "newPrimaryKeyId": "kid_new",
  "previousPrimaryKeyId": "kid_abc",
  "rotatedAt": "2025-11-20T10:50:00.000Z"
}
```

**Status Code:** `200 OK`

**What happens:**

1. New RSA key pair generated
2. New key set as primary
3. Old primary key remains active for verification
4. JWKS updated immediately

---

### 01.17 - Update Organization ✏️

**Purpose:** Modify organization information

**Request:**

```http
PUT {{baseUrl}}/admin/organizations/{{organizationId}}
Cookie: {{sessionCookie}}
Content-Type: application/json

{
  "name": "Updated Organization Name",
  "slug": "updated-org"
}
```

**Expected Response:**

```json
{
  "id": "cm4g9...",
  "name": "Updated Organization Name",
  "slug": "updated-org",
  "updatedAt": "2025-11-20T11:00:00.000Z"
}
```

**Status Code:** `200 OK`

---

### 01.18 - Deactivate Client (Soft Delete) 🗑️

**Purpose:** Deactivate client without permanent deletion

**Request:**

```http
DELETE {{baseUrl}}/admin/clients/{{clientId}}
Cookie: {{sessionCookie}}
```

**Expected Response:**

```
(No content)
```

**Status Code:** `204 No Content`

**Result:**

- Client marked as `isActive: false`
- Can be reactivated later
- Existing tokens may still work until expiration

---

### 01.19 - Delete Client Permanently 💀

**Purpose:** Permanently delete client (cannot be undone)

**Request:**

```http
DELETE {{baseUrl}}/admin/clients/{{clientId}}?hard=true
Cookie: {{sessionCookie}}
```

**Expected Response:**

```
(No content)
```

**Status Code:** `204 No Content`

**⚠️ WARNING:**

- **Cannot be undone**
- Client data permanently removed
- All associated tokens invalidated
- Applications using this client will fail immediately

---

### 01.20 - Deactivate Organization (Soft Delete) 🗑️

**Purpose:** Deactivate organization without permanent deletion

**Request:**

```http
DELETE {{baseUrl}}/admin/organizations/{{organizationId}}
Cookie: {{sessionCookie}}
```

**Expected Response:**

```
(No content)
```

**Status Code:** `204 No Content`

---

### 01.21 - Delete Organization Permanently 💀

**Purpose:** Permanently delete organization (cannot be undone)

**Request:**

```http
DELETE {{baseUrl}}/admin/organizations/{{organizationId}}?hard=true
Cookie: {{sessionCookie}}
```

**Expected Response:**

```
(No content)
```

**Status Code:** `204 No Content`

**⚠️ WARNING:**

- **Cannot be undone**
- Organization and all associated data removed
- May affect related clients

---

## Collection 02: OAuth 2.0 Flows

**Purpose:** Test complete OAuth 2.0 authorization code flow with PKCE and token operations.

**Requirements:** Client created from Collection 01 (request 01.6)

### 02.1 - OIDC Discovery 🔍

**Purpose:** Get OpenID Connect configuration metadata

**Request:**

```http
GET {{baseUrl}}/.well-known/openid-configuration
```

**Expected Response:**

```json
{
  "issuer": "http://localhost:3000",
  "authorization_endpoint": "http://localhost:3000/oauth/authorize",
  "token_endpoint": "http://localhost:3000/oauth/token",
  "userinfo_endpoint": "http://localhost:3000/oauth/userinfo",
  "jwks_uri": "http://localhost:3000/.well-known/jwks.json",
  "revocation_endpoint": "http://localhost:3000/oauth/revoke",
  "introspection_endpoint": "http://localhost:3000/oauth/introspect",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "email", "profile"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "code_challenge_methods_supported": ["S256"]
}
```

**Status Code:** `200 OK`

**No authentication required**

---

### 02.2 - Get JWKS (Public Keys) 🔐

**Purpose:** Get JSON Web Key Set for JWT verification

**Request:**

```http
GET {{baseUrl}}/.well-known/jwks.json
```

**Expected Response:**

```json
{
  "keys": [
    {
      "kid": "kid_abc",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "0vx7agoebGcQSuu...",
      "e": "AQAB"
    }
  ]
}
```

**Status Code:** `200 OK`

**Use case:** External applications verify JWT signatures using these public keys

**No authentication required**

---

### 02.3 - Generate PKCE Code Verifier & Challenge ⭐ REQUIRED

**Purpose:** Generate PKCE parameters for secure authorization flow

**How it works:**

- Pre-request script automatically generates:
  - `code_verifier`: Random 43-128 character string (base64url)
  - `code_challenge`: SHA256 hash of code_verifier (base64url)
- Both values saved to environment

**Request:**

```http
GET {{baseUrl}}/health
```

**Pre-request Script (runs automatically):**

```javascript
function base64URLEncode(str) {
  return str
    .toString(CryptoJS.enc.Base64)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

const verifier = base64URLEncode(CryptoJS.lib.WordArray.random(32));
const challenge = base64URLEncode(CryptoJS.SHA256(verifier));

pm.environment.set('codeVerifier', verifier);
pm.environment.set('codeChallenge', challenge);
```

**Auto-saves:**

- ✅ `codeVerifier` → Used when exchanging authorization code (02.5)
- ✅ `codeChallenge` → Used in authorization URL (02.4)

**⚠️ IMPORTANT:** Run this BEFORE starting OAuth flow (request 02.4)

---

### 02.4 - Start Authorization Flow (Browser Required) 🌐

**Purpose:** Initiate OAuth 2.0 authorization code flow

**Request URL:**

```http
GET {{baseUrl}}/oauth/authorize
  ?client_id={{clientId}}
  &redirect_uri=http://localhost:4000/callback
  &response_type=code
  &scope=openid email profile
  &state=random_state_123
  &code_challenge={{codeChallenge}}
  &code_challenge_method=S256
```

**⚠️ MANUAL STEPS REQUIRED:**

1. **Copy full URL** from Postman request
2. **Open URL in browser**
3. **Login** (if not already logged in)
   - Use admin credentials or create new user
4. **Review consent page**
   - Shows requested scopes
   - Shows client information
5. **Click "Allow" or "Authorize"**
6. **Browser redirects** to callback URL:
   ```
   http://localhost:4000/callback?code=AUTH_CODE_HERE&state=random_state_123
   ```
7. **Copy the `code` parameter** value
8. **In Postman:**
   - Go to environment variables
   - Set `authorizationCode` to the copied code
   - Click Save

**Authorization Code Properties:**

- Valid for **10 minutes**
- **Single-use only** (expires after exchange)
- Must be used with matching `code_verifier`

**Troubleshooting:**

- If redirect fails: Check client's `redirectUris` configuration
- If login fails: Check user credentials
- If consent fails: Check client's `allowedScopes`

---

### 02.5 - Exchange Authorization Code for Tokens 🎟️

**Purpose:** Exchange authorization code for access and refresh tokens

**Request:**

```http
POST {{baseUrl}}/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code={{authorizationCode}}
&redirect_uri=http://localhost:4000/callback
&client_id={{clientId}}
&client_secret={{clientSecret}}
&code_verifier={{codeVerifier}}
```

**Expected Response:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZF9hYmMifQ...",
  "refresh_token": "rt_cm4gcdefgh...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid email profile",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZF9hYmMifQ..."
}
```

**Status Code:** `200 OK`

**Auto-saves:**

- ✅ `accessToken` → Used for API requests (02.6)
- ✅ `refreshToken` → Used to get new access token (02.8)

**Token Details:**

- `access_token`: JWT, expires in 1 hour (3600 seconds)
- `refresh_token`: Opaque token, expires in 30 days
- `id_token`: JWT with user identity claims (OIDC)

**Errors:**

- `400 invalid_grant`: Code expired or already used
- `400 invalid_request`: Missing PKCE verifier
- `400 invalid_client`: Wrong client credentials

---

### 02.6 - Get User Info (with Access Token) 👤

**Purpose:** Get authenticated user profile using access token

**Request:**

```http
GET {{baseUrl}}/oauth/userinfo
Authorization: Bearer {{accessToken}}
```

**Expected Response:**

```json
{
  "sub": "cm4user123",
  "email": "admin@example.com",
  "email_verified": true,
  "name": "admin"
}
```

**Status Code:** `200 OK`

**Claims returned based on scopes:**

- `openid` scope → `sub` (user ID)
- `email` scope → `email`, `email_verified`
- `profile` scope → `name` (currently derived from email)

**Errors:**

- `401 Unauthorized`: Missing or invalid access token
- `401 Unauthorized`: Token expired
- `403 Forbidden`: Insufficient scopes

---

### 02.7 - Introspect Access Token 🔍

**Purpose:** Check token metadata and validity

**Request:**

```http
POST {{baseUrl}}/oauth/introspect
Content-Type: application/x-www-form-urlencoded

token={{accessToken}}
&client_id={{clientId}}
&client_secret={{clientSecret}}
```

**Expected Response (Active Token):**

```json
{
  "active": true,
  "scope": "openid email profile",
  "client_id": "cm4ga...",
  "username": "admin@example.com",
  "token_type": "Bearer",
  "exp": 1700000000,
  "iat": 1699996400,
  "sub": "cm4user123"
}
```

**Expected Response (Inactive Token):**

```json
{
  "active": false
}
```

**Status Code:** `200 OK`

**Use cases:**

- Check if token is still valid
- Get token expiration time
- Verify token scopes
- Audit token usage

---

### 02.8 - Refresh Access Token 🔄

**Purpose:** Get new access token without user interaction

**Request:**

```http
POST {{baseUrl}}/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token={{refreshToken}}
&client_id={{clientId}}
&client_secret={{clientSecret}}
```

**Expected Response:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZF9hYmMifQ...",
  "refresh_token": "rt_cm4gnewtoken...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid email profile"
}
```

**Status Code:** `200 OK`

**Auto-saves:**

- ✅ `accessToken` → New access token
- ✅ `refreshToken` → New refresh token (token rotation)

**Refresh Token Rotation:**

- Each refresh returns a **new** refresh token
- Old refresh token is invalidated
- Improves security (detects token theft)

**Errors:**

- `400 invalid_grant`: Refresh token expired or revoked
- `400 invalid_client`: Wrong client credentials

---

### 02.9 - Client Credentials Grant 🤖

**Purpose:** Machine-to-machine authentication (no user)

**Request:**

```http
POST {{baseUrl}}/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id={{clientId}}
&client_secret={{clientSecret}}
&scope=openid
```

**Expected Response:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZF9hYmMifQ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid"
}
```

**Status Code:** `200 OK`

**Use cases:**

- Backend service-to-service authentication
- Scheduled jobs accessing APIs
- Server-side automation

**Note:** No refresh token returned (use client credentials again)

---

### 02.10 - Revoke Access Token 🚫

**Purpose:** Invalidate an access token

**Request:**

```http
POST {{baseUrl}}/oauth/revoke
Content-Type: application/x-www-form-urlencoded

token={{accessToken}}
&token_type_hint=access_token
&client_id={{clientId}}
&client_secret={{clientSecret}}
```

**Expected Response:**

```
(No content)
```

**Status Code:** `200 OK`

**Result:** Token immediately invalidated (cannot be used)

---

### 02.11 - Revoke Refresh Token 🚫

**Purpose:** Invalidate refresh token and associated access tokens

**Request:**

```http
POST {{baseUrl}}/oauth/revoke
Content-Type: application/x-www-form-urlencoded

token={{refreshToken}}
&token_type_hint=refresh_token
&client_id={{clientId}}
&client_secret={{clientSecret}}
```

**Expected Response:**

```
(No content)
```

**Status Code:** `200 OK`

**Result:**

- Refresh token invalidated
- Associated access tokens may be invalidated (implementation dependent)

---

## Collection 03: User Authentication

**Purpose:** Test user registration, login, and session management.

### 03.1 - Register New User 📝

**Purpose:** Create new user account

**Request:**

```http
POST {{baseUrl}}/register
Content-Type: application/x-www-form-urlencoded

email={{testUserEmail}}
&password={{testUserPassword}}
&confirmPassword={{testUserPassword}}
```

**Expected Response:**

- Status: `302 Found` (redirect) or `200 OK`
- Cookie: `connect.sid=...` (auto-saved)

**Auto-saves:**

- ✅ `sessionCookie` → User automatically logged in after registration

**Validation:**

- Email must be valid format
- Email must not already exist
- Password must meet requirements
- Passwords must match

**Errors:**

- `400 Bad Request`: Invalid email format
- `409 Conflict`: Email already registered
- `400 Bad Request`: Password too weak
- `400 Bad Request`: Passwords don't match

---

### 03.2 - Login Existing User 🔐

**Purpose:** Authenticate with email and password

**Request:**

```http
POST {{baseUrl}}/login
Content-Type: application/x-www-form-urlencoded

email={{testUserEmail}}
&password={{testUserPassword}}
```

**Expected Response:**

- Status: `302 Found` (redirect) or `200 OK`
- Cookie: `connect.sid=...` (auto-saved)

**Auto-saves:**

- ✅ `sessionCookie` → Session valid for 24 hours

**Errors:**

- `401 Unauthorized`: Invalid email or password
- `401 Unauthorized`: Account disabled

---

### 03.3 - Login with Remember Me ⏰

**Purpose:** Extended session (30 days)

**Request:**

```http
POST {{baseUrl}}/login
Content-Type: application/x-www-form-urlencoded

email={{testUserEmail}}
&password={{testUserPassword}}
&rememberMe=on
```

**Expected Response:**

- Status: `302 Found` (redirect) or `200 OK`
- Cookie: `connect.sid=...` with extended expiration

**Auto-saves:**

- ✅ `sessionCookie` → Session valid for 30 days

**Difference from 03.2:**

- Session TTL: 30 days vs 24 hours
- Cookie maxAge extended

---

### 03.4 - Logout 👋

**Purpose:** Destroy session and logout user

**Request:**

```http
GET {{baseUrl}}/logout
Cookie: {{sessionCookie}}
```

**Expected Response:**

- Status: `302 Found` (redirect to login)

**Auto-clears:**

- ✅ `sessionCookie` → Cleared from environment

**Result:**

- Session destroyed in Redis
- Cookie invalidated
- User must login again

---

### 03.5 - Get Login Page (HTML) 📄

**Purpose:** Get login form HTML

**Request:**

```http
GET {{baseUrl}}/login
```

**Expected Response:**

- Status: `200 OK`
- Content-Type: `text/html`
- Body: Login form HTML

**Use case:** Test that login page renders correctly

---

### 03.6 - Get Register Page (HTML) 📄

**Purpose:** Get registration form HTML

**Request:**

```http
GET {{baseUrl}}/register
```

**Expected Response:**

- Status: `200 OK`
- Content-Type: `text/html`
- Body: Registration form HTML

**Use case:** Test that registration page renders correctly

---

## Troubleshooting

### Issue 1: "Unauthorized" or "Session not found"

**Symptoms:**

- 401 Unauthorized responses
- "Session cookie not found" errors

**Causes:**

- Session cookie not sent
- Session expired
- Redis connection lost

**Solutions:**

1. Check `sessionCookie` environment variable is set
2. Re-login using request **01.2** or **03.2**
3. Verify Cookie header is included in requests
4. Check Redis is running: `redis-cli ping` (should return `PONG`)
5. Check session TTL in Redis: `redis-cli ttl sess:...`

---

### Issue 2: "Invalid authorization code"

**Symptoms:**

- `invalid_grant` error when exchanging code (02.5)

**Causes:**

- Authorization code expired (10 min TTL)
- Code already used (single-use)
- Wrong `code_verifier` (doesn't match `code_challenge`)

**Solutions:**

1. Generate new PKCE codes: Run request **02.3**
2. Get new authorization code: Run request **02.4** in browser
3. Verify `codeVerifier` matches original `codeChallenge`
4. Exchange code immediately (within 10 minutes)

---

### Issue 3: "Invalid client credentials"

**Symptoms:**

- `invalid_client` error
- 401 Unauthorized on token endpoint

**Causes:**

- Wrong `clientId` or `clientSecret`
- Client deactivated or deleted
- Public client sending secret

**Solutions:**

1. Verify `clientId` and `clientSecret` in environment variables
2. Check client exists and is active: Request **01.9**
3. For public clients: Don't send `client_secret`
4. Regenerate secret if needed: Request **01.11**

---

### Issue 4: PKCE validation failed

**Symptoms:**

- `invalid_request` error
- "code_challenge required" or "code_verifier required"

**Causes:**

- Missing PKCE parameters
- Wrong `code_verifier` for `code_challenge`

**Solutions:**

1. Always run request **02.3** before OAuth flow
2. Don't manually edit `codeVerifier` or `codeChallenge`
3. Use same environment for entire flow
4. Check `code_challenge_method` is `S256`

---

### Issue 5: "Redirect URI mismatch"

**Symptoms:**

- `invalid_request` error on authorization endpoint
- "redirect_uri not allowed" error

**Causes:**

- Callback URL doesn't match registered redirect URI
- Protocol mismatch (http vs https)
- Trailing slash mismatch

**Solutions:**

1. Check client's `redirectUris`: Request **01.9**
2. Ensure exact match (case-sensitive)
3. Update client redirect URIs: Request **01.10**
4. Common values:
   - Development: `http://localhost:4000/callback`
   - Production: `https://app.example.com/callback`

---

### Issue 6: Token expired

**Symptoms:**

- `invalid_token` error
- 401 Unauthorized on protected endpoints

**Causes:**

- Access token expired (1 hour TTL)
- Refresh token expired (30 days TTL)

**Solutions:**

1. Check token expiration: Request **02.7** (introspect)
2. Refresh access token: Request **02.8**
3. If refresh token expired: Re-authenticate (request **02.4**)
4. Check token `exp` claim (Unix timestamp)

---

### Issue 7: Missing environment variables

**Symptoms:**

- Requests show `{{variableName}}` instead of value
- "Variable not found" errors

**Causes:**

- Environment not selected
- Variables not auto-saved from previous requests
- Manual variable required but not set

**Solutions:**

1. Select "Identity Server Environment" in environment dropdown
2. Run setup requests in order: **01.1** → **01.2** → **01.3** → **01.6**
3. Check test scripts ran successfully (green checkmarks)
4. Manually set `authorizationCode` after browser OAuth flow
5. View environment variables: Click eye icon

---

### Issue 8: Database or Redis errors

**Symptoms:**

- 500 Internal Server Error
- "Database connection failed"
- "Redis connection failed"

**Causes:**

- PostgreSQL not running
- Redis not running
- Connection string misconfigured

**Solutions:**

1. Start PostgreSQL: `brew services start postgresql` (macOS)
2. Start Redis: `redis-server` or `brew services start redis`
3. Check `.env` file:
   ```
   DATABASE_URL=postgresql://user:pass@localhost:5432/dbname
   REDIS_URL=redis://localhost:6379
   ```
4. Test connections:
   ```bash
   psql $DATABASE_URL
   redis-cli ping
   ```

---

### Issue 9: "Invalid scope" error

**Symptoms:**

- `invalid_scope` error on authorization or token endpoint

**Causes:**

- Requested scope not in client's `allowedScopes`
- Typo in scope string
- Wrong scope separator

**Solutions:**

1. Check client's allowed scopes: Request **01.9**
2. Update client scopes: Request **01.10**
3. Use space-separated scopes: `openid email profile`
4. Supported scopes: `openid`, `email`, `profile`

---

### Issue 10: CORS errors in Postman

**Symptoms:**

- CORS errors in console
- Requests blocked

**Note:** Postman should NOT have CORS issues (unlike browsers)

**Solutions:**

1. Disable "SSL certificate verification" in Postman settings (development only)
2. Check Postman interceptor is disabled
3. Use Postman desktop app (not web version)
4. Clear Postman cache: Settings → Data → Clear cache

---

## API Reference

### Base URL

```
http://localhost:3000
```

### Authentication Methods

**1. Session Cookie (Admin & User endpoints)**

```http
Cookie: connect.sid=s%3A...
```

**2. Client Credentials (Token endpoint)**

```http
client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET
```

**3. Bearer Token (UserInfo endpoint)**

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZF9hYmMifQ...
```

### Content Types

**Form Data:**

```http
Content-Type: application/x-www-form-urlencoded
```

**JSON:**

```http
Content-Type: application/json
```

### Status Codes

| Code | Meaning               | When                                   |
| ---- | --------------------- | -------------------------------------- |
| 200  | OK                    | Successful request                     |
| 201  | Created               | Resource created successfully          |
| 204  | No Content            | Successful deletion                    |
| 302  | Found                 | Redirect (login, logout)               |
| 400  | Bad Request           | Invalid parameters or validation error |
| 401  | Unauthorized          | Missing or invalid authentication      |
| 403  | Forbidden             | Insufficient permissions               |
| 404  | Not Found             | Resource not found                     |
| 409  | Conflict              | Resource already exists                |
| 500  | Internal Server Error | Server error                           |

### Error Response Format

```json
{
  "error": "error_code",
  "error_description": "Human-readable error message"
}
```

**OAuth 2.0 Error Codes:**

- `invalid_request` - Missing or invalid parameters
- `invalid_client` - Client authentication failed
- `invalid_grant` - Invalid authorization code or refresh token
- `unauthorized_client` - Client not authorized for grant type
- `unsupported_grant_type` - Grant type not supported
- `invalid_scope` - Invalid or unauthorized scope

---

## Testing Checklist

Use this to verify all functionality:

### Setup ✅

- [ ] Server running at http://localhost:3000
- [ ] Database seeded with admin user
- [ ] Redis running
- [ ] Postman collections imported
- [ ] Environment selected

### Collection 01: Admin Operations ✅

- [ ] 01.1 - Health check passes
- [ ] 01.2 - Admin login successful (cookie saved)
- [ ] 01.3 - Organization created (ID saved)
- [ ] 01.4 - Organizations listed
- [ ] 01.5 - Organization details retrieved
- [ ] 01.6 - Confidential client created (credentials saved)
- [ ] 01.7 - Public client created
- [ ] 01.8 - Clients listed
- [ ] 01.9 - Client details retrieved
- [ ] 01.10 - Client updated
- [ ] 01.11 - Client secret regenerated
- [ ] 01.12 - Organization clients retrieved
- [ ] 01.13 - All keys listed
- [ ] 01.14 - Primary key retrieved
- [ ] 01.15 - Rotation status checked
- [ ] 01.16 - Key rotation triggered
- [ ] 01.17 - Organization updated
- [ ] 01.18 - Client soft deleted
- [ ] 01.19 - Client hard deleted (use with caution)
- [ ] 01.20 - Organization soft deleted
- [ ] 01.21 - Organization hard deleted (use with caution)

### Collection 02: OAuth Flows ✅

- [ ] 02.1 - Discovery document retrieved
- [ ] 02.2 - JWKS retrieved
- [ ] 02.3 - PKCE codes generated (saved to environment)
- [ ] 02.4 - Authorization URL opened in browser
- [ ] 02.4 - User logged in and granted consent
- [ ] 02.4 - Authorization code copied to environment
- [ ] 02.5 - Tokens received (access & refresh saved)
- [ ] 02.6 - User info retrieved with access token
- [ ] 02.7 - Token introspection returned metadata
- [ ] 02.8 - Access token refreshed
- [ ] 02.9 - Client credentials grant successful
- [ ] 02.10 - Access token revoked
- [ ] 02.11 - Refresh token revoked

### Collection 03: User Auth ✅

- [ ] 03.1 - User registered (session saved)
- [ ] 03.2 - User logged in
- [ ] 03.3 - Remember Me login worked
- [ ] 03.4 - Logout successful (session cleared)
- [ ] 03.5 - Login page HTML retrieved
- [ ] 03.6 - Register page HTML retrieved

---

## Advanced Tips

### 1. Using Collection Runner

Run entire collection automatically:

1. Click collection name → **Run**
2. Select requests to run
3. Choose environment
4. Set iterations and delay
5. Click **Run Collection**

**Note:** Request 02.4 (browser OAuth) must be run manually

### 2. Exporting Environment

Save environment for team:

1. Click environment → **...** → **Export**
2. Share JSON file with team
3. **Warning:** Contains secrets! Share securely

### 3. Using Variables in Tests

View variables in test scripts:

```javascript
// Get variable
pm.environment.get('clientId');

// Set variable
pm.environment.set('myVar', 'value');

// Clear variable
pm.environment.unset('myVar');
```

### 4. Debugging Requests

View full request/response:

1. Click request → **Console** (bottom left)
2. View request headers, body, response
3. Check test script execution
4. View variable values

### 5. Using Newman (CLI)

Run collections from command line:

```bash
# Install Newman
npm install -g newman

# Run collection
newman run postman/01-admin-collection.json \
  -e postman/environment.json \
  --reporters cli,json \
  --reporter-json-export results.json

# Run with environment variables
newman run postman/01-admin-collection.json \
  -e postman/environment.json \
  --env-var "baseUrl=http://localhost:3000"
```

---

## Summary

**Total API Endpoints: 38 requests**

**Collections:**

1. **Admin & Setup** (21 requests) - Organizations, clients, keys
2. **OAuth 2.0 Flows** (11 requests) - Authorization, tokens, OIDC
3. **User Authentication** (6 requests) - Registration, login, logout

**Recommended Testing Order:**

1. Run 01.1-01.6 (setup)
2. Run 02.1-02.11 (OAuth flow)
3. Run 03.1-03.6 (user auth)

**Auto-saved Variables:**

- Session cookies
- Client credentials
- OAuth tokens
- Resource IDs

**Manual Steps:**

- Only request 02.4 requires browser interaction
- Copy authorization code to environment

For web UI testing, see **UI_TESTING_GUIDE.md**
