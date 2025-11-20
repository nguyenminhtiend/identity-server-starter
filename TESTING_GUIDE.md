# Testing Guide - Identity Server Starter

This guide provides comprehensive instructions for testing the Identity Server using both Postman (API testing) and web browser (UI testing).

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Postman Setup](#postman-setup)
3. [Postman Testing Order](#postman-testing-order)
4. [Web UI Testing](#web-ui-testing)
5. [Common Issues & Troubleshooting](#common-issues--troubleshooting)

---

## Prerequisites

### Required Software

- Node.js (v18 or higher)
- pnpm package manager
- PostgreSQL database
- Redis server
- Postman (for API testing)
- Modern web browser (Chrome, Firefox, or Edge)

### Environment Setup

1. **Start the server:**

   ```bash
   pnpm dev
   ```

2. **Verify server is running:**
   - Server should be accessible at `http://localhost:3000`
   - Check health endpoint: `http://localhost:3000/health`

3. **Database seeding:**
   The database should be seeded with an admin user:
   - Email: `admin@example.com`
   - Password: `Admin123!`

---

## Postman Setup

### 1. Import Postman Collections

Import all three collection files from the `postman/` directory:

1. **`environment.json`** - Environment variables
2. **`01-admin-collection.json`** - Admin & Setup endpoints
3. **`02-oauth-flow-collection.json`** - OAuth 2.0 & OIDC flows
4. **`03-user-auth-collection.json`** - User authentication

### 2. Configure Environment

After importing, select the "Identity Server Environment" from the environment dropdown in Postman.

#### Environment Variables:

| Variable            | Default Value           | Description                               |
| ------------------- | ----------------------- | ----------------------------------------- |
| `baseUrl`           | `http://localhost:3000` | Server URL                                |
| `adminEmail`        | `admin@example.com`     | Admin user email                          |
| `adminPassword`     | `Admin123!`             | Admin user password                       |
| `testUserEmail`     | `testuser@example.com`  | Test user email                           |
| `testUserPassword`  | `TestUser123!`          | Test user password                        |
| `sessionCookie`     | (auto-filled)           | Session cookie for authenticated requests |
| `clientId`          | (auto-filled)           | OAuth client ID                           |
| `clientSecret`      | (auto-filled)           | OAuth client secret                       |
| `authorizationCode` | (manual)                | Authorization code from OAuth flow        |
| `accessToken`       | (auto-filled)           | OAuth access token                        |
| `refreshToken`      | (auto-filled)           | OAuth refresh token                       |
| `organizationId`    | (auto-filled)           | Organization ID                           |

**Note:** Variables marked "(auto-filled)" are automatically populated by test scripts. Only `authorizationCode` needs manual input during the OAuth flow.

---

## Postman Testing Order

Follow this sequence to test all functionality systematically:

### Collection 01: Admin & Setup (START HERE)

This collection sets up your test environment with clients and organizations.

#### **01.1 - Health Check**

- **Purpose:** Verify server is running
- **Expected:** `200 OK` with `{"status": "ok"}`

#### **01.2 - Admin Login (Get Session)**

- **Purpose:** Authenticate as admin user
- **Expected:** `302` redirect or `200 OK`
- **Auto-saves:** `sessionCookie` to environment
- **Action:** Session cookie is now available for admin endpoints

#### **01.3 - Create Organization**

- **Purpose:** Create a test organization
- **Expected:** `201 Created`
- **Auto-saves:** `organizationId` to environment
- **Response example:**
  ```json
  {
    "id": "org_123",
    "name": "Test Organization",
    "slug": "test-org"
  }
  ```

#### **01.4 - List Organizations**

- **Purpose:** View all organizations
- **Expected:** `200 OK` with array of organizations
- **Query params:** `limit`, `offset`, `isActive` (optional)

#### **01.5 - Get Organization Details**

- **Purpose:** View specific organization
- **Expected:** `200 OK` with organization details

#### **01.6 - Create Confidential Client** ⭐ IMPORTANT

- **Purpose:** Create OAuth client for authorization code flow
- **Expected:** `201 Created`
- **Auto-saves:** `clientId` and `clientSecret` to environment
- **⚠️ WARNING:** Client secret is only shown once! Save it securely.
- **Response example:**
  ```json
  {
    "clientId": "client_abc123",
    "clientSecret": "secret_xyz789",
    "name": "Test Confidential Client",
    "clientType": "confidential"
  }
  ```

#### **01.7 - Create Public Client**

- **Purpose:** Create OAuth client for SPAs/mobile apps
- **Expected:** `201 Created`
- **Auto-saves:** `publicClientId` to environment
- **Note:** Public clients don't receive a secret

#### **01.8 - List All Clients**

- **Purpose:** View all OAuth clients
- **Expected:** `200 OK` with array of clients
- **Filters:** `organizationId`, `clientType`, `isActive`

#### **01.9 - Get Client Details**

- **Purpose:** View specific client details
- **Expected:** `200 OK` with client information

#### **01.10 - Update Client**

- **Purpose:** Modify client configuration
- **Expected:** `200 OK`
- **Fields:** `name`, `redirectUris`, `allowedScopes`, etc.

#### **01.11 - Regenerate Client Secret**

- **Purpose:** Create new secret for confidential client
- **Expected:** `200 OK` with new secret
- **Auto-saves:** New `clientSecret` to environment
- **⚠️ WARNING:** Old secret is invalidated immediately!

#### **01.12 - Get Organization Clients**

- **Purpose:** List all clients in an organization
- **Expected:** `200 OK` with array of clients

#### **01.13 - List All Keys**

- **Purpose:** View all JWT signing keys
- **Expected:** `200 OK` with array of keys
- **Response includes:** Public keys, key IDs, algorithms, expiration dates

#### **01.14 - Get Primary Key**

- **Purpose:** Get current active signing key
- **Expected:** `200 OK` with primary key metadata

#### **01.15 - Get Key Rotation Status**

- **Purpose:** Check next scheduled key rotation
- **Expected:** `200 OK` with rotation timestamp

#### **01.16 - Trigger Key Rotation**

- **Purpose:** Manually rotate signing keys
- **Expected:** `200 OK`
- **Body:** `{"confirm": true}`
- **Result:** New key generated and set as primary

#### **01.17 - Update Organization**

- **Purpose:** Modify organization details
- **Expected:** `200 OK`

#### **01.18 - Deactivate Client (Soft Delete)**

- **Purpose:** Deactivate client without permanent deletion
- **Expected:** `204 No Content`

#### **01.19 - Delete Client Permanently**

- **Purpose:** Permanently remove client
- **Expected:** `204 No Content`
- **Query:** `?hard=true`
- **⚠️ WARNING:** This action cannot be undone!

#### **01.20 - Deactivate Organization (Soft Delete)**

- **Purpose:** Deactivate organization
- **Expected:** `204 No Content`

#### **01.21 - Delete Organization Permanently**

- **Purpose:** Permanently remove organization
- **Expected:** `204 No Content`
- **Query:** `?hard=true`

---

### Collection 02: OAuth 2.0 & OIDC Flows

This collection tests the complete OAuth 2.0 authorization flow with PKCE.

#### **02.1 - OIDC Discovery**

- **Purpose:** Get OpenID Connect metadata
- **Expected:** `200 OK` with discovery document
- **Contains:** Endpoint URLs, supported scopes, grant types, algorithms

#### **02.2 - Get JWKS (Public Keys)**

- **Purpose:** Get public keys for JWT verification
- **Expected:** `200 OK` with JWKS
- **Use case:** Verify JWT signatures from external applications

#### **02.3 - Generate PKCE Code Verifier & Challenge** ⭐ REQUIRED

- **Purpose:** Generate PKCE parameters for authorization flow
- **Expected:** `200 OK`
- **Auto-generates:**
  - `codeVerifier` - Random 43-128 character string
  - `codeChallenge` - SHA256 hash of verifier
- **Action:** These are now ready for the authorization flow
- **Note:** Run this BEFORE starting authorization flow

#### **02.4 - Start Authorization Flow (Browser Required)** 🌐 MANUAL STEP

- **Purpose:** Initiate OAuth authorization
- **Method:** Copy the full URL and open in browser
- **Flow:**
  1. Copy request URL from Postman
  2. Open URL in browser
  3. You'll be redirected to login (if not logged in)
  4. After login, you'll see consent page
  5. Approve the requested scopes
  6. You'll be redirected to callback URL with authorization code

- **Callback URL example:**

  ```
  http://localhost:4000/callback?code=AUTH_CODE_HERE&state=random_state_123
  ```

- **⚠️ ACTION REQUIRED:** Copy the `code` parameter value and manually set it as the `authorizationCode` environment variable in Postman

#### **02.5 - Exchange Authorization Code for Tokens**

- **Purpose:** Exchange auth code for access & refresh tokens
- **Expected:** `200 OK`
- **Auto-saves:** `accessToken` and `refreshToken` to environment
- **Response example:**
  ```json
  {
    "access_token": "eyJhbGc...",
    "refresh_token": "rt_abc123...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "openid email profile"
  }
  ```

#### **02.6 - Get User Info (with Access Token)**

- **Purpose:** Get authenticated user profile
- **Expected:** `200 OK` with user claims
- **Headers:** `Authorization: Bearer {{accessToken}}`
- **Response based on scopes:**
  - `openid` → `sub` (user ID)
  - `email` → `email`, `email_verified`
  - `profile` → `name` (derived from email)

#### **02.7 - Introspect Access Token**

- **Purpose:** Check token metadata and validity
- **Expected:** `200 OK` with introspection response
- **Response example:**
  ```json
  {
    "active": true,
    "scope": "openid email profile",
    "client_id": "client_abc123",
    "exp": 1700000000,
    "iat": 1699996400
  }
  ```

#### **02.8 - Refresh Access Token**

- **Purpose:** Get new access token without user interaction
- **Expected:** `200 OK`
- **Auto-saves:** New `accessToken` and `refreshToken`
- **Use case:** When access token expires

#### **02.9 - Client Credentials Grant**

- **Purpose:** Machine-to-machine authentication
- **Expected:** `200 OK` with access token
- **Use case:** Backend services authenticating without a user

#### **02.10 - Revoke Access Token**

- **Purpose:** Invalidate access token
- **Expected:** `200 OK`
- **Result:** Token is no longer valid

#### **02.11 - Revoke Refresh Token**

- **Purpose:** Invalidate refresh token
- **Expected:** `200 OK`
- **Result:** Refresh token and associated access tokens invalidated

---

### Collection 03: User Authentication

This collection tests user registration, login, and session management.

#### **03.1 - Register New User**

- **Purpose:** Create new user account
- **Expected:** `302` redirect or `200 OK`
- **Auto-saves:** `sessionCookie` to environment
- **Body:**
  - `email`: New user email
  - `password`: Strong password
  - `confirmPassword`: Must match password
- **Result:** User created and automatically logged in

#### **03.2 - Login Existing User**

- **Purpose:** Authenticate with credentials
- **Expected:** `302` redirect or `200 OK`
- **Auto-saves:** `sessionCookie` to environment
- **Session duration:** 24 hours (default)

#### **03.3 - Login with Remember Me**

- **Purpose:** Extended session login
- **Expected:** `302` redirect or `200 OK`
- **Body includes:** `rememberMe=on`
- **Session duration:** 30 days

#### **03.4 - Logout**

- **Purpose:** End current session
- **Expected:** `302` redirect or `200 OK`
- **Auto-clears:** `sessionCookie` from environment
- **Result:** Session destroyed in Redis

#### **03.5 - Get Login Page (HTML)**

- **Purpose:** View login form
- **Expected:** `200 OK` with HTML

#### **03.6 - Get Register Page (HTML)**

- **Purpose:** View registration form
- **Expected:** `200 OK` with HTML

---

## Web UI Testing

This section covers manual testing through the web browser interface.

### Prerequisites

- Server running at `http://localhost:3000`
- Admin user seeded in database
- OAuth client created (via Postman or admin API)

---

### Test Scenario 1: User Registration & Login Flow

#### Step 1: Register New User

1. Navigate to `http://localhost:3000/register`
2. Fill in registration form:
   - **Email:** `newuser@example.com`
   - **Password:** `SecurePass123!`
   - **Confirm Password:** `SecurePass123!`
3. Click "Register"
4. **Expected:** Redirected to home page or dashboard
5. **Verify:** User is logged in (check for session)

#### Step 2: Logout

1. Navigate to `http://localhost:3000/logout`
2. **Expected:** Redirected to login page
3. **Verify:** Session cleared (no longer authenticated)

#### Step 3: Login

1. Navigate to `http://localhost:3000/login`
2. Fill in login form:
   - **Email:** `newuser@example.com`
   - **Password:** `SecurePass123!`
3. Optional: Check "Remember Me" for extended session
4. Click "Login"
5. **Expected:** Redirected to home page or dashboard
6. **Verify:** User is authenticated

---

### Test Scenario 2: OAuth 2.0 Authorization Code Flow (Browser)

This tests the complete OAuth flow as a user would experience it.

#### Setup: Create Test Client

Use Postman Collection 01 request **01.6** to create a confidential client with:

- Redirect URI: `http://localhost:4000/callback`
- Allowed scopes: `openid email profile`

Save the `clientId` and `clientSecret`.

#### Step 1: Initiate Authorization Request

Open browser and navigate to:

```
http://localhost:3000/oauth/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:4000/callback&response_type=code&scope=openid%20email%20profile&state=test123&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256
```

Replace:

- `YOUR_CLIENT_ID` - Your client ID from setup
- `YOUR_CODE_CHALLENGE` - Generate using Postman request **02.3**

#### Step 2: Login (if not authenticated)

1. You'll be redirected to login page
2. Enter credentials (admin or test user)
3. Click "Login"
4. **Expected:** Redirected to consent page

#### Step 3: Grant Consent

1. Review requested scopes:
   - ✅ Access your email address
   - ✅ Access your profile information
2. Click "Allow" or "Authorize"
3. **Expected:** Redirected to callback URL with authorization code

#### Step 4: Verify Callback

1. Browser shows: `http://localhost:4000/callback?code=AUTH_CODE&state=test123`
2. Copy the `code` parameter value
3. **Expected:** Authorization code is a long alphanumeric string

#### Step 5: Exchange Code for Tokens

Use Postman Collection 02 request **02.5**:

1. Set `authorizationCode` environment variable to copied code
2. Send request
3. **Expected:** Receive access token and refresh token

---

### Test Scenario 3: OpenID Connect Discovery

#### Step 1: Get Discovery Document

1. Navigate to: `http://localhost:3000/.well-known/openid-configuration`
2. **Expected:** JSON document with server metadata
3. **Verify fields:**
   - `issuer`: `http://localhost:3000`
   - `authorization_endpoint`: `http://localhost:3000/oauth/authorize`
   - `token_endpoint`: `http://localhost:3000/oauth/token`
   - `userinfo_endpoint`: `http://localhost:3000/oauth/userinfo`
   - `jwks_uri`: `http://localhost:3000/.well-known/jwks.json`

#### Step 2: Get JWKS (Public Keys)

1. Navigate to: `http://localhost:3000/.well-known/jwks.json`
2. **Expected:** JSON with array of public keys
3. **Verify:** Keys include `kid`, `kty`, `alg`, `n`, `e` parameters

---

### Test Scenario 4: Admin Operations (Browser)

**Note:** Admin operations are primarily designed for API use. For UI testing, use Postman.

#### Using Browser Developer Tools:

1. Open DevTools (F12)
2. Go to "Network" tab
3. Perform admin login via Postman to get session cookie
4. Use "Console" to make fetch requests with session cookie

Example (in browser console):

```javascript
// Create organization
fetch('http://localhost:3000/admin/organizations', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  credentials: 'include', // Include cookies
  body: JSON.stringify({
    name: 'Browser Test Org',
    slug: 'browser-test',
    ownerUserId: 'admin-user-id',
  }),
})
  .then((r) => r.json())
  .then(console.log);
```

---

## Common Issues & Troubleshooting

### Issue 1: "Session cookie not found" or "Unauthorized"

**Cause:** Session cookie not sent or expired

**Solutions:**

1. **Postman:** Ensure `sessionCookie` environment variable is set
2. **Postman:** Check that Cookie header is included: `Cookie: {{sessionCookie}}`
3. Re-login using Collection 01 request **01.2** or Collection 03 request **03.2**
4. Verify Redis is running (sessions stored in Redis)

### Issue 2: "Invalid authorization code"

**Cause:** Authorization code expired or already used

**Solutions:**

1. Authorization codes expire after 10 minutes
2. Codes are single-use only (cannot reuse)
3. Generate new code by repeating OAuth flow (request **02.4**)
4. Verify `code_verifier` matches original `code_challenge`

### Issue 3: "Invalid client credentials"

**Cause:** Wrong client ID or secret

**Solutions:**

1. Verify `clientId` and `clientSecret` in environment variables
2. Regenerate secret using request **01.11**
3. Ensure client type is correct (confidential vs public)
4. Check client is active (not deactivated)

### Issue 4: "PKCE code challenge required"

**Cause:** Missing PKCE parameters in authorization request

**Solutions:**

1. Run request **02.3** to generate PKCE codes
2. Ensure `code_challenge` and `code_challenge_method` are in authorization URL
3. Use correct `code_verifier` when exchanging authorization code

### Issue 5: "Redirect URI mismatch"

**Cause:** Callback URL doesn't match registered redirect URI

**Solutions:**

1. Check client configuration (request **01.9**)
2. Verify `redirect_uri` in authorization request exactly matches registered URI
3. URIs are case-sensitive and must match protocol (http/https)
4. Update client redirect URIs using request **01.10**

### Issue 6: Token expired

**Cause:** Access token past expiration time

**Solutions:**

1. Use refresh token to get new access token (request **02.8**)
2. Check token expiration using introspection (request **02.7**)
3. Re-authenticate if refresh token also expired

### Issue 7: Database connection errors

**Cause:** PostgreSQL not running or connection misconfigured

**Solutions:**

1. Verify PostgreSQL is running
2. Check `DATABASE_URL` in `.env` file
3. Run migrations: `pnpm db:push`
4. Check database credentials

### Issue 8: Redis connection errors

**Cause:** Redis server not running

**Solutions:**

1. Start Redis: `redis-server`
2. Check `REDIS_URL` in `.env` file
3. Verify Redis is accessible on configured host/port

### Issue 9: "Invalid scope" error

**Cause:** Requested scope not allowed for client

**Solutions:**

1. Check client's `allowedScopes` (request **01.9**)
2. Update client scopes using request **01.10**
3. Verify scope string format (space-separated, e.g., `openid email profile`)

### Issue 10: CORS errors in browser

**Cause:** Cross-origin request blocked

**Solutions:**

1. Ensure client and server on same origin for browser testing
2. Check CORS configuration in server settings
3. Use Postman for API testing (no CORS restrictions)

---

## Testing Checklist

Use this checklist to verify all functionality:

### Admin Operations

- [ ] Health check passes
- [ ] Admin login successful
- [ ] Organization CRUD operations work
- [ ] Client creation (confidential) works
- [ ] Client creation (public) works
- [ ] Client listing and filtering work
- [ ] Client update works
- [ ] Client secret regeneration works
- [ ] Client soft delete works
- [ ] Client hard delete works
- [ ] Key management operations work
- [ ] Key rotation works

### OAuth 2.0 & OIDC

- [ ] OIDC discovery endpoint returns metadata
- [ ] JWKS endpoint returns public keys
- [ ] PKCE code generation works
- [ ] Authorization flow initiates correctly
- [ ] User login during OAuth flow works
- [ ] Consent page displays correctly
- [ ] Authorization code exchange works
- [ ] Access token works for UserInfo endpoint
- [ ] Token introspection returns correct data
- [ ] Token refresh works
- [ ] Client credentials grant works
- [ ] Token revocation works

### User Authentication

- [ ] User registration works
- [ ] Duplicate email validation works
- [ ] Password validation works
- [ ] Login with valid credentials works
- [ ] Login with invalid credentials fails
- [ ] Remember Me extends session
- [ ] Logout destroys session
- [ ] Session persistence works

### Web UI

- [ ] Login page renders correctly
- [ ] Registration page renders correctly
- [ ] Consent page renders correctly
- [ ] OAuth flow completes in browser
- [ ] Error messages display properly
- [ ] Redirects work correctly

---

## Next Steps

After completing all tests:

1. **Integration Testing:** Test with real OAuth clients (web apps, mobile apps)
2. **Performance Testing:** Load test with multiple concurrent users
3. **Security Testing:** Verify all endpoints require proper authentication
4. **Documentation:** Document any custom flows or additional endpoints
5. **Monitoring:** Set up logging and monitoring for production

---

## Additional Resources

- **OAuth 2.0 Specification:** https://oauth.net/2/
- **OpenID Connect Specification:** https://openid.net/connect/
- **PKCE RFC:** https://tools.ietf.org/html/rfc7636
- **Project README:** See main repository README for setup instructions
