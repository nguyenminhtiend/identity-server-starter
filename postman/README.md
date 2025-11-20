# Postman Collections for Identity Server

This directory contains complete Postman collections for testing the Identity Server API.

## Quick Start

### 1. Import to Postman

Import all files in this directory:

1. Open Postman
2. Click **Import** button
3. Select all JSON files from this directory:
   - `environment.json`
   - `01-admin-collection.json`
   - `02-oauth-flow-collection.json`
   - `03-user-auth-collection.json`
4. Click **Import**

### 2. Select Environment

1. Click the environment dropdown (top right)
2. Select **"Identity Server Environment"**
3. Verify `baseUrl` is set to `http://localhost:3000`

### 3. Start Testing

Run collections in order:

1. **Collection 01** - Admin & Setup (requests 01.1 - 01.6)
2. **Collection 02** - OAuth Flows (requests 02.1 - 02.11)
3. **Collection 03** - User Authentication (requests 03.1 - 03.6)

## Collections Overview

### Collection 01: Admin & Setup (21 requests)

Sets up test environment with organizations and OAuth clients.

**Key Requests:**

- 01.2 - Admin Login (get session cookie)
- 01.3 - Create Organization
- 01.6 - Create Confidential Client (saves clientId & clientSecret)
- 01.13-01.16 - Key management

**Auto-saved Variables:**

- `sessionCookie`
- `organizationId`
- `clientId`
- `clientSecret`

### Collection 02: OAuth 2.0 & OIDC (11 requests)

Tests complete OAuth 2.0 authorization code flow with PKCE.

**Key Requests:**

- 02.1 - OIDC Discovery
- 02.3 - Generate PKCE codes (required before OAuth flow)
- 02.4 - Start authorization (open in browser)
- 02.5 - Exchange code for tokens
- 02.6 - Get user info

**Manual Steps:**

- Request 02.4: Copy URL to browser, complete login/consent, copy authorization code to environment

**Auto-saved Variables:**

- `codeVerifier`
- `codeChallenge`
- `accessToken`
- `refreshToken`

### Collection 03: User Authentication (6 requests)

Tests user registration, login, and session management.

**Key Requests:**

- 03.1 - Register new user
- 03.2 - Login
- 03.3 - Login with Remember Me
- 03.4 - Logout

**Auto-saved Variables:**

- `sessionCookie`

## Environment Variables

| Variable            | Auto-filled? | Description                                 |
| ------------------- | ------------ | ------------------------------------------- |
| `baseUrl`           | No           | Server URL (default: http://localhost:3000) |
| `adminEmail`        | No           | Admin email (default: admin@example.com)    |
| `adminPassword`     | No           | Admin password (default: Admin123!)         |
| `testUserEmail`     | No           | Test user email                             |
| `testUserPassword`  | No           | Test user password                          |
| `sessionCookie`     | Yes          | Session cookie for authenticated requests   |
| `clientId`          | Yes          | OAuth client ID                             |
| `clientSecret`      | Yes          | OAuth client secret                         |
| `authorizationCode` | **Manual**   | Auth code from browser OAuth flow           |
| `accessToken`       | Yes          | OAuth access token                          |
| `refreshToken`      | Yes          | OAuth refresh token                         |
| `organizationId`    | Yes          | Organization ID                             |
| `publicClientId`    | Yes          | Public client ID                            |
| `codeVerifier`      | Yes          | PKCE code verifier                          |
| `codeChallenge`     | Yes          | PKCE code challenge                         |

**Note:** Only `authorizationCode` requires manual input during the OAuth flow (request 02.4).

## Testing Order

### First Time Setup (Run Once)

Execute in order:

1. ✅ **01.1** - Health Check
2. ✅ **01.2** - Admin Login
3. ✅ **01.3** - Create Organization
4. ✅ **01.6** - Create Confidential Client

After this, your environment has:

- Active admin session
- Organization created
- OAuth client with credentials

### OAuth Flow Testing

Execute in order:

1. ✅ **02.1** - OIDC Discovery
2. ✅ **02.2** - Get JWKS
3. ✅ **02.3** - Generate PKCE codes
4. 🌐 **02.4** - Start Authorization (BROWSER)
   - Copy full URL
   - Open in browser
   - Login and consent
   - Copy `code` from callback URL
   - Paste to `authorizationCode` variable
5. ✅ **02.5** - Exchange code for tokens
6. ✅ **02.6** - Get user info
7. ✅ **02.7** - Introspect token
8. ✅ **02.8** - Refresh token

### Full Test Suite

Run all requests in numerical order from 01.1 to 03.6.

## Common Issues

### "Unauthorized" or "Session not found"

**Solution:** Re-run request **01.2** (Admin Login) to get fresh session cookie.

### "Invalid authorization code"

**Causes:**

- Code expired (10 min TTL)
- Code already used (single-use only)
- Wrong code_verifier

**Solution:** Re-run OAuth flow from request **02.3**.

### "Invalid client credentials"

**Solution:** Verify `clientId` and `clientSecret` in environment variables match created client.

### Missing PKCE codes

**Solution:** Run request **02.3** before starting OAuth flow.

## Test Scripts

Collections include automatic test scripts that:

1. ✅ Verify response status codes
2. 💾 Save values to environment variables
3. 📝 Log important information to console
4. ✅ Validate response structure

View test results in the **Test Results** tab after each request.

## Advanced Usage

### Running Collections with Newman

Install Newman (Postman CLI):

```bash
npm install -g newman
```

Run collection:

```bash
newman run 01-admin-collection.json -e environment.json
```

### Automated Testing

Collections can be run in CI/CD pipelines:

```bash
# Install Newman
npm install -g newman

# Run all collections
newman run 01-admin-collection.json -e environment.json
newman run 02-oauth-flow-collection.json -e environment.json
newman run 03-user-auth-collection.json -e environment.json
```

**Note:** Request 02.4 (browser authorization flow) cannot be automated and must be run manually.

## Additional Resources

- **Full Testing Guide:** See `TESTING_GUIDE.md` in project root
- **API Documentation:** See project README
- **OAuth 2.0 Spec:** https://oauth.net/2/
- **OpenID Connect:** https://openid.net/connect/

## Support

For issues or questions:

1. Check `TESTING_GUIDE.md` troubleshooting section
2. Verify server is running: `pnpm dev`
3. Check environment variables are set correctly
4. Review Postman console for detailed error messages
