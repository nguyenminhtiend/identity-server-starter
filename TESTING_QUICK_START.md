# API Testing Quick Start Guide

This guide helps you test the Identity Server APIs using automated scripts.

## 📋 Prerequisites

- Server running at `http://localhost:3000`
- Database seeded with test user
- Terminal/command line access

## 🚀 Quick Start

### 1. Run Basic API Tests

Test all main endpoints with one command:

```bash
./scripts/test-api.sh
```

This will test:

- ✅ Health check endpoint
- ✅ OIDC discovery & JWKS
- ✅ User login/logout
- ✅ Admin endpoints (organizations, clients, keys)

**Expected output:**

```
========================================
Identity Server API Testing
========================================

[1/10] Testing Health Endpoint...
✓ Health check passed
   Response: {"status":"ok","timestamp":"..."}

[2/10] Testing OIDC Discovery Endpoint...
✓ OIDC Discovery successful
   Issuer: http://localhost:3000

...

✓ API Testing Complete!
```

### 2. Test OAuth 2.0 Flow

Test the complete OAuth authorization code flow:

```bash
./scripts/test-oauth-flow.sh
```

This script will:

1. Create a test OAuth client (if needed)
2. Generate authorization URL
3. Guide you through the manual authorization step
4. Exchange code for tokens
5. Test UserInfo endpoint

**Interactive flow:**

```
Do you want to continue with automated testing? (y/n) y
Please enter the authorization code from the redirect URL:
> [paste code here]

✓ Token exchange successful
✓ UserInfo retrieved
```

## 📝 Test Credentials

### Test User

- **Email:** `test@example.com`
- **Password:** `Test123456!`

## 🔧 Environment Variables

You can customize the test configuration:

```bash
# Change base URL
export BASE_URL="http://localhost:3000"

# For OAuth flow testing (after creating a client)
export CLIENT_ID="your_client_id"
export CLIENT_SECRET="your_client_secret"
export REDIRECT_URI="http://localhost:3001/callback"

# Run tests
./scripts/test-api.sh
```

## 📊 What to Test Next

### 1. Basic Functionality ✅

- [x] Health check
- [x] User login/logout
- [x] Home page access

### 2. OIDC Endpoints

```bash
# Discovery
curl http://localhost:3000/.well-known/openid-configuration | jq

# JWKS (public keys)
curl http://localhost:3000/.well-known/jwks.json | jq
```

### 3. Admin API

#### Create an Organization

```bash
# Login first and save cookie
curl -c cookies.txt -X POST http://localhost:3000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=test@example.com&password=Test123456!"

# Create organization
curl -b cookies.txt -X POST http://localhost:3000/admin/organizations \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Test Org",
    "slug": "my-test-org"
  }'
```

#### Create an OAuth Client

```bash
curl -b cookies.txt -X POST http://localhost:3000/admin/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "clientType": "confidential",
    "redirectUris": ["http://localhost:3001/callback"],
    "grantTypes": ["authorization_code", "refresh_token"],
    "allowedScopes": "openid profile email"
  }'
```

**Save the `clientId` and `clientSecret` from the response!**

### 4. OAuth 2.0 Authorization Flow

#### Step 1: Get Authorization Code

Open in browser:

```
http://localhost:3000/oauth/authorize?client_id=YOUR_CLIENT_ID&response_type=code&redirect_uri=http://localhost:3001/callback&scope=openid%20profile%20email&state=random123
```

Login and approve consent. Copy the `code` from the redirect URL.

#### Step 2: Exchange Code for Tokens

```bash
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE" \
  -d "redirect_uri=http://localhost:3001/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

#### Step 3: Use Access Token

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:3000/oauth/userinfo
```

#### Step 4: Refresh Token

```bash
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"
```

### 5. Token Management

#### Introspect Token

```bash
curl -X POST http://localhost:3000/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -d "token=YOUR_ACCESS_TOKEN"
```

#### Revoke Token

```bash
curl -X POST http://localhost:3000/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -d "token=YOUR_REFRESH_TOKEN"
```

## 🐛 Troubleshooting

### Login fails with "Invalid email or password"

- Verify database is seeded: `pnpm db:seed`
- Check credentials: `test@example.com` / `Test123456!`

### Admin endpoints return 401

- Make sure you're logged in (cookie saved)
- Session might have expired, login again

### OAuth flow fails

- Verify client credentials are correct
- Check redirect URI matches exactly
- Ensure client is active in database

## 📚 Using Postman

For more detailed testing, import the Postman collections:

1. Open Postman
2. Import files from `postman/` directory:
   - `environment.json`
   - `01-admin-collection.json`
   - `02-oauth-flow-collection.json`
   - `03-user-auth-collection.json`
3. Select "Identity Server Environment"
4. Run requests in order

See [API_TESTING_GUIDE.md](./docs/API_TESTING_GUIDE.md) for detailed Postman instructions.

## 🎯 Testing Checklist

- [ ] Health check endpoint
- [ ] OIDC discovery & JWKS
- [ ] User registration
- [ ] User login/logout
- [ ] Create organization
- [ ] Create OAuth client (confidential)
- [ ] Create OAuth client (public with PKCE)
- [ ] Authorization code flow
- [ ] Token refresh
- [ ] Token introspection
- [ ] Token revocation
- [ ] UserInfo endpoint
- [ ] Key rotation
- [ ] Client secret regeneration

## 💡 Tips

1. **Use `jq` for JSON formatting:**

   ```bash
   curl http://localhost:3000/health | jq
   ```

2. **Save cookies for session:**

   ```bash
   curl -c cookies.txt ...  # Save cookies
   curl -b cookies.txt ...  # Use cookies
   ```

3. **Follow redirects:**

   ```bash
   curl -L http://localhost:3000/login
   ```

4. **See full request/response:**
   ```bash
   curl -v http://localhost:3000/health
   ```
