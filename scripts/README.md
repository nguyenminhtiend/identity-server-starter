# Testing Scripts

This directory contains automated testing scripts for the Identity Server.

## Available Scripts

### `test-api.sh`

Automated API endpoint testing using curl.

**Tests:**

- Health check
- OIDC discovery & JWKS
- User authentication
- Admin endpoints (organizations, clients, keys)

**Usage:**

```bash
./scripts/test-api.sh
```

### `test-oauth-flow.sh`

Interactive OAuth 2.0 authorization code flow testing.

**Features:**

- Auto-creates test client if needed
- Generates PKCE challenge for public clients
- Guides through manual authorization
- Tests token exchange and UserInfo

**Usage:**

```bash
# Basic usage
./scripts/test-oauth-flow.sh

# With existing client
export CLIENT_ID="your_client_id"
export CLIENT_SECRET="your_client_secret"
./scripts/test-oauth-flow.sh
```

## Environment Variables

```bash
# Server configuration
export BASE_URL="http://localhost:3000"

# Test credentials
export TEST_EMAIL="test@example.com"
export TEST_PASSWORD="Test123456!"

# OAuth client (for test-oauth-flow.sh)
export CLIENT_ID="your_client_id"
export CLIENT_SECRET="your_client_secret"
export REDIRECT_URI="http://localhost:3001/callback"
```

## Prerequisites

- `curl` - HTTP client
- `openssl` - For PKCE generation
- `python3` - For JSON formatting (optional)
- `jq` - For JSON parsing (optional)

## Quick Start

1. **Start the server:**

   ```bash
   pnpm dev
   ```

2. **Run basic tests:**

   ```bash
   ./scripts/test-api.sh
   ```

3. **Test OAuth flow:**
   ```bash
   ./scripts/test-oauth-flow.sh
   ```

See [TESTING_QUICK_START.md](../TESTING_QUICK_START.md) for detailed testing guide.
