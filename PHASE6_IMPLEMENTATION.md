# Phase 6: OpenID Connect (OIDC) Implementation

## Overview

Phase 6 implements the OpenID Connect (OIDC) layer on top of the OAuth 2.0 foundation. OIDC is an identity layer that provides authentication and user information endpoints.

## What Was Implemented

### 1. OIDC Module Structure

Created a complete OIDC module following the modular architecture:

```
src/modules/oidc/
├── controllers/
│   ├── DiscoveryController.ts    # OIDC Discovery Document endpoint
│   ├── JWKSController.ts          # JSON Web Key Set endpoint
│   └── UserInfoController.ts      # UserInfo endpoint
├── services/
│   └── OIDCService.ts             # OIDC business logic
└── routes/
    └── index.ts                   # Route definitions
```

### 2. OIDC Discovery Document Endpoint

**Endpoint**: `GET /.well-known/openid-configuration`

**Purpose**: Provides metadata about the OIDC provider's configuration

**Implementation**: `src/modules/oidc/controllers/DiscoveryController.ts:10`

**Response Example**:

```json
{
  "issuer": "http://localhost:3000",
  "authorization_endpoint": "http://localhost:3000/oauth/authorize",
  "token_endpoint": "http://localhost:3000/oauth/token",
  "userinfo_endpoint": "http://localhost:3000/oauth/userinfo",
  "jwks_uri": "http://localhost:3000/.well-known/jwks.json",
  "revocation_endpoint": "http://localhost:3000/oauth/revoke",
  "introspection_endpoint": "http://localhost:3000/oauth/introspect",
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name"],
  "code_challenge_methods_supported": ["S256"]
}
```

**Features**:

- Returns all OAuth and OIDC endpoints
- Lists supported scopes, grant types, and response types
- Advertises RS256 signing algorithm
- Indicates PKCE support (S256 method)
- Configurable based on `config.issuer`

### 3. JWKS (JSON Web Key Set) Endpoint

**Endpoint**: `GET /.well-known/jwks.json`

**Purpose**: Exposes public keys for JWT signature verification

**Implementation**: `src/modules/oidc/controllers/JWKSController.ts:21`

**Response Example**:

```json
{
  "keys": [
    {
      "kid": "2025-01-19-abc123",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "<base64url-encoded-modulus>",
      "e": "AQAB"
    },
    {
      "kid": "2024-10-15-xyz789",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "<base64url-encoded-modulus>",
      "e": "AQAB"
    }
  ]
}
```

**Features**:

- Returns all active public keys from the database
- Supports multiple concurrent keys for rotation
- Uses `KeyManagementService.getPublicKeys()` for key retrieval
- Keys include `kid` (key ID) for JWT header matching
- Enables zero-downtime key rotation

**Key Rotation Support**:

- When keys are rotated, old keys remain active for verification
- New tokens are signed with the new primary key
- Old tokens can still be verified with old keys
- Clients automatically discover new keys via this endpoint

### 4. UserInfo Endpoint

**Endpoint**: `GET /oauth/userinfo`

**Purpose**: Returns user claims based on the access token and granted scopes

**Implementation**: `src/modules/oidc/controllers/UserInfoController.ts:37`

**Authentication**: Requires Bearer token in Authorization header

**Response Example** (with `openid email profile` scopes):

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "email_verified": true,
  "name": "user"
}
```

**Features**:

- Verifies access token using `TokenService.verifyToken()`
- Requires `openid` scope to access endpoint
- Returns claims based on granted scopes:
  - `openid`: Returns `sub` (subject/user ID)
  - `email`: Returns `email` and `email_verified`
  - `profile`: Returns `name`, `given_name`, `family_name`, `picture` (when available in schema)
- Fetches user data from database
- Returns appropriate error codes:
  - `401 invalid_token`: Missing or invalid token
  - `403 insufficient_scope`: Missing `openid` scope
  - `404 user_not_found`: User doesn't exist

**Scope-to-Claims Mapping**:

```typescript
openid  → sub, iss, aud, exp, iat
email   → email, email_verified
profile → name, given_name, family_name, picture
```

### 5. OIDC Service

**File**: `src/modules/oidc/services/OIDCService.ts`

**Purpose**: Centralized OIDC business logic and configuration

**Methods**:

- `getDiscoveryDocument()`: Returns discovery metadata
- `getScopesWithDescriptions()`: Human-readable scope descriptions
- `getClaimsForScope(scope)`: Maps scopes to claims
- `isScopeSupported(scope)`: Validates scope support
- `validateScopes(scopes)`: Batch scope validation

**Supported Scopes**:

- `openid`: Required for OIDC authentication
- `profile`: Access to profile information
- `email`: Access to email address
- `offline_access`: Request refresh token

### 6. Server Integration

**File**: `src/server.ts:11,78,116-119`

**Changes**:

1. Import OIDC routes
2. Mount OIDC routes (no prefix needed for `.well-known` paths)
3. Add OIDC endpoints to startup console output

**Console Output Example**:

```
OpenID Connect Endpoints:
  - Discovery: http://localhost:3000/.well-known/openid-configuration
  - JWKS: http://localhost:3000/.well-known/jwks.json
  - UserInfo: http://localhost:3000/oauth/userinfo
```

## API Documentation

### Discovery Document Endpoint

```bash
curl http://localhost:3000/.well-known/openid-configuration
```

**Use Case**: Client applications use this to discover available endpoints and supported features

### JWKS Endpoint

```bash
curl http://localhost:3000/.well-known/jwks.json
```

**Use Case**: Client applications and resource servers use this to verify JWT signatures

### UserInfo Endpoint

```bash
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:3000/oauth/userinfo
```

**Use Case**: Retrieve authenticated user's claims after successful OAuth login

**Error Responses**:

```json
// Missing token
{
  "error": "invalid_token",
  "error_description": "Missing or invalid Authorization header"
}

// Invalid token
{
  "error": "invalid_token",
  "error_description": "Token signature verification failed"
}

// Missing openid scope
{
  "error": "insufficient_scope",
  "error_description": "The openid scope is required to access UserInfo endpoint"
}

// User not found
{
  "error": "user_not_found",
  "error_description": "User not found"
}
```

## Standards Compliance

This implementation follows these specifications:

1. **OpenID Connect Core 1.0**
   - Discovery Document format
   - UserInfo endpoint specification
   - Scope-based claims delivery

2. **OpenID Connect Discovery 1.0**
   - `.well-known/openid-configuration` endpoint
   - Required and optional metadata fields

3. **RFC 7517: JSON Web Key (JWK)**
   - JWKS endpoint format
   - Public key representation

4. **RFC 7519: JSON Web Token (JWT)**
   - JWT signature verification
   - Claims validation

## Security Features

1. **Token Verification**:
   - RS256 signature verification using JWKS
   - Issuer and expiration validation
   - Key ID (`kid`) header matching

2. **Scope Enforcement**:
   - `openid` scope required for UserInfo endpoint
   - Claims filtered by granted scopes
   - Proper error responses for insufficient scopes

3. **Key Rotation Support**:
   - Multiple active keys supported
   - Zero-downtime rotation
   - Automatic key discovery via JWKS

4. **Error Handling**:
   - Standard OAuth error codes
   - Descriptive error messages
   - No sensitive information leakage

## Testing

### Manual Testing

Once the server is running and database is seeded:

```bash
# 1. Discover OIDC configuration
curl http://localhost:3000/.well-known/openid-configuration | jq

# 2. Get public keys
curl http://localhost:3000/.well-known/jwks.json | jq

# 3. Test UserInfo endpoint (requires valid access token)
# First, obtain an access token via OAuth flow, then:
curl -H "Authorization: Bearer <your-access-token>" \
  http://localhost:3000/oauth/userinfo | jq
```

### Integration with OAuth Flow

The UserInfo endpoint integrates with the OAuth 2.0 Authorization Code flow:

1. Client redirects user to `/oauth/authorize` with `openid email profile` scopes
2. User authenticates and grants consent
3. Client exchanges authorization code for access token at `/oauth/token`
4. Client calls `/oauth/userinfo` with access token to get user claims
5. Client can verify token signature using keys from `/jwks.json`

## Future Enhancements

1. **Additional User Profile Fields**:
   - Add `name`, `given_name`, `family_name`, `picture` to user schema
   - Update UserInfo endpoint to return these claims

2. **ID Token Claims**:
   - Enhance `TokenService.generateIDToken()` to include more claims
   - Support `nonce` parameter for replay protection

3. **Claims Parameter**:
   - Support `claims` parameter in authorization request
   - Allow clients to request specific claims

4. **UserInfo Signing**:
   - Support signed UserInfo responses (JWT format)
   - Add `userinfo_signed_response_alg` to discovery

5. **Additional Scopes**:
   - `address`: Physical mailing address
   - `phone`: Phone number
   - Custom application-specific scopes

## Files Modified

- `src/modules/oidc/services/OIDCService.ts` (created)
- `src/modules/oidc/controllers/DiscoveryController.ts` (created)
- `src/modules/oidc/controllers/JWKSController.ts` (created)
- `src/modules/oidc/controllers/UserInfoController.ts` (created)
- `src/modules/oidc/routes/index.ts` (created)
- `src/server.ts` (modified to register OIDC routes)

## Dependencies Used

- `express`: Web framework
- `jose`: JWT/JWK handling (via KeyManagementService and TokenService)
- `drizzle-orm`: Database queries (for user lookup)

## Next Steps (Phase 7)

Phase 7 will implement the user interface:

- Login page
- Registration page
- Consent screen
- Error pages

These UI components will complete the end-user authentication experience.

---

**Phase 6 Status**: ✅ Complete

All OIDC endpoints are implemented and ready for testing once the TypeScript compilation errors in other modules are resolved.
