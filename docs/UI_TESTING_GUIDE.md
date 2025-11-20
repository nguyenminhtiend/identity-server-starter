# UI Web Testing Guide

Complete guide for testing the Identity Server through web browser interface.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Test Environment Setup](#test-environment-setup)
3. [Test Scenario 1: User Registration Flow](#test-scenario-1-user-registration-flow)
4. [Test Scenario 2: User Login Flow](#test-scenario-2-user-login-flow)
5. [Test Scenario 3: OAuth Authorization Flow](#test-scenario-3-oauth-authorization-flow)
6. [Test Scenario 4: Session Management](#test-scenario-4-session-management)
7. [Test Scenario 5: Error Handling](#test-scenario-5-error-handling)
8. [Test Scenario 6: OIDC Discovery](#test-scenario-6-oidc-discovery)
9. [Browser Testing Checklist](#browser-testing-checklist)
10. [Common Issues](#common-issues)

---

## Prerequisites

### Required Software

- **Modern Web Browser** (Chrome, Firefox, Safari, or Edge)
- **Server running** at `http://localhost:3000`
- **Database seeded** with admin user
- **Redis running** for session storage

### Browser Developer Tools

Enable developer tools for testing:

- **Chrome/Edge:** F12 or Cmd+Option+I (Mac) / Ctrl+Shift+I (Windows)
- **Firefox:** F12 or Cmd+Option+I (Mac) / Ctrl+Shift+I (Windows)
- **Safari:** Cmd+Option+I (Mac) - Enable first in Preferences → Advanced

### Useful Browser Tabs

- **Console:** View JavaScript errors and logs
- **Network:** Monitor HTTP requests/responses
- **Application/Storage:** View cookies and session storage
- **Elements:** Inspect HTML and CSS

### Start Server

```bash
# Terminal 1: Start server
pnpm dev

# Terminal 2: Verify server
curl http://localhost:3000/health
```

Expected output: `{"status":"ok"}`

---

## Test Environment Setup

### Step 1: Create OAuth Client (Required for OAuth testing)

Use Postman or curl to create an OAuth client:

```bash
# First, login as admin to get session cookie
curl -c cookies.txt -X POST http://localhost:3000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=admin@example.com&password=Admin123!&rememberMe=on"

# Create OAuth client
curl -b cookies.txt -X POST http://localhost:3000/admin/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Web Client",
    "clientType": "confidential",
    "redirectUris": ["http://localhost:3000/callback"],
    "grantTypes": ["authorization_code", "refresh_token"],
    "allowedScopes": "openid email profile"
  }'
```

**Save the `clientId` and `clientSecret` from the response!**

Alternatively, use Postman Collection 01, requests 01.2 and 01.6.

---

## Test Scenario 1: User Registration Flow

**Objective:** Register a new user account through the web interface.

### Test Case 1.1: Successful Registration

**Steps:**

1. **Navigate to registration page**

   ```
   http://localhost:3000/register
   ```

2. **Verify page loads correctly**
   - ✅ Page title: "Register" or "Sign Up"
   - ✅ Registration form visible
   - ✅ Fields present:
     - Email input field
     - Password input field
     - Confirm Password input field
     - Submit button ("Register" or "Sign Up")
   - ✅ Link to login page visible

3. **Fill in registration form**
   - **Email:** `newuser@example.com`
   - **Password:** `SecurePass123!`
   - **Confirm Password:** `SecurePass123!`

4. **Submit form**
   - Click "Register" or "Sign Up" button

5. **Expected Results:**
   - ✅ Redirect to home page or dashboard
   - ✅ User is logged in (session created)
   - ✅ No error messages displayed
   - ✅ Success message (optional): "Account created successfully"

6. **Verify in Developer Tools:**
   - Open **Application/Storage** tab
   - Check **Cookies** → `http://localhost:3000`
   - ✅ `connect.sid` cookie present
   - ✅ Cookie has `HttpOnly` flag
   - ✅ Cookie has `Path=/`

7. **Verify session in Redis (optional):**
   ```bash
   redis-cli keys "sess:*"
   ```
   Should show your session key.

**Test Data:**

```
Email: testuser1@example.com
Password: TestPass123!
Confirm Password: TestPass123!
```

---

### Test Case 1.2: Registration with Invalid Email

**Steps:**

1. Navigate to `http://localhost:3000/register`
2. Fill in form with invalid email:
   - **Email:** `invalidemail` (no @ symbol)
   - **Password:** `SecurePass123!`
   - **Confirm Password:** `SecurePass123!`
3. Submit form

**Expected Results:**

- ✅ Error message: "Invalid email format" or similar
- ✅ User stays on registration page
- ✅ No account created

**Test Data:**

```
Invalid emails to test:
- "invalidemail"
- "test@"
- "@example.com"
- "test @example.com" (space)
```

---

### Test Case 1.3: Registration with Weak Password

**Steps:**

1. Navigate to `http://localhost:3000/register`
2. Fill in form with weak password:
   - **Email:** `test@example.com`
   - **Password:** `123` (too short)
   - **Confirm Password:** `123`
3. Submit form

**Expected Results:**

- ✅ Error message: "Password too weak" or "Password must be at least X characters"
- ✅ User stays on registration page
- ✅ No account created

**Test Data:**

```
Weak passwords to test:
- "123" (too short)
- "password" (no numbers/special chars)
- "abc" (too short)
```

---

### Test Case 1.4: Registration with Mismatched Passwords

**Steps:**

1. Navigate to `http://localhost:3000/register`
2. Fill in form with mismatched passwords:
   - **Email:** `test@example.com`
   - **Password:** `SecurePass123!`
   - **Confirm Password:** `DifferentPass456!`
3. Submit form

**Expected Results:**

- ✅ Error message: "Passwords do not match"
- ✅ User stays on registration page
- ✅ No account created

---

### Test Case 1.5: Registration with Existing Email

**Steps:**

1. Navigate to `http://localhost:3000/register`
2. Fill in form with already registered email:
   - **Email:** `admin@example.com` (already exists)
   - **Password:** `SecurePass123!`
   - **Confirm Password:** `SecurePass123!`
3. Submit form

**Expected Results:**

- ✅ Error message: "Email already registered" or "Account already exists"
- ✅ User stays on registration page
- ✅ No duplicate account created

---

## Test Scenario 2: User Login Flow

**Objective:** Test user login functionality through the web interface.

### Test Case 2.1: Successful Login

**Steps:**

1. **Navigate to login page**

   ```
   http://localhost:3000/login
   ```

2. **Verify page loads correctly**
   - ✅ Page title: "Login" or "Sign In"
   - ✅ Login form visible
   - ✅ Fields present:
     - Email input field
     - Password input field
     - "Remember Me" checkbox (optional)
     - Submit button ("Login" or "Sign In")
   - ✅ Link to registration page visible
   - ✅ "Forgot Password" link (if implemented)

3. **Fill in login form**
   - **Email:** `admin@example.com`
   - **Password:** `Admin123!`

4. **Submit form**
   - Click "Login" or "Sign In" button

5. **Expected Results:**
   - ✅ Redirect to home page or dashboard
   - ✅ User is authenticated
   - ✅ No error messages
   - ✅ Welcome message (optional): "Welcome, admin"

6. **Verify session cookie:**
   - Open **Application** tab → **Cookies**
   - ✅ `connect.sid` cookie present
   - ✅ Cookie expiration: ~24 hours from now

**Test Data:**

```
Email: admin@example.com
Password: Admin123!
```

---

### Test Case 2.2: Login with "Remember Me"

**Steps:**

1. Navigate to `http://localhost:3000/login`
2. Fill in login form:
   - **Email:** `admin@example.com`
   - **Password:** `Admin123!`
   - ✅ **Check** "Remember Me" checkbox
3. Submit form

**Expected Results:**

- ✅ Login successful
- ✅ Session cookie expiration: ~30 days from now (extended)

**Verify:**

- Open **Application** tab → **Cookies** → `connect.sid`
- Check **Expires** field
- Should be approximately 30 days in the future

---

### Test Case 2.3: Login with Invalid Credentials

**Steps:**

1. Navigate to `http://localhost:3000/login`
2. Fill in form with wrong password:
   - **Email:** `admin@example.com`
   - **Password:** `WrongPassword123!`
3. Submit form

**Expected Results:**

- ✅ Error message: "Invalid email or password"
- ✅ User stays on login page
- ✅ No session created
- ✅ Form cleared or preserves email (common UX pattern)

**Test Cases:**

```
Wrong password: admin@example.com / WrongPass123
Wrong email: nonexistent@example.com / Admin123!
Both wrong: wrong@example.com / WrongPass123
```

---

### Test Case 2.4: Login with Non-Existent User

**Steps:**

1. Navigate to `http://localhost:3000/login`
2. Fill in form with non-existent email:
   - **Email:** `doesnotexist@example.com`
   - **Password:** `AnyPassword123!`
3. Submit form

**Expected Results:**

- ✅ Error message: "Invalid email or password" (same as wrong password for security)
- ✅ User stays on login page
- ✅ No session created

---

### Test Case 2.5: Access Protected Page Without Login

**Steps:**

1. **Clear all cookies:**
   - Open **Application** tab → **Cookies**
   - Right-click → "Clear all cookies"
2. **Attempt to access protected route** (if applicable):
   ```
   http://localhost:3000/dashboard
   ```
   Or try OAuth authorization without session:
   ```
   http://localhost:3000/oauth/authorize?client_id=xxx&response_type=code&redirect_uri=http://localhost:3000/callback
   ```

**Expected Results:**

- ✅ Redirect to login page
- ✅ URL parameter preserved: `?returnTo=/dashboard` or similar
- ✅ After login, redirect back to originally requested page

---

## Test Scenario 3: OAuth Authorization Flow

**Objective:** Test complete OAuth 2.0 authorization code flow with PKCE through the browser.

**Prerequisites:**

- OAuth client created (see Test Environment Setup)
- User account available (admin or registered user)

### Test Case 3.1: Complete Authorization Code Flow

**Steps:**

#### Part 1: Generate PKCE Parameters

Use browser console to generate PKCE codes:

1. Open browser console (F12 → Console tab)
2. Paste and run this code:

```javascript
// Generate PKCE code verifier and challenge
function base64URLEncode(str) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function generatePKCE() {
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  const verifier = base64URLEncode(randomBytes);

  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const challenge = base64URLEncode(hashBuffer);

  console.log('Code Verifier:', verifier);
  console.log('Code Challenge:', challenge);

  return { verifier, challenge };
}

// Run it
generatePKCE().then((pkce) => {
  window.codeVerifier = pkce.verifier;
  window.codeChallenge = pkce.challenge;
  console.log('PKCE codes saved to window.codeVerifier and window.codeChallenge');
});
```

3. **Save the output:**
   - `codeVerifier`: Copy this value
   - `codeChallenge`: Copy this value

---

#### Part 2: Initiate Authorization Request

4. **Build authorization URL:**

Replace `YOUR_CLIENT_ID` and `YOUR_CODE_CHALLENGE`:

```
http://localhost:3000/oauth/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid%20email%20profile&state=random_state_12345&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256
```

5. **Navigate to authorization URL** in browser

6. **Expected: Redirect to Login (if not logged in)**
   - ✅ Redirected to `/login`
   - ✅ After login, redirected back to authorization page

7. **Login** (if required):
   - **Email:** `admin@example.com`
   - **Password:** `Admin123!`
   - Submit

---

#### Part 3: Grant Consent

8. **Consent Page Appears:**

   **Verify page elements:**
   - ✅ Client information displayed:
     - Client name: "Test Web Client"
     - Client logo (if provided)
   - ✅ Requested scopes listed:
     - ☑ Access your email address
     - ☑ Access your profile information
     - ☑ OpenID Connect authentication
   - ✅ User email displayed
   - ✅ "Allow" or "Authorize" button
   - ✅ "Deny" or "Cancel" button (optional)

9. **Grant consent:**
   - Click "Allow" or "Authorize" button

10. **Expected: Redirect to Callback**
    - ✅ Browser redirects to callback URL
    - ✅ URL contains authorization code:
      ```
      http://localhost:3000/callback?code=AUTH_CODE_HERE&state=random_state_12345
      ```
    - ✅ `code` parameter is a long alphanumeric string
    - ✅ `state` parameter matches original state value

11. **Copy authorization code**
    - From URL, copy the value of `code` parameter
    - Example: `AUTH_CODE_HERE`

---

#### Part 4: Exchange Code for Tokens

12. **Exchange authorization code for tokens**

Use browser console or curl:

```bash
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code_verifier=YOUR_CODE_VERIFIER"
```

Or use browser console:

```javascript
fetch('http://localhost:3000/oauth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: 'YOUR_AUTH_CODE',
    redirect_uri: 'http://localhost:3000/callback',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET',
    code_verifier: window.codeVerifier, // From step 3
  }),
})
  .then((r) => r.json())
  .then((tokens) => {
    console.log('Tokens:', tokens);
    window.accessToken = tokens.access_token;
    window.refreshToken = tokens.refresh_token;
  });
```

13. **Expected Response:**

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

    **Verify:**

- ✅ `access_token` present (JWT format)
- ✅ `refresh_token` present
- ✅ `token_type`: "Bearer"
- ✅ `expires_in`: 3600 (1 hour)
- ✅ `id_token` present (OIDC)

---

#### Part 5: Use Access Token

14. **Call UserInfo endpoint with access token:**

```javascript
fetch('http://localhost:3000/oauth/userinfo', {
  headers: {
    Authorization: 'Bearer ' + window.accessToken,
  },
})
  .then((r) => r.json())
  .then(console.log);
```

15. **Expected Response:**

    ```json
    {
      "sub": "cm4user123",
      "email": "admin@example.com",
      "email_verified": true,
      "name": "admin"
    }
    ```

    **Verify:**

- ✅ User ID (`sub`) present
- ✅ Email present (if `email` scope granted)
- ✅ Name present (if `profile` scope granted)

---

### Test Case 3.2: Deny Consent

**Steps:**

1. Follow Test Case 3.1 steps 1-8 (up to consent page)
2. **On consent page, click "Deny" or "Cancel"** (if button exists)

**Expected Results:**

- ✅ Redirect to callback URL with error:
  ```
  http://localhost:3000/callback?error=access_denied&error_description=User%20denied%20consent&state=random_state_12345
  ```
- ✅ No authorization code in URL
- ✅ Error parameter: `access_denied`

---

### Test Case 3.3: Authorization with Invalid Client ID

**Steps:**

1. Build authorization URL with invalid client ID:
   ```
   http://localhost:3000/oauth/authorize?client_id=INVALID_CLIENT&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid
   ```
2. Navigate to URL

**Expected Results:**

- ✅ Error page displayed: "Invalid client" or "Client not found"
- ✅ No redirect to callback
- ✅ HTTP 400 Bad Request

---

### Test Case 3.4: Authorization with Invalid Redirect URI

**Steps:**

1. Build authorization URL with unauthorized redirect URI:
   ```
   http://localhost:3000/oauth/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=http://evil.com/callback&response_type=code&scope=openid
   ```
2. Navigate to URL

**Expected Results:**

- ✅ Error page: "Invalid redirect_uri"
- ✅ No redirect to callback (security measure)
- ✅ HTTP 400 Bad Request

---

### Test Case 3.5: Authorization without PKCE (Should Require It)

**Steps:**

1. Build authorization URL WITHOUT code_challenge:
   ```
   http://localhost:3000/oauth/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid
   ```
2. Navigate to URL

**Expected Results:**

- ✅ Error: "code_challenge required" or "PKCE required"
- ✅ HTTP 400 Bad Request

---

## Test Scenario 4: Session Management

**Objective:** Test session persistence, expiration, and logout.

### Test Case 4.1: Session Persistence

**Steps:**

1. Login to the application (Test Case 2.1)
2. Verify session cookie created
3. **Close browser tab** (not entire browser)
4. **Reopen** `http://localhost:3000`

**Expected Results:**

- ✅ User still logged in (if session cookie hasn't expired)
- ✅ No need to login again
- ✅ Session cookie still present

---

### Test Case 4.2: Logout

**Steps:**

1. Login to the application
2. **Navigate to logout URL:**
   ```
   http://localhost:3000/logout
   ```

**Expected Results:**

- ✅ Redirect to login page
- ✅ Session destroyed
- ✅ Cookie cleared or invalidated
- ✅ Success message: "Logged out successfully" (optional)

**Verify:**

- Open **Application** tab → **Cookies**
- ✅ `connect.sid` cookie removed or expired

3. **Try to access protected page:**
   - Should redirect to login

---

### Test Case 4.3: Session Expiration

**Steps:**

1. Login with short session (do NOT check "Remember Me")
2. Wait 24+ hours (or manually expire session in Redis)
3. Try to access protected page

**Expected Results:**

- ✅ Redirect to login page
- ✅ Message: "Session expired, please login again" (optional)

**To test faster (using Redis CLI):**

```bash
# Find session key
redis-cli keys "sess:*"

# Delete session
redis-cli del "sess:YOUR_SESSION_KEY"
```

Then refresh browser:

- ✅ Should redirect to login

---

### Test Case 4.4: Multiple Browser Sessions

**Steps:**

1. **Browser 1:** Login as `admin@example.com`
2. **Browser 2 (different browser or incognito):** Login as `testuser@example.com`
3. Verify both sessions work independently

**Expected Results:**

- ✅ Each browser has its own session
- ✅ Both users can be logged in simultaneously
- ✅ Logging out in one browser doesn't affect the other

---

## Test Scenario 5: Error Handling

**Objective:** Test error pages and validation.

### Test Case 5.1: 404 Not Found

**Steps:**

1. Navigate to non-existent page:
   ```
   http://localhost:3000/nonexistent-page
   ```

**Expected Results:**

- ✅ 404 error page displayed
- ✅ Message: "Page not found" or similar
- ✅ Link back to home page
- ✅ HTTP 404 status (check Network tab)

---

### Test Case 5.2: Invalid OAuth Parameters

**Steps:**

1. Navigate to authorization endpoint with invalid parameters:
   ```
   http://localhost:3000/oauth/authorize?invalid=params
   ```

**Expected Results:**

- ✅ Error page or error message
- ✅ Description of what's wrong: "Missing required parameter: client_id"
- ✅ HTTP 400 Bad Request

---

### Test Case 5.3: Expired Authorization Code

**Steps:**

1. Complete OAuth flow to get authorization code
2. Wait 10+ minutes (code expires)
3. Try to exchange code for tokens

**Expected Results:**

- ✅ Error response: `{"error": "invalid_grant", "error_description": "Authorization code expired or invalid"}`
- ✅ HTTP 400 Bad Request

---

### Test Case 5.4: Invalid Access Token

**Steps:**

1. Try to access UserInfo endpoint with invalid token:

```javascript
fetch('http://localhost:3000/oauth/userinfo', {
  headers: {
    Authorization: 'Bearer INVALID_TOKEN_12345',
  },
})
  .then((r) => r.json())
  .then(console.log);
```

**Expected Results:**

- ✅ Error: `{"error": "invalid_token"}`
- ✅ HTTP 401 Unauthorized

---

## Test Scenario 6: OIDC Discovery

**Objective:** Test OpenID Connect discovery endpoints.

### Test Case 6.1: Discovery Document

**Steps:**

1. **Navigate to discovery endpoint:**
   ```
   http://localhost:3000/.well-known/openid-configuration
   ```

**Expected Results:**

- ✅ JSON document displayed
- ✅ Contains required fields:
  ```json
  {
    "issuer": "http://localhost:3000",
    "authorization_endpoint": "http://localhost:3000/oauth/authorize",
    "token_endpoint": "http://localhost:3000/oauth/token",
    "userinfo_endpoint": "http://localhost:3000/oauth/userinfo",
    "jwks_uri": "http://localhost:3000/.well-known/jwks.json",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
    "scopes_supported": ["openid", "email", "profile"],
    "code_challenge_methods_supported": ["S256"]
  }
  ```

**Verify:**

- ✅ All endpoints are valid URLs
- ✅ PKCE support indicated: `"code_challenge_methods_supported": ["S256"]`
- ✅ Scopes include: openid, email, profile

---

### Test Case 6.2: JWKS Endpoint

**Steps:**

1. **Navigate to JWKS endpoint:**
   ```
   http://localhost:3000/.well-known/jwks.json
   ```

**Expected Results:**

- ✅ JSON Web Key Set displayed
- ✅ Contains public keys:
  ```json
  {
    "keys": [
      {
        "kid": "key_id_here",
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": "modulus_here",
        "e": "AQAB"
      }
    ]
  }
  ```

**Verify:**

- ✅ At least one key present
- ✅ Key type (`kty`): "RSA"
- ✅ Algorithm (`alg`): "RS256"
- ✅ Use (`use`): "sig" (signature)

---

## Browser Testing Checklist

### User Registration ✅

- [ ] Successful registration creates account and logs in
- [ ] Invalid email shows error
- [ ] Weak password shows error
- [ ] Mismatched passwords show error
- [ ] Duplicate email shows error
- [ ] Page layout and styling correct
- [ ] Form validation works client-side
- [ ] Form validation works server-side

### User Login ✅

- [ ] Successful login with valid credentials
- [ ] "Remember Me" extends session
- [ ] Invalid credentials show error
- [ ] Non-existent user shows error
- [ ] Protected pages redirect to login
- [ ] After login, redirect to original page
- [ ] Page layout and styling correct

### OAuth Authorization Flow ✅

- [ ] Authorization page loads
- [ ] Redirects to login if not authenticated
- [ ] Consent page displays correctly
- [ ] Client information shown on consent page
- [ ] Scopes clearly explained
- [ ] Allow button grants consent
- [ ] Deny button rejects consent
- [ ] Callback receives authorization code
- [ ] Code can be exchanged for tokens
- [ ] Access token works for UserInfo
- [ ] Invalid client shows error
- [ ] Invalid redirect_uri shows error
- [ ] Missing PKCE shows error

### Session Management ✅

- [ ] Session persists across page reloads
- [ ] Session persists across tab close/reopen
- [ ] Logout destroys session
- [ ] Session expiration works
- [ ] Multiple sessions work independently
- [ ] Session cookie is HttpOnly
- [ ] Session cookie is Secure (production)

### Error Handling ✅

- [ ] 404 page displays for non-existent routes
- [ ] Invalid OAuth parameters show errors
- [ ] Expired authorization code shows error
- [ ] Invalid access token shows error
- [ ] All errors have user-friendly messages
- [ ] Error pages have navigation options

### OIDC Discovery ✅

- [ ] Discovery document accessible
- [ ] Discovery document contains all required fields
- [ ] JWKS endpoint accessible
- [ ] JWKS contains valid public keys
- [ ] All endpoint URLs are correct

### Cross-Browser Testing ✅

- [ ] Chrome works correctly
- [ ] Firefox works correctly
- [ ] Safari works correctly
- [ ] Edge works correctly
- [ ] Mobile browsers work (if applicable)

### Accessibility ✅

- [ ] Forms have proper labels
- [ ] Buttons have descriptive text
- [ ] Error messages are clear
- [ ] Keyboard navigation works
- [ ] Screen reader compatible (test with NVDA/JAWS)

### Security ✅

- [ ] Passwords not visible in URL
- [ ] Session cookies are HttpOnly
- [ ] HTTPS enforced (production)
- [ ] CSRF protection (if implemented)
- [ ] XSS protection (no script injection)
- [ ] SQL injection protection (via parameterized queries)

---

## Common Issues

### Issue 1: Login redirects in a loop

**Symptoms:**

- After login, redirects back to login page repeatedly
- Browser shows multiple redirects in Network tab

**Causes:**

- Session cookie not being set
- Redis not running
- Incorrect cookie domain/path

**Solutions:**

1. Check Redis is running: `redis-cli ping`
2. Clear cookies and try again
3. Check browser console for cookie errors
4. Verify `SESSION_SECRET` in `.env`
5. Check cookie settings in session middleware

---

### Issue 2: "Cannot set headers after they are sent"

**Symptoms:**

- Error in server console
- Page may not load correctly

**Causes:**

- Multiple redirects or responses sent
- Bug in middleware

**Solutions:**

1. Check server logs for stack trace
2. Ensure routes only send one response
3. Restart server

---

### Issue 3: OAuth callback shows "Cannot GET /callback"

**Symptoms:**

- After authorization, callback page shows 404
- No callback route defined

**Causes:**

- Callback route not implemented
- Wrong redirect_uri in authorization request

**Solutions:**

1. Implement callback route in server:
   ```javascript
   app.get('/callback', (req, res) => {
     const code = req.query.code;
     const state = req.query.state;
     res.send(`Authorization code: ${code}`);
   });
   ```
2. Or use registered redirect_uri from client configuration
3. Or show code in URL for manual copying

---

### Issue 4: Session expires too quickly

**Symptoms:**

- User logged out after closing tab
- Session doesn't persist

**Causes:**

- Session cookie has no `maxAge`
- Session cookie is session-only (expires on browser close)

**Solutions:**

1. Check "Remember Me" is working
2. Verify session configuration:
   ```javascript
   cookie: {
     maxAge: 24 * 60 * 60 * 1000; // 24 hours
   }
   ```
3. Check Redis TTL: `redis-cli ttl sess:...`

---

### Issue 5: CORS errors in browser console

**Symptoms:**

- Console shows: "Access to fetch at '...' has been blocked by CORS policy"
- Requests fail from different origins

**Causes:**

- Frontend on different port/domain than backend
- CORS not configured

**Solutions:**

1. Configure CORS in server:
   ```javascript
   app.use(
     cors({
       origin: 'http://localhost:5173', // Your frontend URL
       credentials: true,
     })
   );
   ```
2. Or use same origin for frontend and backend
3. Or use proxy in development

---

### Issue 6: Cookies not saving in browser

**Symptoms:**

- Login successful but session cookie not saved
- Every page requires re-login

**Causes:**

- Browser blocking third-party cookies
- SameSite cookie attribute
- Secure flag on HTTP

**Solutions:**

1. Check cookie settings in browser
2. For localhost testing, use HTTP (not HTTPS)
3. Configure cookie settings:
   ```javascript
   cookie: {
     httpOnly: true,
     secure: process.env.NODE_ENV === 'production',
     sameSite: 'lax'
   }
   ```
4. Clear all cookies and try again

---

### Issue 7: Consent page not showing

**Symptoms:**

- After login, immediately redirects to callback
- No chance to grant consent

**Causes:**

- Consent already granted in previous session
- Consent page not implemented
- Auto-approval for trusted clients

**Solutions:**

1. Clear previous consent (if stored in DB)
2. Verify consent route is implemented
3. Check client configuration for auto-approval setting
4. Test with different user account

---

### Issue 8: Access token not working

**Symptoms:**

- UserInfo endpoint returns 401 Unauthorized
- Token looks valid but doesn't work

**Causes:**

- Token expired
- Token revoked
- Wrong endpoint or scope

**Solutions:**

1. Check token expiration (decode JWT):
   ```javascript
   JSON.parse(atob(token.split('.')[1]));
   ```
2. Introspect token to check if active
3. Verify Authorization header format: `Bearer TOKEN`
4. Check required scopes for endpoint

---

### Issue 9: Mobile browser issues

**Symptoms:**

- Works on desktop, fails on mobile
- Layout broken on mobile
- Cookies not saved on mobile

**Causes:**

- Viewport not configured
- Mobile browser restrictions
- Different cookie behavior

**Solutions:**

1. Add viewport meta tag:
   ```html
   <meta name="viewport" content="width=device-width, initial-scale=1.0" />
   ```
2. Test in mobile browser dev tools
3. Check mobile-specific cookie restrictions
4. Use responsive design

---

### Issue 10: Form submission doesn't work

**Symptoms:**

- Clicking submit does nothing
- JavaScript errors in console

**Causes:**

- JavaScript error preventing submission
- Form action/method incorrect
- CSRF token missing (if implemented)

**Solutions:**

1. Check browser console for errors
2. Verify form has correct attributes:
   ```html
   <form method="POST" action="/login"></form>
   ```
3. Check network tab for request
4. Verify all required fields present
5. Test with JavaScript disabled (should still work)

---

## Testing Tips

### 1. Use Private/Incognito Mode

- Fresh session every time
- No cached cookies or data
- Easier to test from "logged out" state

### 2. Monitor Network Tab

- Watch all HTTP requests/responses
- Check status codes
- View request headers and cookies
- See redirects

### 3. Use Browser Extensions

- **EditThisCookie:** Easily view/edit cookies
- **JSON Viewer:** Format JSON responses
- **React DevTools:** If using React
- **Vue DevTools:** If using Vue

### 4. Test Across Browsers

- Chrome (most users)
- Firefox (good for testing standards compliance)
- Safari (for Mac/iOS users)
- Edge (for Windows users)

### 5. Test Responsive Design

- Use browser DevTools responsive mode
- Test on actual mobile devices
- Check tablet sizes
- Verify touch interactions

### 6. Automate Repetitive Tests

- Use Selenium or Playwright for automation
- Record test scenarios
- Run regression tests

### 7. Performance Testing

- Check page load times
- Optimize images and assets
- Test with slow network (DevTools → Network → Throttling)

---

## Additional Resources

- **OAuth 2.0 Best Practices:** https://oauth.net/2/oauth-best-practice/
- **OpenID Connect:** https://openid.net/connect/
- **Browser DevTools Documentation:**
  - Chrome: https://developer.chrome.com/docs/devtools/
  - Firefox: https://firefox-source-docs.mozilla.org/devtools-user/
  - Safari: https://developer.apple.com/safari/tools/

---

## Summary

This guide covers:

- ✅ 6 test scenarios
- ✅ 20+ test cases
- ✅ Complete OAuth flow testing
- ✅ Session management testing
- ✅ Error handling verification
- ✅ OIDC discovery testing

**For API testing with Postman, see API_TESTING_GUIDE.md**
