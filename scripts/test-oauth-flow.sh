#!/bin/bash

# OAuth 2.0 Authorization Code Flow Testing Script
# This script demonstrates a complete OAuth flow

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
BASE_URL="${BASE_URL:-http://localhost:3000}"
TEST_EMAIL="test@example.com"
TEST_PASSWORD="Test123456!"

# OAuth Configuration (you'll need to set these after creating a client)
CLIENT_ID="${CLIENT_ID:-}"
CLIENT_SECRET="${CLIENT_SECRET:-}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:3001/callback}"

COOKIE_FILE=$(mktemp)
trap "rm -f $COOKIE_FILE" EXIT

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}OAuth 2.0 Flow Testing${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Check if CLIENT_ID is set
if [ -z "$CLIENT_ID" ]; then
    echo -e "${YELLOW}⚠ CLIENT_ID not set${NC}"
    echo ""
    echo "To test OAuth flow, you need to:"
    echo "  1. Create a client via admin API or seed script"
    echo "  2. Set environment variables:"
    echo ""
    echo "     export CLIENT_ID='your_client_id'"
    echo "     export CLIENT_SECRET='your_client_secret'"
    echo "     export REDIRECT_URI='http://localhost:3001/callback'"
    echo ""
    echo "Then run this script again."
    echo ""
    echo "Creating a test client now..."
    echo ""

    # Login first
    echo -e "${YELLOW}Logging in as test user...${NC}"
    LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" -c "$COOKIE_FILE" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "email=$TEST_EMAIL&password=$TEST_PASSWORD" \
        -L)

    HTTP_CODE=$(echo "$LOGIN_RESPONSE" | tail -n1)
    if [ "$HTTP_CODE" != "200" ]; then
        echo -e "${RED}✗ Login failed${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Logged in${NC}\n"

    # Create a test client
    echo -e "${YELLOW}Creating test OAuth client...${NC}"
    CLIENT_RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_FILE" \
        -X POST "$BASE_URL/admin/clients" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Test OAuth Client",
            "clientType": "confidential",
            "redirectUris": ["http://localhost:3001/callback"],
            "grantTypes": ["authorization_code", "refresh_token"],
            "allowedScopes": "openid profile email"
        }')

    HTTP_CODE=$(echo "$CLIENT_RESPONSE" | tail -n1)
    BODY=$(echo "$CLIENT_RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" = "201" ]; then
        CLIENT_ID=$(echo "$BODY" | grep -o '"clientId":"[^"]*"' | cut -d'"' -f4)
        CLIENT_SECRET=$(echo "$BODY" | grep -o '"clientSecret":"[^"]*"' | cut -d'"' -f4)

        echo -e "${GREEN}✓ Client created successfully${NC}"
        echo ""
        echo "Client credentials:"
        echo "  CLIENT_ID: $CLIENT_ID"
        echo "  CLIENT_SECRET: $CLIENT_SECRET"
        echo ""
        echo "Save these for future testing:"
        echo ""
        echo "  export CLIENT_ID='$CLIENT_ID'"
        echo "  export CLIENT_SECRET='$CLIENT_SECRET'"
        echo ""
    else
        echo -e "${RED}✗ Failed to create client (HTTP $HTTP_CODE)${NC}"
        echo "$BODY"
        exit 1
    fi
fi

# Generate PKCE challenge (optional, for public clients)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -binary -sha256 | openssl base64 | tr -d "=+/" | tr "/+" "_-")

echo -e "${YELLOW}Step 1: Authorization Request${NC}"
echo "Building authorization URL..."
echo ""

STATE=$(openssl rand -hex 16)
NONCE=$(openssl rand -hex 16)

AUTH_URL="$BASE_URL/oauth/authorize"
AUTH_URL+="?client_id=$CLIENT_ID"
AUTH_URL+="&response_type=code"
AUTH_URL+="&redirect_uri=$REDIRECT_URI"
AUTH_URL+="&scope=openid%20profile%20email"
AUTH_URL+="&state=$STATE"
AUTH_URL+="&nonce=$NONCE"

if [ -z "$CLIENT_SECRET" ]; then
    # Public client - use PKCE
    AUTH_URL+="&code_challenge=$CODE_CHALLENGE"
    AUTH_URL+="&code_challenge_method=S256"
    echo "Using PKCE (public client)"
fi

echo "Authorization URL:"
echo "$AUTH_URL"
echo ""
echo -e "${BLUE}To complete the flow:${NC}"
echo "  1. Open the URL above in your browser"
echo "  2. Login with: $TEST_EMAIL / $TEST_PASSWORD"
echo "  3. Approve the consent (if shown)"
echo "  4. Copy the 'code' parameter from the redirect URL"
echo "  5. Run the token exchange:"
echo ""

if [ -n "$CLIENT_SECRET" ]; then
    echo "     curl -X POST $BASE_URL/oauth/token \\"
    echo "       -H 'Content-Type: application/x-www-form-urlencoded' \\"
    echo "       -d 'grant_type=authorization_code' \\"
    echo "       -d 'code=YOUR_AUTH_CODE' \\"
    echo "       -d 'redirect_uri=$REDIRECT_URI' \\"
    echo "       -d 'client_id=$CLIENT_ID' \\"
    echo "       -d 'client_secret=$CLIENT_SECRET'"
else
    echo "     curl -X POST $BASE_URL/oauth/token \\"
    echo "       -H 'Content-Type: application/x-www-form-urlencoded' \\"
    echo "       -d 'grant_type=authorization_code' \\"
    echo "       -d 'code=YOUR_AUTH_CODE' \\"
    echo "       -d 'redirect_uri=$REDIRECT_URI' \\"
    echo "       -d 'client_id=$CLIENT_ID' \\"
    echo "       -d 'code_verifier=$CODE_VERIFIER'"
fi

echo ""
echo -e "${YELLOW}Alternative: Automated flow with manual code input${NC}"
echo ""
read -p "Do you want to continue with automated testing? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 0
fi

echo ""
echo "Please enter the authorization code from the redirect URL:"
read -r AUTH_CODE

if [ -z "$AUTH_CODE" ]; then
    echo -e "${RED}No code provided, exiting${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Step 2: Token Exchange${NC}"

if [ -n "$CLIENT_SECRET" ]; then
    # Confidential client
    TOKEN_RESPONSE=$(curl -s -w "\n%{http_code}" \
        -X POST "$BASE_URL/oauth/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=authorization_code" \
        -d "code=$AUTH_CODE" \
        -d "redirect_uri=$REDIRECT_URI" \
        -d "client_id=$CLIENT_ID" \
        -d "client_secret=$CLIENT_SECRET")
else
    # Public client with PKCE
    TOKEN_RESPONSE=$(curl -s -w "\n%{http_code}" \
        -X POST "$BASE_URL/oauth/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=authorization_code" \
        -d "code=$AUTH_CODE" \
        -d "redirect_uri=$REDIRECT_URI" \
        -d "client_id=$CLIENT_ID" \
        -d "code_verifier=$CODE_VERIFIER")
fi

HTTP_CODE=$(echo "$TOKEN_RESPONSE" | tail -n1)
BODY=$(echo "$TOKEN_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Token exchange successful${NC}"
    echo ""
    echo "Response:"
    echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"

    ACCESS_TOKEN=$(echo "$BODY" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    REFRESH_TOKEN=$(echo "$BODY" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
    ID_TOKEN=$(echo "$BODY" | grep -o '"id_token":"[^"]*"' | cut -d'"' -f4)

    echo ""
    echo -e "${YELLOW}Step 3: Test UserInfo Endpoint${NC}"

    if [ -n "$ACCESS_TOKEN" ]; then
        USERINFO_RESPONSE=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            "$BASE_URL/oauth/userinfo")

        HTTP_CODE=$(echo "$USERINFO_RESPONSE" | tail -n1)
        BODY=$(echo "$USERINFO_RESPONSE" | sed '$d')

        if [ "$HTTP_CODE" = "200" ]; then
            echo -e "${GREEN}✓ UserInfo retrieved${NC}"
            echo ""
            echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
        else
            echo -e "${RED}✗ UserInfo failed (HTTP $HTTP_CODE)${NC}"
        fi
    fi

    echo ""
    echo -e "${GREEN}✓ OAuth 2.0 Flow Complete!${NC}"
else
    echo -e "${RED}✗ Token exchange failed (HTTP $HTTP_CODE)${NC}"
    echo "$BODY"
fi

echo ""
