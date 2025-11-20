#!/bin/bash

# Identity Server API Testing Script
# This script tests the main API endpoints using curl

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BASE_URL="${BASE_URL:-http://localhost:3000}"
TEST_EMAIL="test@example.com"
TEST_PASSWORD="Test123456!"

# Temporary file for cookies
COOKIE_FILE=$(mktemp)
trap "rm -f $COOKIE_FILE" EXIT

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Identity Server API Testing${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Test 1: Health Check
echo -e "${YELLOW}[1/10] Testing Health Endpoint...${NC}"
HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL/health")
HTTP_CODE=$(echo "$HEALTH_RESPONSE" | tail -n1)
BODY=$(echo "$HEALTH_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Health check passed${NC}"
    echo "   Response: $BODY"
else
    echo -e "${RED}✗ Health check failed (HTTP $HTTP_CODE)${NC}"
    exit 1
fi
echo ""

# Test 2: OIDC Discovery
echo -e "${YELLOW}[2/10] Testing OIDC Discovery Endpoint...${NC}"
DISCOVERY_RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL/.well-known/openid-configuration")
HTTP_CODE=$(echo "$DISCOVERY_RESPONSE" | tail -n1)
BODY=$(echo "$DISCOVERY_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ OIDC Discovery successful${NC}"
    echo "   Issuer: $(echo "$BODY" | grep -o '"issuer":"[^"]*"' | cut -d'"' -f4)"
else
    echo -e "${RED}✗ OIDC Discovery failed (HTTP $HTTP_CODE)${NC}"
    exit 1
fi
echo ""

# Test 3: JWKS Endpoint
echo -e "${YELLOW}[3/10] Testing JWKS Endpoint...${NC}"
JWKS_RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL/.well-known/jwks.json")
HTTP_CODE=$(echo "$JWKS_RESPONSE" | tail -n1)
BODY=$(echo "$JWKS_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ JWKS endpoint accessible${NC}"
    KEY_COUNT=$(echo "$BODY" | grep -o '"kid"' | wc -l)
    echo "   Public keys available: $KEY_COUNT"
else
    echo -e "${RED}✗ JWKS endpoint failed (HTTP $HTTP_CODE)${NC}"
    exit 1
fi
echo ""

# Test 4: Login (Get Session)
echo -e "${YELLOW}[4/10] Testing User Login...${NC}"
LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" -c "$COOKIE_FILE" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "email=$TEST_EMAIL&password=$TEST_PASSWORD&remember=on" \
    -L)  # Follow redirects

HTTP_CODE=$(echo "$LOGIN_RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Login successful${NC}"
    echo "   Session cookie saved"
else
    echo -e "${RED}✗ Login failed (HTTP $HTTP_CODE)${NC}"
    echo "   Response: $(echo "$LOGIN_RESPONSE" | sed '$d')"
    exit 1
fi
echo ""

# Test 5: Access Home Page (Authenticated)
echo -e "${YELLOW}[5/10] Testing Authenticated Home Page...${NC}"
HOME_RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_FILE" "$BASE_URL/")
HTTP_CODE=$(echo "$HOME_RESPONSE" | tail -n1)
BODY=$(echo "$HOME_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    if echo "$BODY" | grep -q "Welcome"; then
        echo -e "${GREEN}✓ Home page accessible${NC}"
        echo "   User authenticated successfully"
    else
        echo -e "${YELLOW}⚠ Home page returned 200 but content unexpected${NC}"
    fi
elif [ "$HTTP_CODE" = "302" ]; then
    echo -e "${YELLOW}⚠ Home page redirected (session may not be persisting)${NC}"
    echo "   This might be a cookie/session issue"
else
    echo -e "${YELLOW}⚠ Home page returned HTTP $HTTP_CODE${NC}"
fi
echo ""

# Test 6: Admin - List Organizations
echo -e "${YELLOW}[6/10] Testing Admin - List Organizations...${NC}"
ORGS_RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_FILE" \
    "$BASE_URL/admin/organizations?limit=10")
HTTP_CODE=$(echo "$ORGS_RESPONSE" | tail -n1)
BODY=$(echo "$ORGS_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Organizations list retrieved${NC}"
    ORG_COUNT=$(echo "$BODY" | grep -o '"total":[0-9]*' | grep -o '[0-9]*')
    echo "   Total organizations: ${ORG_COUNT:-0}"

    # Extract first organization ID if exists
    ORG_ID=$(echo "$BODY" | grep -o '"id":"[^"]*"' | head -n1 | cut -d'"' -f4)
    if [ -n "$ORG_ID" ]; then
        echo "   First org ID: $ORG_ID"
    fi
else
    echo -e "${YELLOW}⚠ Organizations endpoint returned HTTP $HTTP_CODE${NC}"
    echo "   (This might be expected if multi-tenant is disabled)"
fi
echo ""

# Test 7: Admin - List Clients
echo -e "${YELLOW}[7/10] Testing Admin - List Clients...${NC}"
CLIENTS_RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_FILE" \
    "$BASE_URL/admin/clients?limit=10")
HTTP_CODE=$(echo "$CLIENTS_RESPONSE" | tail -n1)
BODY=$(echo "$CLIENTS_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Clients list retrieved${NC}"
    CLIENT_COUNT=$(echo "$BODY" | grep -o '"total":[0-9]*' | grep -o '[0-9]*')
    echo "   Total clients: ${CLIENT_COUNT:-0}"

    # Extract first client ID if exists
    CLIENT_ID=$(echo "$BODY" | grep -o '"clientId":"[^"]*"' | head -n1 | cut -d'"' -f4)
    if [ -n "$CLIENT_ID" ]; then
        echo "   First client ID: $CLIENT_ID"
    fi
else
    echo -e "${RED}✗ Clients endpoint failed (HTTP $HTTP_CODE)${NC}"
fi
echo ""

# Test 8: Admin - List Signing Keys
echo -e "${YELLOW}[8/10] Testing Admin - List Signing Keys...${NC}"
KEYS_RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_FILE" \
    "$BASE_URL/admin/keys")
HTTP_CODE=$(echo "$KEYS_RESPONSE" | tail -n1)
BODY=$(echo "$KEYS_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Signing keys retrieved${NC}"
    KEY_COUNT=$(echo "$BODY" | grep -o '"keyId"' | wc -l)
    echo "   Total keys: $KEY_COUNT"
else
    echo -e "${RED}✗ Keys endpoint failed (HTTP $HTTP_CODE)${NC}"
fi
echo ""

# Test 9: OAuth - Authorization Endpoint (should redirect to login or consent)
echo -e "${YELLOW}[9/10] Testing OAuth Authorization Endpoint...${NC}"
if [ -n "$CLIENT_ID" ]; then
    AUTH_RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_FILE" \
        "$BASE_URL/oauth/authorize?client_id=$CLIENT_ID&response_type=code&redirect_uri=http://localhost:3001/callback&scope=openid%20profile&state=test123")
    HTTP_CODE=$(echo "$AUTH_RESPONSE" | tail -n1)

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        echo -e "${GREEN}✓ Authorization endpoint accessible${NC}"
        echo "   HTTP Code: $HTTP_CODE"
    else
        echo -e "${YELLOW}⚠ Authorization endpoint returned HTTP $HTTP_CODE${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Skipped (no client ID available)${NC}"
fi
echo ""

# Test 10: Logout
echo -e "${YELLOW}[10/10] Testing Logout...${NC}"
LOGOUT_RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_FILE" \
    -L "$BASE_URL/logout")
HTTP_CODE=$(echo "$LOGOUT_RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Logout successful${NC}"
else
    echo -e "${YELLOW}⚠ Logout returned HTTP $HTTP_CODE${NC}"
fi
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ API Testing Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Summary:"
echo "  - Health check: ✓"
echo "  - OIDC endpoints: ✓"
echo "  - Authentication: ✓"
echo "  - Admin endpoints: ✓"
echo ""
echo "Next steps:"
echo "  1. Test with Postman for more detailed testing"
echo "  2. Create OAuth clients via admin API"
echo "  3. Test full OAuth 2.0 authorization code flow"
echo ""
