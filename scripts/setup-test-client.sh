#!/bin/bash

# OAuth Client Credentials for Testing
# Generated: 2025-11-20
# Client: Backend Web Application (Confidential)

export CLIENT_ID="client_TYvroiO_VvomZaxjFHXCQw"
export CLIENT_SECRET="ob93rys1-K9uYcPxP7_-AZF0zCAW7gQhyRSy69Y90JaQe9xcJgqGVDfCLlOfY9qA"
export REDIRECT_URI="http://localhost:3001/callback"

echo "✅ OAuth client credentials exported:"
echo "   CLIENT_ID=$CLIENT_ID"
echo "   CLIENT_SECRET=$CLIENT_SECRET"
echo "   REDIRECT_URI=$REDIRECT_URI"
echo ""
echo "💡 You can now test the OAuth flow with:"
echo "   ./scripts/test-oauth-flow.sh"
