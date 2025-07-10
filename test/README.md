# Integration Tests for Google OIDC Auth Middleware

This directory contains integration tests for the Traefik plugin using **Local Mode** plugin installation.

## Overview

The test suite includes:
- **Unit Integration Tests**: HTTP client-based tests for redirects, cookies, and middleware behavior (fast, no browser)

## Quick Start

### 1. Setup
```bash
cd test
make setup
```

### 2. Configure Credentials
```bash
# Edit .env with your Google OAuth credentials
cp .env.example .env
# Fill in GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, TEST_EMAIL, TEST_DOMAIN
```

### 3. Run Tests
```bash
# Fast integration tests
make test-unit
```

## Google OAuth Setup

### Create OAuth Credentials
1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a new OAuth 2.0 Client ID
3. Add these redirect URIs:
   - `http://localhost/protected/oauth/callback`

### Configure Test Users
The plugin authorizes users based on:
- **Email allowlist**: Specific email addresses (`TEST_EMAIL`)
- **Domain allowlist**: Email domains (`TEST_DOMAIN`)

## Manual Testing

Start services for manual testing:
```bash
make start
```

Test URLs:
- **Protected**: http://localhost/protected (requires auth)
- **Unprotected**: http://localhost (no auth)
- **Traefik Dashboard**: http://localhost:18080

Stop services:
```bash
make stop
```