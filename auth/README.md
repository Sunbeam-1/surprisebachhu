# Authentication

This folder adds a FastAPI authentication layer for Surprise Bachhu.

## Request flow

1. POST /auth/register receives email/password.
2. The password is converted to an Argon2 hash; plaintext is not stored.
3. POST /auth/login verifies the hash.
4. Login returns a short-lived access JWT.
5. Login sets a longer-lived refresh JWT in an HttpOnly cookie scoped to /auth.
6. Protected requests send Authorization: Bearer <access_token>.
7. POST /auth/refresh reads the refresh cookie and issues a new access token.
8. POST /auth/logout removes the refresh cookie.

## Important

The existing repository has a large static index.html whose contents could not be safely read through the GitHub connector. These files therefore provide a separate backend layer rather than claiming the existing page is already wired to authentication.

The users dictionary is demo-only. Production should use a database and add refresh-token rotation/revocation, rate limiting, password reset/email verification, appropriate CSRF protection, and HTTPS.

## Run

pip install -r requirements.txt
uvicorn main:app --reload

Interactive API docs: /docs

## Examples

Register:
POST /auth/register
Content-Type: application/json

{"email":"user@example.com","password":"at-least-8-chars"}

Login:
POST /auth/login
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=at-least-8-chars

Authenticated request:
GET /auth/me
Authorization: Bearer <access_token>
