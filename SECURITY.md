# Security Policy

## Reporting a Vulnerability

Do not open public issues for security problems in the authentication or account system.

Report vulnerabilities privately to the project maintainer with:

- a short description of the issue
- affected routes or files
- reproduction steps
- impact assessment
- any proof-of-concept material needed to verify the report

If email reporting is available for your deployment, use the same support/security contact that is
configured for account and login notifications. If there is no dedicated contact yet, establish one
before treating the dashboard as production-ready.

## Scope

This project contains a live authentication surface, including:

- password login and refresh sessions
- email verification and password reset
- MFA and backup codes
- passkeys / WebAuthn
- OAuth account linking and sign-in
- public profile discovery endpoints

Treat changes in those areas as security-sensitive by default.

## Expectations

- Keep `JWT_SECRET` and `REFRESH_TOKEN_SECRET` strong and unique per environment.
- Run the backend only behind HTTPS in production.
- Set `TRUST_PROXY` correctly when the service is behind a reverse proxy.
- Restrict `ALLOWED_ORIGINS` to trusted dashboard/login origins.
- Review login, reset, OAuth, MFA, and passkey flows after any auth-related change.
- Avoid logging secrets, reset tokens, verification tokens, backup codes, or raw cookies.
