# Continental ID Dashboard

A full-stack account dashboard with hardened auth/session handling, profile and security controls, and real API-driven account settings.

## What Was Upgraded

- Hardened backend API with:
  - request IDs
  - health endpoint (`/api/health`)
  - env-driven CORS and rate-limiting
  - graceful shutdown
  - safer refresh-token lifecycle (`refreshTokenVersion` invalidation)
- Expanded account model and endpoints for:
  - profile
  - linked accounts
  - privacy/notification preferences
  - security settings
  - recent activity
- Safer email utility configuration (no hardcoded credentials)
- Rebuilt frontend dashboard with:
  - fully wired forms for every tab
  - auto refresh-token retry on 401
  - activity filtering and CSV export
  - toasts, loading states, connection status, and popup fallback
  - responsive layout and improved visual polish

## Backend Setup

1. Install dependencies:
   ```bash
   cd backend
   npm install
   ```
2. Create env file:
   ```bash
   cp .env.example .env
   ```
3. Start backend:
   ```bash
   npm run start
   ```

## Frontend Setup

You can serve `frontend/` with any static server (for example Live Server or `python -m http.server`).

Optional runtime overrides:

- `window.__API_BASE_URL__` or `localStorage.setItem('apiBaseUrl', 'http://localhost:5000')`
- `window.__LOGIN_POPUP_URL__` or `localStorage.setItem('loginPopupUrl', '...')`

## Key API Endpoints

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `POST /api/auth/refresh_token`
- `GET /api/auth/me`
- `PATCH /api/auth/profile`
- `PATCH /api/auth/email`
- `PATCH /api/auth/password`
- `GET/PATCH /api/auth/preferences`
- `GET/PATCH /api/auth/linked`
- `GET /api/auth/activity`
- `GET/PATCH /api/auth/security`
- `DELETE /api/auth/account`
- `GET /api/auth/verify-email?token=...`

## Notes

- `ALLOWED_ORIGINS` is comma-separated and supports local development via `localhost`/`127.0.0.1` automatically.
- Password updates invalidate existing refresh sessions and force re-login.
- Logout invalidates refresh sessions and clears auth cookie.
