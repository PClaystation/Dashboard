# Continental ID Dashboard

A full-stack account dashboard with hardened auth/session handling, profile and security controls, and real API-driven account settings.

## What Was Upgraded

- Hardened backend API with:
  - request IDs
  - health endpoint (`/api/health`)
  - env-driven CORS and rate-limiting
  - login brute-force throttling and temporary lockouts
  - graceful shutdown
  - safer refresh-token lifecycle (`refreshTokenVersion` invalidation + tracked refresh sessions)
- Expanded account model and endpoints for:
  - profile and rich profile fields (bio, location, website, timezone, language)
  - external profile references
  - privacy/notification preferences and appearance settings
  - security settings
  - active session management (list/revoke/revoke-all)
  - recent activity
  - account JSON export
- Safer email utility configuration (no hardcoded credentials)
- Rebuilt frontend dashboard with:
  - fully wired forms for every tab
  - auto refresh-token retry on 401
  - activity filtering, trend mini-bars, and CSV export
  - toasts, loading states, sync status, connection status, and popup fallback
  - in-memory access-token handling backed by secure refresh cookies
  - appearance themes, density controls, high-contrast/reduced-motion options
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

Optional runtime globals:

- `window.__API_BASE_URL__`
- `window.__LOGIN_POPUP_URL__`

Default behavior now assumes the frontend and `/api/*` are available on the same HTTPS origin. That is the preferred deployment because it avoids exposing `:5000` to browsers and reduces cross-site cookie failures on restrictive networks.

## GitHub Pages Hosting

- A deploy workflow is included at `.github/workflows/deploy-pages.yml`.
- It publishes the `frontend/` folder to GitHub Pages and includes `CNAME`.
- In your GitHub repo settings, set Pages to **GitHub Actions** as the source.
- If your API is on a different origin, set backend `ALLOWED_ORIGINS` to include your Pages/custom domain.
- If you proxy the API through the same public host on `443`, leave the frontend on its default same-origin `/api/*` setup instead of pointing browsers at `:5000`.

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
- `GET /api/auth/sessions`
- `DELETE /api/auth/sessions/:sessionId`
- `DELETE /api/auth/sessions`
- `GET /api/auth/export`
- `DELETE /api/auth/account`
- `GET /api/auth/verify-email?token=...`

## Notes

- `ALLOWED_ORIGINS` is comma-separated. `localhost`/`127.0.0.1` are allowed automatically only in development, or when `ALLOW_LOCALHOST_ORIGINS=true`.
- `https://mpmc.ddns.net` is trusted by default for production CORS and popup handshakes.
- Login anti-bruteforce guardrails are configurable via `LOGIN_RATE_WINDOW_MS`, `LOGIN_RATE_MAX_ATTEMPTS`, and `LOGIN_BLOCK_MS`.
- Password updates invalidate existing refresh sessions and force re-login.
- Logout invalidates refresh sessions and clears auth cookie.
- Refresh cookies now use `SameSite=Lax` for same-origin HTTPS requests and only fall back to `SameSite=None` when the request is truly cross-site.
