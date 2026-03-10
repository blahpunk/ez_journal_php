# ez_journal_php

Single-file PHP journal/blog app with:
- Google OAuth session integration via an external auth service
- role-based visibility for entries (`Guest`, named users, editor/admin)
- one fallback PIN account for admin/editor access when OAuth is unavailable
- Quill-powered rich text editing for editors
- SQLite storage

## Requirements
- PHP 8.1+
- PHP extensions: `pdo_sqlite`, `dom`, `session`
- `openssl` CLI (optional fallback for scrypt hashing)
- A writable SQLite database path

## Authentication Model
- Primary auth: Google OAuth handled by an external service.
- This app trusts the signed `user` / `user_sig` cookies (`SECURE_AUTH_SECRET`).
- Local `/login` sends users to the OAuth login endpoint.
- `/pin-login` is reserved for the fallback PIN account.

## Configuration
The app auto-loads environment variables from `.env` (if present), without overriding already-exported shell vars.

| Variable | Default | Notes |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///.data/journal.db` | Only `sqlite:///...` URLs are supported. DB directory is auto-created if missing. |
| `SECRET_KEY` | `change-me` | Legacy app secret; keep non-default in production. |
| `LOG_PATH` | `.logs/journal.log` | PIN login attempt log path. Log directory is auto-created if missing. |
| `OAUTH_LOGIN_URL` | `https://secure.example.com/oauth_login` | External Google OAuth login endpoint. |
| `OAUTH_LOGOUT_URL` | `https://secure.example.com/logout` | External OAuth logout endpoint. |
| `SECURE_AUTH_SECRET` | empty | Active HMAC secret for validating `user` cookie signature. |
| `SECURE_AUTH_PREVIOUS_SECRETS` | empty | Comma-separated previous secrets accepted during rotation overlap. |
| `FLASK_SECRET_KEY` | empty | Fallback secret if `SECURE_AUTH_SECRET` is unset. |
| `JOURNAL_ADMIN_EMAIL` | `admin@example.com` | Canonical Admin OAuth identity. |
| `JOURNAL_SECONDARY_OAUTH_EMAIL` | empty | Optional extra OAuth identity email. |
| `JOURNAL_SECONDARY_OAUTH_LABEL` | empty | Optional extra OAuth identity label. |
| `JOURNAL_SECONDARY_OAUTH_NAME` | empty | Optional display name for extra OAuth identity. |
| `JOURNAL_SECONDARY_OAUTH_IS_EDITOR` | `false` | Optional editor access for extra OAuth identity. |
| `JOURNAL_FALLBACK_ADMIN_LABEL` | `Fallback Admin` | Fallback PIN account label (used by `/pin-login`). |
| `JOURNAL_FALLBACK_ADMIN_PIN` | `change-me` | Fallback PIN (set securely in production). |
| `JOURNAL_FALLBACK_ADMIN_IS_EDITOR` | `true` | Gives fallback PIN account editor/admin-level write access. |
| `JOURNAL_PIN_LABEL` | empty | Backward-compatible alias for fallback label (only used if `JOURNAL_FALLBACK_ADMIN_LABEL` is unset). |
| `PIN_USER_PIN` | empty | Backward-compatible alias for fallback PIN (only used if `JOURNAL_FALLBACK_ADMIN_PIN` is unset). |
| `JOURNAL_TIMEZONE` | `America/Chicago` | App display/input timezone (for St. Louis, use `America/Chicago`). |
| `APP_TIMEZONE` | empty | Backward-compatible alias for `JOURNAL_TIMEZONE`. |
| `ADMIN_SESSION_TTL_SECONDS` | `315360000` | Persistent admin session TTL floor is 1 day. |
| `SITE_TITLE` | `Journal` | Navbar/site title text. |
| `HOME_URL` | `/` | Home button URL in top nav. |
| `MATOMO_BASE_URL` | empty | Optional Matomo base URL (for example `https://analytics.example.com`). |
| `MATOMO_SITE_ID` | empty | Optional Matomo site id; used only when `MATOMO_BASE_URL` is set. |

Entry times are stored in UTC and converted to your app timezone for display/editing.

## Local Run
Example local setup:

```bash
cp .env-sample .env
# edit .env with your OAuth URLs, secrets, and fallback admin PIN
php -S 127.0.0.1:8080 index.php
```

Then open `http://127.0.0.1:8080`.

`.env` is ignored by git. `.env-sample` is committed as the template.

## Migration Behavior
At startup, the app auto-migrates `user` auth fields and canonical identities:
- `Admin` is OAuth-mapped to `JOURNAL_ADMIN_EMAIL` and set editor.
- Optional secondary OAuth identity is mapped when `JOURNAL_SECONDARY_OAUTH_EMAIL` and `JOURNAL_SECONDARY_OAUTH_LABEL` are set.
- The fallback PIN account is mapped to `JOURNAL_FALLBACK_ADMIN_LABEL` and its editor access is controlled by `JOURNAL_FALLBACK_ADMIN_IS_EDITOR`.
- Existing `entry_viewers` permissions are preserved.
