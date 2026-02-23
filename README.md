# ez_journal_php

Single-file PHP journal/blog app with:
- Google OAuth session integration via `secure.blahpunk.com`
- role-based visibility for entries (`Guest`, named users, editor/admin)
- one fallback PIN account (`J.`)
- Quill-powered rich text editing for editors
- SQLite storage

## Requirements
- PHP 8.1+
- PHP extensions: `pdo_sqlite`, `dom`, `session`
- `openssl` CLI (optional fallback for scrypt hashing)
- A writable SQLite database path

## Authentication Model
- Primary auth: Google OAuth handled by `secure.blahpunk.com`.
- This app trusts the signed `user` / `user_sig` cookies (`SECURE_AUTH_SECRET`).
- Local `/login` sends users to the OAuth login endpoint.
- `/pin-login` is reserved for the private fallback PIN user.

## Configuration
The app reads these environment variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:////var/lib/ez_journal/journal.db` | Only `sqlite:///...` URLs are supported. |
| `SECRET_KEY` | `change-me` | Legacy app secret; keep non-default in production. |
| `LOG_PATH` | `/var/www/log/journal.log` | PIN login attempt log path. |
| `OAUTH_LOGIN_URL` | `https://secure.blahpunk.com/oauth_login` | External Google OAuth login endpoint. |
| `OAUTH_LOGOUT_URL` | `https://secure.blahpunk.com/logout` | External OAuth logout endpoint. |
| `SECURE_AUTH_SECRET` | empty | HMAC secret for validating `user` cookie signature. |
| `FLASK_SECRET_KEY` | empty | Fallback secret if `SECURE_AUTH_SECRET` is unset. |
| `JOURNAL_ADMIN_EMAIL` | `eric.zeigenbein@gmail.com` | Canonical Admin OAuth identity. |
| `JOURNAL_DAMIAN_EMAIL` | `ionru404@gmail.com` | Canonical Damian OAuth identity. |
| `JOURNAL_PIN_LABEL` | `J.` | Canonical fallback PIN user label. |
| `PIN_USER_PIN` | `09111984` | Fallback PIN for `J.` (set securely in production). |

Timezone is set in code to `America/Chicago`.

## Local Run
Example local setup using paths inside this repo:

```bash
mkdir -p .data .logs
export DATABASE_URL="sqlite:///$PWD/.data/journal.db"
export LOG_PATH="$PWD/.logs/journal.log"
export SECURE_AUTH_SECRET="replace-with-shared-auth-secret"
export JOURNAL_ADMIN_EMAIL="eric.zeigenbein@gmail.com"
export JOURNAL_DAMIAN_EMAIL="ionru404@gmail.com"
export PIN_USER_PIN="09111984"
php -S 127.0.0.1:8080 index.php
```

Then open `http://127.0.0.1:8080`.

## Migration Behavior
At startup, the app auto-migrates `user` auth fields and canonical identities:
- `Admin` is OAuth-mapped to `JOURNAL_ADMIN_EMAIL` and set editor.
- `Damian` is OAuth-mapped to `JOURNAL_DAMIAN_EMAIL`.
- `J.` remains PIN-authenticated.
- Existing `entry_viewers` permissions are preserved.
