# ez_journal_php

Single-file PHP journal/blog app with:
- PIN-based login and lockout protection
- role-based visibility for entries (`Guest`, users, editor/admin)
- Quill-powered rich text editing for editors
- SQLite storage

## Requirements
- PHP 8.1+
- PHP extensions: `pdo_sqlite`, `dom`, `session`
- `openssl` CLI (optional fallback for scrypt hashing)
- A writable SQLite database path

## Configuration
The app reads these environment variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:////var/lib/ez_journal/journal.db` | Only `sqlite:///...` URLs are supported. |
| `SECRET_KEY` | `change-me` | Set this in production. |
| `ADMIN_PIN` | `0000` | Used only when creating the initial admin user. |
| `LOG_PATH` | `/var/www/log/journal.log` | Login attempt log file path. |

Timezone is set in code to `America/Chicago`.

## Local Run
Example local setup using paths inside this repo:

```bash
mkdir -p .data .logs
export DATABASE_URL="sqlite:///$PWD/.data/journal.db"
export LOG_PATH="$PWD/.logs/journal.log"
export SECRET_KEY="replace-with-random-secret"
export ADMIN_PIN="1234"
php -S 127.0.0.1:8080 index.php
```

Then open `http://127.0.0.1:8080`.

## Notes
- This repo currently does not include migrations. The app expects existing `user`, `entry`, and `entry_viewers` tables; it auto-creates only `login_lockout`.
- On first run with an empty user table, it creates an `Admin` user using `ADMIN_PIN` and a `Guest` user with id `0`.
