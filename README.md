# Qube backend

FastAPI + SQLite backend for the Qube NFC focus product. See `PLAN.md` for the build plan
and the design decisions behind it.

## Setup

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
cp .env.example .env          # then set QUBE_JWT_SECRET and QUBE_MASTER_KEY
.venv/bin/alembic upgrade head
.venv/bin/python -m scripts.create_org --name "Snell Library" \
    --timezone America/New_York --admin-email you@example.edu
.venv/bin/uvicorn app.asgi:app --reload
```

API docs: http://localhost:8000/docs

## Tests

```bash
.venv/bin/pytest
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

## Working without tags

`scripts/gen_test_tap.py` simulates an NTAG 424 DNA tag using `QUBE_MASTER_KEY`:

```bash
.venv/bin/python -m scripts.gen_test_tap 04AABBCCDDEEFF 1 --json   # body "tap" for /taps/verify
```

Counters must go up (or at least never repeat) per tag, like a real tag's would.

## Provisioning a real tag

```bash
.venv/bin/python -m scripts.provision_tag <UID> --base-url https://<domain>/t
```

This prints the keys and SDM settings to write onto the tag. Then register the UID with
`POST /admin/tags`. The master key never goes through the API.

## Layout

```
app/
  main.py               app factory, /health, /t landing page
  config.py             settings from QUBE_* env vars
  db.py                 engine: WAL, busy timeout, BEGIN IMMEDIATE for requests
  models.py             tables
  schemas.py            request/response models
  security.py           JWT, password hashing, auth deps, rate limiter
  sun.py                NTAG 424 SUN decrypt + CMAC verification (pure)
  services/taps.py      tap checks + session state machine (online and sync)
  services/sessions.py  zone rules, deadlines, lazy timer expiry
  routers/              auth, me, devices, taps (+ sync), admin
migrations/             Alembic
scripts/                create_org, provision_tag, gen_test_tap
tests/
```

## Things to know

- **Replay protection** is the `tag_taps` table, where each (tag, counter) pair can be used
  once. Online taps are also rejected if far below the tag's highest counter. Offline syncs
  aren't, so late uploads still verify.
- **Every device event is stored** in `events` with its `client_event_id`. Retrying any
  upload returns the stored result.
- **Sessions close lazily.** A session past `max_lock_minutes` or `auto_unlock_time` is
  ended with reason `timer` the next time it's read, timestamped at the deadline.
- **Admin emergency unlock is best-effort.** Phones learn about it on their next
  `GET /me/state` poll, until push notifications exist.
- **Timestamps** are stored and returned as UTC (`...Z`).
