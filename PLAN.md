# Qube Backend: Implementation Plan

Companion to `backend-plan.md` (the design doc). This file covers how we build it: stack, milestones, and where this plan departs from the design doc.

## Status (2026-10-02)

| Milestone | State |
|---|---|
| M0 Skeleton | Done |
| M1 Auth | Done |
| M2 SUN verification | Done in software: AN12196 vector passes. Not yet tested on real tags |
| M3 Taps and sessions | Done |
| M4 Admin API | Done |
| M5 Real tags + deploy | Not started: needs hardware, a domain, and a hosting choice |
| M6 Hardening | Not started |

74 tests pass. A live-server smoke test passed (create org → zone/tag → invite/join → lock/unlock/replay).

Differences from the original plan, found while building:
- **`events` table** (not in the design doc). It stores every tap and sync event with its outcome.
  This makes `client_event_id` idempotent across both endpoints, and lets a late-synced
  offline start close against an exit tap the server already handled (`orphan_end`).
- **Timezone-aware UTC datetimes** throughout. SQLModel now defaults to them, and they map
  cleanly to Postgres `timestamptz` later.
- **`BEGIN IMMEDIATE` for API requests** (via an execution option, see `app/db.py`).
  Otherwise a read-then-write transaction can fail instantly with SQLITE_BUSY in WAL mode.
- **One `routers/admin.py`** instead of four admin files. It's ~300 lines and can be split
  if it grows.
- **`scripts/provision_tag.py` prints keys and settings** instead of writing to the tag.
  Writing over a USB reader (pyscard) is a TODO for M5.

## Stack

| Concern | Choice |
|---|---|
| Runtime | Python 3.12, FastAPI, Uvicorn |
| ORM / migrations | SQLModel on SQLAlchemy 2.x, Alembic (`render_as_batch=True` for SQLite ALTERs) |
| Config | pydantic-settings (`QUBE_DB_URL`, `QUBE_JWT_SECRET`, `QUBE_MASTER_KEY`) |
| Auth | PyJWT (HS256), argon2-cffi for admin passwords |
| Crypto | `cryptography` (AES-128 ECB/CBC, CMAC) |
| Tests | pytest, httpx `TestClient`, a fresh temp SQLite file per test |
| Lint/format | ruff |
| Env | `python3.12 -m venv .venv` + `requirements.txt` (or uv if installed) |

## Changes to the design doc

These are places where the design doc is ambiguous or would cause bugs. Each is folded into the milestones below.

1. **Offline sync breaks the counter replay check.** With the `last_counter < :counter` rule, if an offline entry tap (counter 10) syncs *after* an online exit tap (counter 11) was verified, the entry tap is flagged as a replay even though it is genuine. **Fix:** add a `tag_taps` table with `UNIQUE(tag_uid, counter)`. A tap is fresh if the insert succeeds. Duplicate inserts are replays. This is still one atomic statement. Keep `tags.last_counter` as a high-water mark. For online `/taps/verify`, also reject counters far below it (e.g. more than 50 behind), so a stale sniffed URL can't be used live.
2. **Do the org and active checks before using up the counter.** Order: decrypt → verify CMAC → look up tag → check `active` and org → insert into `tag_taps`. Otherwise a tap from someone in another org uses up a counter value.
3. **Per-tag key derivation has a chicken-and-egg problem.** The encrypted PICC data has to be decrypted before we know the UID, so the *meta-read key* must be shared across tags (derived from the master key with no UID). Only the *SDM file-read/MAC key* is diversified per UID. This matches `sdm-backend` (`derive_undiversified_key` vs `derive_tag_key`). The provisioning script must write keys the same way.
4. **`/taps/verify` also takes a `client_event_id`.** Retries over a flaky connection then can't create duplicate sessions, and an online tap and its later sync upload dedupe against each other.
5. **Only one active session per user.** Enforce it with a partial unique index: `CREATE UNIQUE INDEX ... ON sessions(user_id) WHERE ended_at IS NULL`.
6. **Out-of-order offline events.** The app should flush its sync queue before calling `/taps/verify`. Server-side, `/sessions/sync` sorts events by `occurred_at` and handles an `end` whose `start` is unknown by creating a closed session marked `provisional`.
7. **Timezones.** `auto_unlock_time` needs one, so add `organizations.timezone` (IANA name). Store all timestamps in UTC. Session events store both `occurred_at` (client) and `received_at` (server).
8. **Long-lived JWTs need a revocation path.** Every authenticated request loads the user and rejects if `active = 0`. Tokens carry `sub`, `org_id`, `role`, `iat`. A `token_version` column on users lets us invalidate a user's tokens.
9. **Invite redemption must be atomic.** Use `UPDATE invites SET use_count = use_count + 1 WHERE code = :c AND revoked = 0 AND (max_uses IS NULL OR use_count < max_uses) AND (expires_at IS NULL OR expires_at > :now)`. One row updated means success. Add a `revoked` column so DELETE does a soft revoke.
10. **Rate limiting.** Add a small in-memory limiter on `/auth/join` and `/auth/admin-login` to stop brute force on invite codes and passwords. Invite codes should have at least 8 characters from an unambiguous alphabet.

## Project layout

```
app/
  main.py            # app factory, router registration, /health
  config.py          # pydantic-settings
  db.py              # engine, WAL + busy_timeout + foreign_keys pragmas, session dependency
  models.py          # SQLModel tables
  schemas.py         # request/response models (kept separate from tables)
  security.py        # JWT, password hashing, current_user / require_admin deps
  sun.py             # NTAG 424 SUN: key derivation, PICC decrypt, CMAC verify (pure, no DB)
  services/
    taps.py          # verify flow + session state machine (shared by /taps/verify and /sessions/sync)
    sessions.py
  routers/
    auth.py  me.py  devices.py  taps.py  sessions.py
    admin_zones.py  admin_tags.py  admin_people.py  admin_sessions.py
migrations/
scripts/
  create_org.py      # org + first admin
  provision_tag.py   # write keys to a tag via a USB reader, print UID
  gen_test_tap.py    # make valid SUN URLs from a fake tag for local testing
tests/
```

The key design point is that `services/taps.py` holds the tap state machine exactly once. Online verify and offline sync both call it, so the two paths can't diverge.

## Milestones

### M0: Skeleton
- venv, `requirements.txt`, ruff config, `.env.example`, `.gitignore`, `git init`.
- `db.py` sets `journal_mode=WAL`, `busy_timeout=5000`, `foreign_keys=ON` on every connect.
- All tables from the data model plus `tag_taps`, the first Alembic migration, `/health`.
- **Done when:** `alembic upgrade head` creates the DB and `/health` returns 200.

### M1: Auth
- `/auth/admin-login`, `/auth/join`, `/me`, `scripts/create_org.py`.
- `current_user`, `require_admin`, and an `org_id` that always comes from the token.
- `/devices` POST/DELETE (a device must belong to the caller).
- **Done when:** tests cover login, join (expired / revoked / max-uses / race), inactive-user rejection, and that a member can't reach admin routes.

### M2: SUN verification (highest risk, do early)
- `sun.py`: parse the URL params (`picc_data`, `cmac`, and `enc` if we use encrypted file data), decrypt the PICC data to get the UID and counter, derive keys, and compute the truncated CMAC over the SV2 session vector.
- Unit tests against the **NXP AN12196 published test vectors** before touching hardware, then cross-check against `sdm-backend` output.
- `scripts/gen_test_tap.py` simulates a tag so the rest of the backend can be built without hardware.
- Order 2–3 real NTAG 424 DNA tags plus a USB reader (e.g. ACR1252U) now, so they arrive by M4.
- **Done when:** the AN12196 vectors pass and a bad CMAC, tampered data, or wrong key is rejected.

### M3: Taps and sessions
- `services/taps.py`: verify → tag lookup → checks → `tag_taps` insert → state machine (entry / exit / toggle / zone change, idempotent repeats).
- `/taps/verify`, `/sessions/sync` (batch, sorted, dedupe by `client_event_id`, per-event result), `/me/state`, `/me/tags`.
- Sync verification results: `verified`, `failed` (bad CMAC or replay), `provisional` (no payload).
- **Done when:** the state machine has table-driven tests for every role × current state, and the out-of-order sync scenario from change 1 passes.

### M4: Admin API
- Zones CRUD (soft archive), tags (register, reassign, deactivate), invites, users (deactivate also ends active sessions), sessions list with filters and pagination, summary, emergency unlock (`admin_unlock` end reason).
- Every query goes through an `org_scoped(query, user)` helper.
- **Done when:** a cross-org test suite shows an admin from org A gets 404 (not 403) for every org B resource across every admin route.

### M5: Real-tag validation and deploy
- `provision_tag.py` against the real tags, then an end-to-end tap from a phone browser hitting `/t`, then `/taps/verify`.
- Deploy on Fly.io or a small VPS with a mounted volume, Litestream to S3/R2, secrets in the platform's secret store.
- **Done when:** a real tag tap verifies on the deployed server and a Litestream restore has been tested.

### M6: Hardening
- Session log retention job (a CLI run from cron), structured request logging that leaves out tap payloads and emails, and an OpenAPI export for the app and dashboard teams.

## Required tests (from design doc §13, expanded)
- Replay: same SUN URL twice → second is `replayed_tap`. Concurrent duplicate → exactly one passes.
- Duplicate sync events → no-op, same response.
- Out-of-order sync: online exit at counter N+1, then sync of the offline entry at N → both verified.
- Cross-org isolation on every admin route plus `/taps/verify` with another org's tag → `wrong_org`.
- Offline lock, then later online exit tap → session closed with `exit_tap`.
- Emergency unlock → `/me/state` shows no active session.

## Decisions needed before / during the build
- **SDM URL format:** PICC data plus CMAC only (simplest), or also encrypted file data? Recommend PICC + CMAC only.
- **Universal link domain** for the `/t` route. The iOS app needs it in its associated-domains entitlement early.
- **Hosting:** Fly.io (easy volumes) vs a VPS. Either works. Pick before M5.
