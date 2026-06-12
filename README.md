# LatentDB

A multi-tenant, metadata-driven object database platform: kernel (tenancy,
RBAC/ABAC, workflow, audit), product HTTP API, BI analytics, and optional AI
agents.

## Quick start

```bash
cargo run -p latentdb-api -- serve
```

On a fresh install no tenant exists yet, so the very first
`POST /v1/bootstrap` requires no credential. Every later call to that endpoint
is platform-admin only.

```bash
curl -s -X POST localhost:8080/v1/bootstrap -H 'content-type: application/json' -d '{
  "name": "Acme", "slug": "acme",
  "admin_email": "admin@acme.test", "admin_name": "Admin",
  "admin_password": "change-me-now"
}'
```

## Security model

* **Tenant isolation** — every kernel service takes an `AuthContext` and scopes
  queries to its tenant; there is no un-scoped query path.
* **Credentials** — passwords are Argon2id-hashed; session/API tokens are
  random 256-bit secrets stored only as SHA-256 hashes. Password policy:
  8–128 characters.
* **Login hardening** — per-identity rate limiting (10 failures / 15 min),
  timing-equalized unknown-user path, case-insensitive emails, and an
  `auth.login.failed` audit event for every failed attempt.
* **Credential lifecycle** — disabling a user (`POST /v1/users/:id/status`)
  revokes their sessions and invalidates their API keys; suspending a tenant
  (`POST /v1/tenants/:id/status`, platform admin) cuts off all of its
  credentials immediately.
* **API keys** — can only be minted for active principals inside the caller's
  tenant.
* **HTTP surface** — security headers + `x-request-id` on every response,
  1 MiB request body cap, configurable CORS allowlist.
* **Approvals** — optional separation of duties: the requester of a gated
  workflow transition may not decide their own approval
  (`LATENTDB_ENABLE_APPROVAL_SEPARATION_OF_DUTIES=1`).

## Operations / configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `LATENTDB_ADDR` | `0.0.0.0:8080` | Listen address |
| `LATENTDB_DATABASE_URL` | `latentdb.db` | SQLite file or `:memory:` |
| `LATENTDB_MAX_CONNECTIONS` | `8` | SQLite pool size (1–64) |
| `LATENTDB_SESSION_TTL_DAYS` | `30` | Session lifetime (1–365) |
| `LATENTDB_CORS_ALLOWED_ORIGINS` | permissive | Comma-separated origin allowlist; set this in production |
| `LATENTDB_LOG` | `info` | Tracing filter |
| `LATENTDB_ENABLE_*` | see `flags.rs` | Feature flags (AI, metering, ABAC, …) |

The server shuts down gracefully on SIGINT/SIGTERM and runs hourly
housekeeping (expired-session purge, rate-limit window pruning).

Per-tenant usage metering (`api_calls`, monthly periods) is on by default and
readable at `GET /v1/usage`.

## Development

```bash
cargo test --workspace   # full suite, in-memory SQLite
cargo clippy --workspace --all-targets
```
