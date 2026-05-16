# hub/ — MISP-compatible Threat-Intel Hub

Additive to root CLAUDE.md. Hub-specific conventions only.

The hub is a **separate deployment** (Worker `ais-hub`) with its own D1 database, migrations, test suite, and CI job. It is nearly independent of the main PhishSOC Worker.

## Scoped commands

Run from the **`hub/` directory**:

```bash
npm test           # vitest run — hub/tests/
npm run typecheck  # wrangler types && tsc --noEmit

# D1 migrations
npm run db:migrate:local   # apply migrations locally
npm run db:migrate:remote  # apply migrations to production
```

The root `npm test` does **not** cover hub tests — use the scoped command above or rely on the dedicated `Typecheck & Test (hub)` CI job in `.github/workflows/ci.yml`.

## Code layout

- **`hub/src/index.ts`** — Hono entry point; all API routes.
- **`hub/src/routes/`** — Route handlers (events, feeds, orgs, sharing groups, admin peers).
- **`hub/src/lib/`** — Core logic: `sync.ts` (MISP inbound pull), `aggregate.ts` (attribute promotion), `push.ts` (outbound push stub).
- **`hub/src/agent/`** — Optional AI agent for hub-level analysis.
- **`hub/src/types.ts`** — Hub-specific `Env` and domain types.
- **`hub/migrations/`** — D1 SQL migrations. Add a new `.sql` file for every schema change; never edit existing migrations.
- **`hub/tests/`** — Vitest tests scoped to the hub.
- **`hub/wrangler.jsonc`** — Hub's own Worker config (name: `ais-hub`, D1 binding, AI binding).

## Key invariants

- **MISP-compatible API format.** Existing MISP peers and the main app's destroylist pull depend on the response shape — don't change field names or status codes without verifying compatibility.
- **Attribute promotion is sybil-resistant:** `score ≥ 2.0 AND contributors ≥ 2` (see `hub/src/lib/aggregate.ts`). Don't lower this threshold without a security review.
- **Loop prevention on pull:** `hub/src/lib/sync.ts` skips events where `orgc_uuid` matches our own org UUID. Preserve this check when modifying sync logic.
- **Admin routes use `HUB_ADMIN_KEY`.** Per-org API routes use per-org `Authorization` bearer tokens (SHA-256 hashed in D1). Don't mix the two auth models.
