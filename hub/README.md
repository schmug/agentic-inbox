# AIS Hub

A community threat-intel hub for the Agentic Inbox Security project. MISP-compatible (subset). Runs on Cloudflare Workers + D1 + Queues.

## Supported API surface

This is not a full MISP implementation. Adopters needing complete MISP functionality should run a real MISP instance; this is a minimal reference aimed at the phishing-report-and-feed-pull loop.

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `POST` | `/events` | API key | MISP event schema; upserts attributes, runs corroboration. |
| `GET` | `/events/{uuid}` | API key | Visibility scoped to own org + sharing-group membership. |
| `POST` | `/events/restSearch` | API key | Filters: `type`, `value`, `limit`, `page`. |
| `GET` | `/feeds/destroylist.txt` | API key | Plain-text list of promoted attributes. |
| `GET` | `/sharing_groups` | API key | Own groups only. |
| `POST` | `/sharing_groups` | API key | Caller becomes owner. |
| `POST` | `/orgs/invite` | API key | Issues one-time token, optionally binds to a sharing group. |
| `POST` | `/orgs/accept` | (public) | Redeems token; returns new `api_key` (shown once). |
| `GET` | `/orgs/me` | API key | Authenticated org. |

## Auth

Header is either `Authorization: <key>` (MISP convention) or `Authorization: Bearer <key>`.

## Trust-weighted aggregation

`hub/src/lib/aggregate.ts` implements a simple score model:

- On each `POST /events`, each attribute value gets a per-(type, value, sharing_group) row in `corroboration`.
- A distinct contributor org adds `org.trust` points (default 1.0). Repeat contributions from the same org don't re-add trust.
- An attribute promotes to the sharing group's `destroylist.txt` when `score ≥ 2.0` and `contributor_count ≥ 2`.

Tune the thresholds in `aggregate.ts`. Manual trust adjustments on `orgs.trust` let you amplify or dampen specific contributors.

## Agent triage

`hub/src/agent/triage.ts` is a Queue consumer that runs Workers AI against each new event to propose MISP taxonomy tags. **LLM output never affects scoring** — tags are the only mutation the triage agent makes. This is a deliberate invariant: attacker-crafted content is in its input, so anything it returns has to be non-load-bearing.

## Bootstrap

```bash
# 1. create D1 database, note the id, paste into wrangler.jsonc
npx wrangler d1 create ais-hub

# 2. apply schema
npm run db:migrate:remote

# 3. create queue
npx wrangler queues create ais-hub-triage

# 4. deploy
npm run deploy

# 5. seed a bootstrap org + key (via SQL — no self-serve signup in MVP)
npx wrangler d1 execute ais-hub --remote --command "
  INSERT INTO orgs (uuid, name) VALUES ('<ORG_UUID>', 'bootstrap');
  INSERT INTO api_keys (key_hash, org_uuid, label) VALUES ('<sha256_of_key>', '<ORG_UUID>', 'bootstrap');
"
```

## Security notes

- API keys are stored as SHA-256 hashes — D1 leaks don't permit impersonation.
- Invite tokens are hashed identically.
- Event visibility is enforced on read via `orgc_uuid` + `sharing_group_uuid` checks — no tenant can read another tenant's non-shared events.
- Prompt-injection defense for the triage agent: the LLM only controls tags, not scores or promotions.

## Future work

- STIX 2.1 export on `/events/{uuid}` (content negotiation).
- Server-to-server sync with real MISP instances (`/events/index`, `/servers/pull`).
- Per-attribute confidence decay over time (cron already wired; logic TBD).
