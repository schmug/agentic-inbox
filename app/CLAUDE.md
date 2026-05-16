# app/ — React Router v7 SPA

Additive to root CLAUDE.md. Frontend-specific conventions only.

## Scoped commands

Run from the **repo root**:

```bash
npm test           # vitest run — includes tests/frontend/
npm run typecheck  # cf-typegen + react-router typegen + tsc -b
```

`react-router typegen` regenerates `app/routes.ts` type stubs; run typecheck before assuming types are current.

## Code layout

- **`app/routes/`** — React Router route modules. One file per page (`home.tsx`, `mailbox.tsx`, `settings.tsx`, etc.).
- **`app/components/`** — Shared UI components. Uses **Cloudflare Kumo** design system (`@cloudflare/kumo`) for all primitives (Button, Input, Dialog, etc.).
- **`app/hooks/`** — Custom hooks. `useUIStore` owns global UI state (compose modal open/close, active mailbox, etc.).
- **`app/queries/`** — React Query wrappers. One file per domain (`mailboxes.ts`, `emails.ts`, `domains.ts`, etc.). All server data fetching goes through these wrappers — don't call `fetch` directly from components.
- **`app/services/api.ts`** — Typed API client (`get`, `post`, `put`, `patch`, `del` helpers). All new API calls are added here, not inlined in components.
- **`app/lib/`** — Pure frontend utilities (feedback toasts, compose helpers, etc.).
- **`app/types/`** — TypeScript types shared across the SPA.

## Test conventions

Frontend tests live in `tests/frontend/`. URL mock dispatchers must use `new URL(url).pathname` or `new URL(url).hostname === 'hostname'` — never `url.startsWith(...)` or `url.includes(...)` (CodeQL gate, root CLAUDE.md Rule 1).

Use `renderWithProviders` from `tests/frontend/test-utils.tsx` and `tests/frontend/shell-mocks.ts` for mocking shell queries.
