# CLAUDE.md

This file is loaded into Claude Code sessions working on this repo. It captures
conventions surfaced by real incidents so future agents inherit the lesson
without re-discovering it. Keep entries grounded in observed events; this is a
seed, not a comprehensive style guide.

## Conventions

### URL host checks in test mocks must parse, not substring

When a test routes mock `fetch` responses by URL, do **not** match with
`url.startsWith("https://example.com")` or `url.includes("example.com")`.
CodeQL's `js/incomplete-url-substring-sanitization` rule (high severity) flags
those patterns as an SSRF / redirect-bypass risk even in test-only code, and
PRs are gated on CodeQL — the alert blocks merge.

Parse the URL and compare the parsed `hostname` instead:

```ts
// BAD
if (url.startsWith("https://cti.api.crowdsec.net")) { ... }

// GOOD
if (new URL(url).hostname === "cti.api.crowdsec.net") { ... }

// GOOD (host + path)
const u = new URL(url);
if (u.hostname === "cti.api.crowdsec.net" && u.pathname.startsWith("/v2/smoke/")) {
  ...
}
```

This applies to both mock dispatchers (deciding which canned response to
return) and assertions (`expect(call[0]).startsWith(...)` → use the parsed
equivalent).

Origin: PR #130 (CrowdSec CTI deep-scan) — five test-only URL substring checks
tripped CodeQL and required a fixup commit.

### Don't race a SECURITY_SPEC.md update against a parallel doc PR

`SECURITY_SPEC.md` codifies invariants the security pipeline enforces. When a
code change narrows or extends one of those invariants, the spec needs to
follow — but if both the code change and a separate spec-document PR are open
at the same time, editing the spec from inside the code PR guarantees a merge
conflict on whichever lands second.

Instead:

1. Land the code change first with the new behavior.
2. In that PR's body, note: `follows up: narrow SECURITY_SPEC.md Rule N once
   #<spec-PR-num> lands.`
3. After both predecessors are on `main`, file a small `docs:` PR doing the
   narrowing.

Origin: PR #132 (Closes #28) changed Rule 5's timeout-vs-parse-fail behavior,
deferred the spec edit to avoid racing PR #119 (which introduced the spec),
and PR #134 narrowed the rule once both had landed.
