#!/usr/bin/env bash
# PreToolUse hook: enforce two PhishSOC invariants before an Edit/Write lands.
#
# Invariant 1 (root CLAUDE.md): every BUCKET.put to a settings-tier key
#   (mailboxes/<id>.json, domains/<domain>.json, org/settings.json) must
#   include a stripDefaultEqual() call in the same change.
#
# Invariant 2 (root CLAUDE.md): any fetch() in an mta-sts file must use
#   redirect: "manual" (RFC 8461 §3.3 forbids following redirects).
#
# Receives Claude Code tool JSON on stdin; exits 0 on clean, 1 on violation.

set -uo pipefail

input=$(cat)

# Parse via python3; fall back to allow (exit 0) on any parse error
tool_name=$(
  printf '%s' "$input" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('tool_name', ''))
except Exception:
    print('')
" 2>/dev/null
) || true

# Only inspect Edit and Write
if [[ "$tool_name" != "Edit" && "$tool_name" != "Write" ]]; then
  exit 0
fi

file_path=$(
  printf '%s' "$input" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('tool_input', {}).get('file_path', ''))
except Exception:
    print('')
" 2>/dev/null
) || true

new_content=$(
  printf '%s' "$input" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ti = d.get('tool_input', {})
    # Edit supplies new_string; Write supplies content
    print(ti.get('new_string', ti.get('content', '')))
except Exception:
    print('')
" 2>/dev/null
) || true

# --- Invariant 1: settings-tier BUCKET.put without stripDefaultEqual ---
# Trigger: new content adds BUCKET.put AND references a settings-tier path
# but does NOT include stripDefaultEqual in the same block.
if printf '%s' "$new_content" | grep -q 'BUCKET\.put'; then
  if printf '%s' "$new_content" | grep -qE '(mailboxes/|domains/|org/settings\.json)'; then
    if ! printf '%s' "$new_content" | grep -q 'stripDefaultEqual'; then
      printf '\nERROR [PhishSOC hook]: settings-tier BUCKET.put without stripDefaultEqual.\n' >&2
      printf 'Every write to mailboxes/<id>.json, domains/<domain>.json, or\n' >&2
      printf 'org/settings.json must route the payload through\n' >&2
      printf 'stripDefaultEqual(...) before BUCKET.put.\n' >&2
      printf 'See root CLAUDE.md ("stripDefaultEqual runs on every settings-tier write").\n\n' >&2
      exit 1
    fi
  fi
fi

# --- Invariant 2: fetch() in mta-sts file without redirect: "manual" ---
# Trigger: file path contains "mta-sts", new content introduces a fetch()
# call, and redirect: "manual" is absent from the same new content.
if printf '%s' "$file_path" | grep -q 'mta-sts'; then
  if printf '%s' "$new_content" | grep -qE '\bfetch\('; then
    if ! printf '%s' "$new_content" | grep -qE 'redirect[[:space:]]*:[[:space:]]*("manual"|'"'"'manual'"'"')'; then
      printf '\nERROR [PhishSOC hook]: fetch() in MTA-STS file without redirect: "manual".\n' >&2
      printf 'RFC 8461 §3.3 forbids following redirects when fetching MTA-STS policies\n' >&2
      printf '(a redirect could substitute a permissive attacker-controlled policy).\n' >&2
      printf 'Add redirect: "manual" to the fetch() options.\n' >&2
      printf 'See root CLAUDE.md MTA-STS invariant.\n\n' >&2
      exit 1
    fi
  fi
fi

exit 0
