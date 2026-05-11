# YaraMail Sidecar: Deployment Guide and Interface Contract

The YaraMail sidecar is an optional, operator-supplied HTTP service that performs
YARA-based attachment scanning on behalf of PhishSOC. When configured, the Worker
dispatches each incoming email to the sidecar for analysis and incorporates the
resulting YARA signal into the verdict score. The sidecar is never on the critical
path: if it does not respond within 30 seconds, PhishSOC proceeds with the
pre-sidecar verdict and treats the absence of a signal as a non-error.

---

## Deployment Model

The sidecar runs as a Docker container and can be hosted anywhere it can receive
HTTP POST requests from Cloudflare Workers over the public internet (or, if you
route Workers egress through a private network, on a private endpoint):

| Platform      | Notes                                                                   |
|---------------|-------------------------------------------------------------------------|
| Google Cloud Run | Scale-to-zero; assign a stable HTTPS URL; use Cloud Run secrets for the HMAC secret. |
| Fly.io        | Small always-on VM; use Fly secrets for the HMAC secret.                |
| Self-hosted   | Any host reachable by the Worker; terminate TLS with nginx or Caddy.    |

Once the container is running, set its public URL in the mailbox settings under
**YaraMail scanner endpoint** (`yaraMailScanner.endpointUrl`). Each mailbox can
point to a different sidecar instance, or all mailboxes can share one.

---

## Inbound Payload (Worker → Sidecar)

The Worker sends a `POST` request to the configured endpoint with a JSON body
matching the following shape:

```json
{
  "emailId":    "01JMPnx2GMU9cpDWJzVHRwAa",
  "r2Key":      "raw/2026/05/01JMPnx2GMU9cpDWJzVHRwAa.eml",
  "mailboxId":  "mbx_abc123",
  "presignedUrl": "https://..."
}
```

### Field Descriptions

| Field          | Type   | Description                                                                                                    |
|----------------|--------|----------------------------------------------------------------------------------------------------------------|
| `emailId`      | string | Unique identifier for the email within PhishSOC.                                                               |
| `r2Key`        | string | R2 object key for the raw message. Only useful if the sidecar has direct R2 access via a service binding.      |
| `mailboxId`    | string | Identifies which mailbox received the email; used when posting the callback.                                   |
| `presignedUrl` | string | A time-limited URL the sidecar can use to `GET` the raw message bytes. **May be an empty string in the current release** (see note below). |

> **Note on `presignedUrl`:** Pre-signed URL support is still being rolled out.
> When `presignedUrl` is an empty string, the sidecar must fall back to fetching
> the attachment via the PhishSOC attachment download endpoint, using an API key
> provisioned in the sidecar's environment. Operators should implement this
> fallback path until pre-signed URL delivery is generally available.

The Worker sets `AbortSignal.timeout(30_000)` on the outbound request. If the
sidecar does not respond within **30 seconds** the Worker abandons the request,
skips the YARA signal, and continues scoring with the pre-sidecar verdict. No
error is surfaced to the operator or end user.

---

## Outbound Callback (Sidecar → Worker)

After completing the YARA scan the sidecar must `POST` its results back to
PhishSOC:

```
POST /api/v1/mailboxes/:mailboxId/yaramail-callback
```

where `:mailboxId` is the value received in the inbound payload.

### Callback Body

```json
{
  "emailId": "01JMPnx2GMU9cpDWJzVHRwAa",
  "matches": [
    { "rule_name": "pdf_phishing", "category": "phishing", "score": 20 },
    { "rule_name": "encrypted_zip", "category": "evasion", "score": 15 }
  ]
}
```

| Field              | Type             | Description                                                        |
|--------------------|------------------|--------------------------------------------------------------------|
| `emailId`          | string           | Must match the `emailId` from the inbound payload.                 |
| `matches`          | `YaraMatchResult[]` | Zero or more YARA rule matches (see structure below).           |

#### `YaraMatchResult` Structure

```ts
interface YaraMatchResult {
  rule_name: string;   // Name of the triggered YARA rule
  category?: string;   // Optional human-readable category tag
  score?: number;      // Optional override; defaults to DEFAULT_YARA_RULE_SCORES[rule_name]
}
```

If `score` is omitted, PhishSOC looks up `rule_name` in the default score table
(see [YARA Rule Score Mapping](#yara-rule-score-mapping) below). If the rule name
is not in the table and no inline `score` is provided, the match contributes **+5
points** (the unknown-rule default, from `workers/security/yaramail-signal.ts`).

### Authentication: HMAC-SHA256 Signature

Every callback request must include the header:

```
X-PhishSOC-Signature: <hex-encoded HMAC-SHA256>
```

The signature is computed over the raw JSON request body using the shared secret
stored in the Worker binding `YARAMAIL_CALLBACK_SECRET`. The sidecar must read
the same secret from its environment and produce a matching signature; the Worker
rejects callbacks with a missing or invalid signature.

**Signing algorithm (Python reference):**

```python
import hashlib, hmac, json, os

secret = os.environ["YARAMAIL_CALLBACK_SECRET"].encode()
body   = json.dumps(payload, separators=(",", ":")).encode()
sig    = hmac.new(secret, body, hashlib.sha256).hexdigest()
headers = {"X-PhishSOC-Signature": sig, "Content-Type": "application/json"}
```

---

## YARA Rule Score Mapping

The Worker applies the following default scores to matched rule names. Scores can
be overridden per-match by supplying an inline `score` value in `YaraMatchResult`.

| Rule Name         | Default Score | Description                                    |
|-------------------|:-------------:|------------------------------------------------|
| `pdf_phishing`    | 20            | PDF containing phishing indicators             |
| `macro_dropper`   | 25            | Office document with macro-based dropper       |
| `encrypted_zip`   | 15            | Password-protected / encrypted ZIP attachment  |
| `nested_archive`  | 10            | Archive-within-archive (evasion technique)     |
| `eml_attachment`  | 5             | Email-as-attachment (potential forwarding abuse) |

### Score Cap

Regardless of how many rules match, the combined YARA contribution to the verdict
score is capped at **+30** (`YARA_SCORE_CAP`). This prevents a flood of low-confidence
matches from overwhelming other signal channels.

---

## Timeout Behavior

| Scenario                                | Outcome                                                           |
|-----------------------------------------|-------------------------------------------------------------------|
| Sidecar responds within 30 s            | YARA matches are scored and merged into the verdict.              |
| Sidecar times out (> 30 s)              | YARA signal is skipped; verdict proceeds without it. No error.    |
| Sidecar returns an HTTP error (4xx/5xx) | YARA signal is skipped; verdict proceeds without it. No error.    |
| Sidecar endpoint not configured         | YARA stage is bypassed entirely. No error.                        |

The absence of a YARA signal is **never treated as an error state**. PhishSOC
degrades gracefully when the sidecar is unavailable, overloaded, or deliberately
disabled.

---

## Security Notes

1. **Do not persist raw message bytes.** The sidecar receives the full email (via
   `presignedUrl` or the attachment endpoint) solely to run the YARA scan. Raw
   message content must be discarded immediately after scanning — it must not be
   written to disk, logged, or forwarded to any third-party service.

2. **Validate the inbound request source.** The Worker does not currently sign the
   inbound dispatch payload. Operators should restrict the sidecar's listening
   address or use network-layer controls (Cloud Run IAM, Fly.io private networking,
   firewall rules) to ensure only the PhishSOC Worker can reach it.

3. **Rotate `YARAMAIL_CALLBACK_SECRET` regularly.** Because the secret is shared
   between the Worker and the sidecar, compromise of either side exposes it. Use
   your platform's secret-management tooling (Wrangler secrets, Cloud Run Secret
   Manager, Fly secrets) to rotate it without downtime.

4. **TLS required.** The sidecar endpoint URL configured in mailbox settings must
   use `https://`. Plain-HTTP endpoints are rejected by the Worker.

---

## Database Schema

Scan results are persisted in the `yaramail_scan_results` Durable Object table
(migration `20_yaramail_scan_results`):

```sql
CREATE TABLE yaramail_scan_results (
  email_id   TEXT    PRIMARY KEY,
  results    JSON    NOT NULL,
  scanned_at INTEGER NOT NULL
);
```

`results` stores the raw `YaraMatchResult[]` array; `scanned_at` is a Unix
timestamp (seconds). Rows are written by the Worker after a successful callback
and are used to populate the verdict audit trail.

---

## Quick Start: Running the Example Stub

A minimal FastAPI stub is provided in `sidecar/example/` to illustrate the
expected request/response shape. It is **not** a production implementation.

```bash
cd sidecar/example
pip install -r requirements.txt
YARAMAIL_CALLBACK_SECRET=dev-secret uvicorn main:app --port 8080
```

The stub listens on `POST /scan`, runs a placeholder YARA scan, and posts the
callback to `http://localhost:8787` (configurable via `PHISHSOC_BASE_URL`).
