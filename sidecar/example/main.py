"""
YaraMail sidecar example stub — NOT for production use.

This stub illustrates the expected request/response shape between PhishSOC
and a YARA-scanning sidecar service.  Real implementations should:

  - Fetch the raw message from `presignedUrl` (or the PhishSOC attachment
    endpoint when `presignedUrl` is empty).
  - Run a full YARA ruleset against the message and its attachments.
  - Discard raw message bytes immediately after the scan.
  - Validate inbound requests via network controls (not implemented here).

Environment variables
---------------------
YARAMAIL_CALLBACK_SECRET  Shared HMAC-SHA256 secret (required).
PHISHSOC_BASE_URL         Base URL of the PhishSOC instance that dispatched
                          the scan.  Defaults to http://localhost:8787.
"""

import hashlib
import hmac
import json
import logging
import os
from typing import List, Optional

import httpx
import yara  # type: ignore[import-untyped]
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("yaramail-sidecar")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CALLBACK_SECRET: bytes = os.environ.get("YARAMAIL_CALLBACK_SECRET", "").encode()
PHISHSOC_BASE_URL: str = os.environ.get("PHISHSOC_BASE_URL", "http://localhost:8787").rstrip("/")

if not CALLBACK_SECRET:
    raise RuntimeError("YARAMAIL_CALLBACK_SECRET environment variable is required")

# ---------------------------------------------------------------------------
# Placeholder YARA rules — replace with your actual ruleset.
# ---------------------------------------------------------------------------

YARA_RULES_SOURCE = """
rule pdf_phishing {
    meta:
        description = "PDF containing phishing indicators"
    strings:
        $uri = /\/URI\s*\(https?:\/\//
        $js  = "/JavaScript"
    condition:
        $uri and $js
}

rule macro_dropper {
    meta:
        description = "Office document with macro-based dropper"
    strings:
        $ole  = { D0 CF 11 E0 }
        $auto = "AutoOpen" nocase
    condition:
        $ole and $auto
}

rule encrypted_zip {
    meta:
        description = "Password-protected ZIP attachment"
    strings:
        $pk   = { 50 4B 03 04 }
        $flag = { 01 00 }
    condition:
        $pk and $flag at 6
}

rule nested_archive {
    meta:
        description = "Archive-within-archive"
    strings:
        $rar = { 52 61 72 21 }
        $pk  = { 50 4B 03 04 }
    condition:
        $rar and $pk
}

rule eml_attachment {
    meta:
        description = "Email-as-attachment"
    strings:
        $mime = "Content-Type: message/rfc822" nocase
    condition:
        $mime
}
"""

_compiled_rules: Optional[yara.Rules] = None  # type: ignore[name-defined]


def get_rules() -> "yara.Rules":  # type: ignore[name-defined]
    global _compiled_rules
    if _compiled_rules is None:
        _compiled_rules = yara.compile(source=YARA_RULES_SOURCE)
    return _compiled_rules


# ---------------------------------------------------------------------------
# Data models (mirror workers/security/yaramail-signal.ts)
# ---------------------------------------------------------------------------

class YaraScanPayload(BaseModel):
    emailId: str
    r2Key: str
    mailboxId: str
    presignedUrl: str  # may be empty string in current release


class YaraMatchResult(BaseModel):
    rule_name: str
    category: Optional[str] = None
    score: Optional[int] = None


class YaraCallbackBody(BaseModel):
    emailId: str
    matches: List[YaraMatchResult]


# ---------------------------------------------------------------------------
# HMAC helper
# ---------------------------------------------------------------------------

def sign_body(body: bytes) -> str:
    """Return hex-encoded HMAC-SHA256 of *body* using CALLBACK_SECRET."""
    return hmac.new(CALLBACK_SECRET, body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Scan logic
# ---------------------------------------------------------------------------

def fetch_message(payload: YaraScanPayload) -> bytes:
    """
    Retrieve raw message bytes.

    Uses presignedUrl when available; otherwise falls back to the PhishSOC
    attachment download endpoint (requires PHISHSOC_API_KEY in environment).
    """
    if payload.presignedUrl:
        logger.info("Fetching message via presignedUrl for emailId=%s", payload.emailId)
        resp = httpx.get(payload.presignedUrl, timeout=25)
        resp.raise_for_status()
        return resp.content

    # Fallback: PhishSOC attachment endpoint
    api_key = os.environ.get("PHISHSOC_API_KEY", "")
    if not api_key:
        raise RuntimeError(
            "presignedUrl is empty and PHISHSOC_API_KEY is not set; "
            "cannot fetch message for emailId=" + payload.emailId
        )
    url = f"{PHISHSOC_BASE_URL}/api/v1/mailboxes/{payload.mailboxId}/emails/{payload.emailId}/raw"
    logger.info("Fetching message via attachment endpoint: %s", url)
    resp = httpx.get(url, headers={"Authorization": f"Bearer {api_key}"}, timeout=25)
    resp.raise_for_status()
    return resp.content


def run_yara_scan(message_bytes: bytes) -> List[YaraMatchResult]:
    """
    Run YARA rules against *message_bytes* and return a list of matches.

    Replace the placeholder rules above with your production ruleset.
    """
    rules = get_rules()
    raw_matches = rules.match(data=message_bytes)

    results: List[YaraMatchResult] = []
    for m in raw_matches:
        results.append(
            YaraMatchResult(
                rule_name=m.rule,
                category=m.meta.get("description"),
                # score omitted — Worker looks up DEFAULT_YARA_RULE_SCORES
            )
        )
    return results


def post_callback(mailbox_id: str, email_id: str, matches: List[YaraMatchResult]) -> None:
    """POST scan results back to PhishSOC with HMAC-SHA256 signature."""
    callback_url = f"{PHISHSOC_BASE_URL}/api/v1/mailboxes/{mailbox_id}/yaramail-callback"

    body_obj = YaraCallbackBody(emailId=email_id, matches=matches)
    # Compact JSON for deterministic signing
    body_bytes = body_obj.model_dump_json(exclude_none=True).encode()

    signature = sign_body(body_bytes)
    headers = {
        "Content-Type": "application/json",
        "X-PhishSOC-Signature": signature,
    }

    logger.info(
        "Posting callback to %s for emailId=%s (%d matches)",
        callback_url,
        email_id,
        len(matches),
    )
    resp = httpx.post(callback_url, content=body_bytes, headers=headers, timeout=10)
    resp.raise_for_status()
    logger.info("Callback accepted: HTTP %d", resp.status_code)


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(title="YaraMail Sidecar Stub", version="0.1.0")


@app.post("/scan", status_code=202)
async def scan(request: Request) -> dict:
    """
    Receive a YaraScanPayload from PhishSOC, run YARA, and post the callback.

    Returns 202 Accepted immediately once the payload is parsed; the callback
    is sent synchronously before the response in this stub.  A production
    implementation should use a task queue to avoid holding the connection.
    """
    try:
        raw_body = await request.body()
        payload = YaraScanPayload.model_validate_json(raw_body)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    logger.info("Received scan request for emailId=%s mailboxId=%s", payload.emailId, payload.mailboxId)

    try:
        message_bytes = fetch_message(payload)
        matches = run_yara_scan(message_bytes)
    finally:
        # Security: ensure raw bytes do not linger in memory
        message_bytes = b""  # noqa: F821  (may be unbound if fetch raised)

    post_callback(payload.mailboxId, payload.emailId, matches)

    return {"status": "accepted", "emailId": payload.emailId, "matchCount": len(matches)}


@app.get("/healthz")
async def healthz() -> dict:
    """Liveness probe."""
    return {"status": "ok"}
