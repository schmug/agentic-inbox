# sidecar/ — YaraMail YARA Attachment Scanner

Additive to root CLAUDE.md. Sidecar-specific conventions only.

The sidecar is a **Python service**, not TypeScript. Workers and npm conventions from root CLAUDE.md do **not** apply here.

## Runtime

Python 3.11+, FastAPI, YARA-python. Operator-deployed as a Docker container on any HTTPS-reachable host (Cloud Run, Fly.io, self-hosted). The main Worker dispatches attachment scan requests to it over HTTP.

## Test / typecheck

No npm scripts. If you add or modify Python logic:

```bash
cd sidecar/example
pip install -r requirements.txt
pytest          # if tests exist
mypy main.py    # type-check with mypy
```

## Code layout

- **`sidecar/example/main.py`** — Reference FastAPI stub illustrating the expected HTTP request/response contract. Not production-ready; real deployments extend this.
- **`sidecar/example/requirements.txt`** — Python dependencies (FastAPI, uvicorn, yara-python, httpx, pydantic).

## Interface contract

Documented in `docs/yaramail-sidecar.md`. Key points:
- Worker sends `POST <endpointUrl>` with JSON (`emailId`, `r2Key`, `mailboxId`, `presignedUrl`).
- Sidecar responds with `{ matches: string[], score: number }`.
- Sidecar must validate inbound requests via `YARAMAIL_CALLBACK_SECRET` HMAC-SHA256.
- The sidecar is **never on the critical path** — the Worker proceeds with the pre-sidecar verdict if the sidecar does not respond within 30 seconds.
- Configured per-mailbox under `yaraMailScanner.endpointUrl` in mailbox settings.
