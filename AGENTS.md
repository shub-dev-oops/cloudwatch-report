# Repository Guidelines

## Project Structure & Modules
- Root: AWS Lambda utilities and docs for alert ingestion and digesting.
- Code: `sqs-ingest-lambda.py` (API Gateway → SQS), `sqs-s3-writer.py` (SQS → S3 JSONL), `s3_digest.py` (S3 → Bedrock → Teams).
- Docs: `SQS-ARCHITECTURE.md`, `PROMPT-BEDROCK-DIGEST.md`.
- Config: `s3-lifecycle.json` (S3 lifecycle policy).

## Build, Test, and Dev Commands
- Run S3 writer locally: `python sqs-s3-writer.py` (includes a simple test harness).
- Run digest locally: `python s3_digest.py` (invokes `lambda_handler` with default event).
- Package for Lambda (zip):
  - PowerShell: `Compress-Archive -Path s3_digest.py -DestinationPath s3_digest.zip`
  - Bash: `zip -r sqs_s3_writer.zip sqs-s3-writer.py`
- Dependencies (local dev): `pip install -U boto3 python-dateutil`

## Coding Style & Naming
- Python 3.11; 4-space indentation; PEP 8 style; type hints where helpful.
- Names: snake_case for functions/vars; keep existing file names/handlers.
- Strings: f-strings; prefer explicit UTC handling (`datetime`, `isoformat` with `Z`).
- Logging: use module-level `logging` with INFO default; DEBUG for verbose flows.

## Testing Guidelines
- Event simulation: craft minimal API Gateway/SQS events and call handlers directly.
  - Example: `python -c "import json,sqs_s3_writer as m; print(m.handler({'Records':[{'messageId':'1','body':json.dumps({'event_ts_utc':'2025-01-01T00:00:00Z'})}]}, None))"`
- S3 output: verify keys like `alerts/year=YYYY/month=MM/day=DD/*.jsonl(.gz)` and required metadata.
- Digest: validate Teams markdown composes without errors; keep under `TEAMS_MAX_CHARS`.

## Commit & Pull Request Guidelines
- Commits: short, imperative summaries (e.g., “Refactor S3 digest grouping”).
- Scope in body: what/why, key files, risk/rollout notes.
- PRs: clear description, linked issues, deployment notes (env vars/IAM), and sample outputs (S3 key preview or Teams screenshot).

## Security & Configuration Tips
- Environment: `SQS_QUEUE_URL`, `ALERTS_BUCKET`, `TEAMS_WEBHOOK`, model/limits vars in `s3_digest.py`.
- Secrets: never commit keys; use Lambda env vars and IAM roles. Outbound HTTPS required for Teams.
- S3: apply `s3-lifecycle.json`; partition writes under `alerts/` to control costs.

## Architecture Overview
- Flow: Teams/API → `sqs-ingest-lambda.py` → SQS → `sqs-s3-writer.py` → S3(JSONL) → `s3_digest.py` → Bedrock → Teams.
- Partial-failure handling: SQS batch item failures returned; S3 writes are batched and optionally gzip compressed.

