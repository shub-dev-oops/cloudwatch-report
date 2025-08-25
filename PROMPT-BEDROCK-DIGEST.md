# Bedrock Daily Alert Digest Prompt (Reference)

System / Instruction Block Provided to Agent (embedded in code constant BASE_INSTRUCTION):

```
You are an SRE assistant generating a daily alert digest.
Input is a list of raw chat-like alert messages (potentially noisy).
Tasks: 1) Identify which messages are actual alerts/incidents versus noise or benign info.
2) Group similar alerts (same issue) and count occurrences.
3) For each alert group, extract: concise title, affected product/service/env if evident, severity (explicit or inferred), 
first_seen (earliest timestamp), last_seen (latest), representative message preview (sanitize multi‑line).
4) Produce action recommendations only when clearly actionable (capacity, stability, thresholds, follow-up).
5) Create sections: Summary KPIs, High Severity, Medium/Low, Noise Ignored (brief bullet of categories), Action Items, Appendix (raw grouped previews).
6) If NO valid alerts, state that explicitly.
Rules: Do NOT hallucinate severity if absent—mark as 'unknown'. Infer only when strongly implied (e.g., 'CRITICAL', 'High memory').
Deduplicate on near-identical bodies (ignore timestamps/IDs). Use Markdown, no HTML. Keep it crisp.
```

Runtime Payload Shape Sent to Agent (JSON serialized into inputText):

```
{
  "instruction": "<above plus window string>",
  "items": [
    {
      "messageId": "uuid or original id",
      "from": "sender / display name if present",
      "body": "raw message body text",
      "event_ts_utc": "2025-08-25T10:30:00Z"
    },
    ...
  ]
}
```

Expected Model Output: Pure Markdown digest conforming to the sections described. No JSON, no extra commentary outside the digest. Should gracefully handle when there are no alerts.

## Safety & Guardrails
- No PII expected; truncate or redact if accidentally present.
- Avoid leaking internal URLs unless clearly part of an actionable runbook reference.
- If more than 1500 messages (MAX_ALERTS), only first N in window are considered (cap logged).

## Chunking Strategy
If > MAX_BODIES_PER_CALL messages, they're chunked and each chunk gets an independent digest prompt (same instruction). Currently we simple-concatenate results; future enhancement: consolidation pass summarizing across chunk outputs.

## Future Enhancements (Backlog)
- Second-stage merge invocation that feeds chunk digests back for a global consolidation.
- Severity calibration step verifying consistent ordering.
- Optional inclusion of historical baseline metrics for anomaly detection context.
- Output token budget control (target length heuristic).

## Environment Variables Referenced
- ALERTS_BUCKET (required) S3 bucket containing partitioned alert JSONL(.gz) files.
- AGENT_ID (required) Bedrock Agent identifier.
- AGENT_ALIAS_ID (required) Bedrock Agent alias id.
- TEAMS_WEBHOOK (required) MS Teams incoming webhook URL to post digest.
- DAY_IST (optional) Default IST day selection (YYYY-MM-DD | today | yesterday). If absent and no event override, uses today.
- MAX_ALERTS (default 1500) Hard cap of messages scanned per window.
- MAX_BODIES_PER_CALL (default 90) Chunk size per agent invocation.
- DEBUG_MODE (default true) Verbose logging.
- SAVE_BEDROCK_LOGS (default false) When true stores per-chunk preview JSON in BEDROCK_LOGS_S3_BUCKET.
- BEDROCK_LOGS_S3_BUCKET (required if SAVE_BEDROCK_LOGS=true) Destination bucket for call previews.
- BEDROCK_LOGS_S3_PREFIX (default bedrock/digests/) Prefix for saved previews.

## Lambda Configuration
- File: `s3_digest.py`
- Handler: `s3_digest.lambda_handler`
- Recommended Memory: 512–1024 MB (increase if large gzip decompression or model response assembly). Start at 512 MB.
- Recommended Timeout: 120 seconds (adjust if large buckets / many objects; total wall time scales with object count). If using many thousands of lines or multi-chunk + future merge pass: 180–300s.
- Ephemeral Storage: Default (512 MB) is sufficient unless extremely large aggregated chunks; raise if needed.

## IAM Policy Minimum
Allow actions:
```
s3:ListBucket on arn:aws:s3:::<ALERTS_BUCKET>
s3:GetObject on arn:aws:s3:::<ALERTS_BUCKET>/alerts/*
bedrock:InvokeAgent on agent resource ARN(s)
logs:CreateLogGroup (if not existing)
logs:CreateLogStream
logs:PutLogEvents
``` 
If SAVE_BEDROCK_LOGS=true add:
```
s3:PutObject on arn:aws:s3:::<BEDROCK_LOGS_S3_BUCKET>/*
```
If posting to Teams via public incoming webhook (outbound HTTPS), ensure VPC config allows egress or keep function out of private subnets without NAT.

## Event Trigger (Daily Example)
EventBridge rule (cron for 18:45 UTC == 00:15 IST next day adjust as needed):
```
cron(45 18 * * ? *)
```
Target input (optional override for yesterday window after day ends):
```
{
  "day_ist": "yesterday"
}
```

## Local / Manual Test Event Examples
Today (implicit): `{}`
Explicit yesterday: `{ "day_ist": "yesterday" }`
Custom absolute window:
```
{
  "override_start_iso": "2025-08-24T18:30:00Z",
  "override_end_iso":   "2025-08-25T18:29:59Z"
}
```

## Operational Metrics (Manual / Future)
- CloudWatch Metric Filters on log lines: `Collected` (count), `Bedrock chunk` (invocations), `Teams post status`.
- Error alarms on `Bedrock invoke error` count > 0 OR `Teams post error`.

## Failure Modes & Mitigations
- Empty day: posts explicit "No alerts" message.
- S3 partial parse errors: logged (warning) but continue streaming.
- Bedrock chunk errors: inline placeholder inserted so digest still posts.
- Teams webhook failure: returns ok=true posted=false; add retry mechanism via Lambda Destinations or Step Function wrapper if needed.

## Future Hardening Ideas
- Second-stage merge Bedrock call when >1 chunk to unify severity ordering.
- Token / cost guardrails using approximate body length accumulation.
- Optional Athena sampling of historical context (past 7 days) to add baseline anomaly notes.


Keep this doc updated when prompt or structure changes.
