"""
S3-Based Alert Digest Lambda (from scratch)

Flow:
  EventBridge (daily) or manual invoke → this Lambda
  Reads alert JSONL (and .jsonl.gz) files from S3 partition(s): alerts/year=YYYY/month=MM/day=DD/
  Extracts minimal fields: messageId, body, fromDisplay (sender)
  Sends in chunks to Bedrock Agent (AGENT_ID/ALIAS) with a strict instruction to:
    - Identify which messages are true alerts vs noise/info
    - Classify severity if present
    - Summarize actionable items & group similar alerts
    - Produce Markdown digest
  Posts digest to Teams via incoming webhook

Environment Variables:
  ALERTS_BUCKET            (required)
  AGENT_ID                 (Bedrock agent id)
  AGENT_ALIAS_ID           (Bedrock agent alias id)
  TEAMS_WEBHOOK            (Teams incoming webhook URL)

  DAY_IST                  (optional override: YYYY-MM-DD | today | yesterday)
  DEBUG_MODE               (default true) - extra logging
  MAX_ALERTS               (cap alerts processed, default 1500)
  MAX_BODIES_PER_CALL      (chunk size to Bedrock, default 90)
  SAVE_BEDROCK_LOGS        (bool) store call previews
  BEDROCK_LOGS_S3_BUCKET   (bucket for logs) if SAVE_BEDROCK_LOGS=true
  BEDROCK_LOGS_S3_PREFIX   (prefix, default bedrock/digests/)

Invocation Overrides (event JSON):
  {
    "day_ist": "YYYY-MM-DD" | "today" | "yesterday",
    "override_start_iso": "...Z",  # absolute UTC
    "override_end_iso": "...Z"
  }
"""
import os
import json
import gzip
import logging
import datetime as dt
from typing import List, Dict, Optional
import boto3
import urllib.request
import hashlib
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---- ENV ----
ALERTS_BUCKET          = os.environ["ALERTS_BUCKET"]
AGENT_ID               = os.environ["AGENT_ID"]
AGENT_ALIAS_ID         = os.environ["AGENT_ALIAS_ID"]
TEAMS_WEBHOOK          = os.environ["TEAMS_WEBHOOK"]
DAY_IST_DEFAULT        = os.environ.get("DAY_IST")  # optional default day

MAX_ALERTS             = int(os.environ.get("MAX_ALERTS", "1500"))
MAX_BODIES_PER_CALL    = int(os.environ.get("MAX_BODIES_PER_CALL", "90"))
DEBUG_MODE             = os.environ.get("DEBUG_MODE", "true").lower() == "true"
SAVE_BEDROCK_LOGS      = os.environ.get("SAVE_BEDROCK_LOGS", "false").lower() == "true"
BEDROCK_LOGS_S3_BUCKET = os.environ.get("BEDROCK_LOGS_S3_BUCKET", "")
BEDROCK_LOGS_S3_PREFIX = os.environ.get("BEDROCK_LOGS_S3_PREFIX", "bedrock/digests/")

# ---- AWS Clients ----
s3 = boto3.client("s3")
agent_rt = boto3.client("bedrock-agent-runtime")
log_s3 = boto3.client("s3") if SAVE_BEDROCK_LOGS and BEDROCK_LOGS_S3_BUCKET else None

IST = dt.timezone(dt.timedelta(hours=5, minutes=30))
UTC = dt.timezone.utc

# ---- Helpers ----
def now_utc():
    return dt.datetime.utcnow().replace(tzinfo=UTC, microsecond=0)

def iso_z(ts: dt.datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def parse_dt(s: str) -> dt.datetime:
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1]
    return dt.datetime.fromisoformat(s).replace(tzinfo=UTC)

def preview(txt: str, n: int = 120) -> str:
    t = (txt or "").strip().replace("\n", " ")
    return (t[:n] + "...") if len(t) > n else t

def body_hash(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8")).hexdigest()[:12]

# ---- Window Calculation ----
def to_ist_day_bounds(day_ist_str: Optional[str]):
    now_ist = now_utc().astimezone(IST)
    if not day_ist_str or day_ist_str.lower() == "today":
        day_date = now_ist.date()
    elif day_ist_str.lower() == "yesterday":
        day_date = (now_ist - dt.timedelta(days=1)).date()
    else:
        try:
            y, m, d = map(int, day_ist_str.split("-"))
            day_date = dt.date(y, m, d)
        except Exception:
            day_date = now_ist.date()
    start_ist = dt.datetime(day_date.year, day_date.month, day_date.day, 0, 0, 0, tzinfo=IST)
    end_ist = start_ist + dt.timedelta(days=1) - dt.timedelta(seconds=1)
    start_utc = start_ist.astimezone(UTC)
    end_utc = end_ist.astimezone(UTC)
    label = f"{start_ist.strftime('%d %b %Y 00:00')} - {end_ist.strftime('%H:%M')} IST"
    return start_utc, end_utc, label

# ---- S3 Reading ----
def iter_day_objects(bucket: str, day: dt.date):
    prefix = f"alerts/year={day.year:04d}/month={day.month:02d}/day={day.day:02d}/"
    token = None
    while True:
        kwargs = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []):
            yield obj["Key"], obj["Size"]
        if not resp.get("IsTruncated"):
            break
        token = resp.get("NextContinuationToken")

def read_jsonl_object(bucket: str, key: str):
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        data = obj["Body"].read()
        if key.endswith(".gz"):
            data = gzip.decompress(data)
        for line_num, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                if DEBUG_MODE:
                    logger.warning(f"JSON parse error {key}:{line_num}: {e}")
    except Exception as e:
        logger.error(f"Failed reading {key}: {e}")

# ---- Collect Alerts ----
def collect_alerts_s3(start_utc: dt.datetime, end_utc: dt.datetime, cap: int) -> List[Dict]:
    alerts: List[Dict] = []
    day = start_utc.date()
    while day <= end_utc.date():
        for key, size in iter_day_objects(ALERTS_BUCKET, day):
            if not (key.endswith('.jsonl') or key.endswith('.jsonl.gz')):
                continue
            if DEBUG_MODE:
                logger.info(f"Reading {key} ({size} bytes)")
            for rec in read_jsonl_object(ALERTS_BUCKET, key):
                # Extract minimal fields
                body = rec.get("body", "")
                if not body.strip():
                    continue
                # Timestamp filter (use event_ts_utc if present else ingestion_ts_utc)
                ts_raw = rec.get("event_ts_utc") or rec.get("ingestion_ts_utc")
                try:
                    ts = parse_dt(ts_raw) if ts_raw else None
                except Exception:
                    ts = None
                if ts is None or ts < start_utc or ts > end_utc:
                    continue
                alerts.append({
                    "messageId": rec.get("messageId", "unknown"),
                    "body": body,
                    "fromDisplay": rec.get("fromDisplay") or rec.get("source") or rec.get("source_system") or "",
                    "event_ts_utc": ts_raw
                })
                if len(alerts) >= cap:
                    if DEBUG_MODE:
                        logger.info(f"Hit cap {cap}, stopping collection")
                    return alerts
        day += dt.timedelta(days=1)
    return alerts

# ---- Bedrock Prompt ----
BASE_INSTRUCTION = (
    "You are an SRE assistant generating a daily alert digest.\n"
    "Input is a list of raw chat-like alert messages (potentially noisy).\n"
    "Tasks: 1) Identify which messages are actual alerts/incidents versus noise or benign info.\n"
    "2) Group similar alerts (same issue) and count occurrences.\n"
    "3) For each alert group, extract: concise title, affected product/service/env if evident, severity (explicit or inferred), \n"
    "first_seen (earliest timestamp), last_seen (latest), representative message preview (sanitize multi‑line).\n"
    "4) Produce action recommendations only when clearly actionable (capacity, stability, thresholds, follow-up).\n"
    "5) Create sections: Summary KPIs, High Severity, Medium/Low, Noise Ignored (brief bullet of categories), Action Items, Appendix (raw grouped previews).\n"
    "6) If NO valid alerts, state that explicitly.\n"
    "Rules: Do NOT hallucinate severity if absent—mark as 'unknown'. Infer only when strongly implied (e.g., 'CRITICAL', 'High memory').\n"
    "Deduplicate on near-identical bodies (ignore timestamps/IDs). Use Markdown, no HTML. Keep it crisp."
)

def chunk_list(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

def invoke_bedrock(session_id: str, window_label: str, alerts: List[Dict], chunk_index: int) -> str:
    # Prepare minimal payload items
    payload_items = []
    for a in alerts:
        payload_items.append({
            "messageId": a["messageId"],
            "from": a.get("fromDisplay", ""),
            "body": a["body"],
            "event_ts_utc": a.get("event_ts_utc")
        })
    instruction = (
        BASE_INSTRUCTION + "\nWindow (IST): " + window_label + "\nRespond ONLY with the digest Markdown."
    )
    payload = {
        "instruction": instruction,
        "items": payload_items
    }
    if DEBUG_MODE:
        logger.info(f"Bedrock chunk {chunk_index} items={len(payload_items)} sampleBody={preview(payload_items[0]['body']) if payload_items else 'n/a'}")
    try:
        resp = agent_rt.invoke_agent(
            agentId=AGENT_ID,
            agentAliasId=AGENT_ALIAS_ID,
            sessionId=session_id,
            inputText=json.dumps(payload)
        )
    except Exception as e:
        logger.error(f"Bedrock invoke error: {e}")
        return f"**Bedrock error chunk {chunk_index}:** {e}"
    out = ""
    if isinstance(resp.get("completion"), list):
        for ev in resp["completion"]:
            if isinstance(ev, dict) and "data" in ev:
                out += ev["data"]
    elif "outputText" in resp:
        out = resp["outputText"]
    elif "message" in resp:
        out = resp["message"].get("content", "")
    out = (out or "").strip()

    if SAVE_BEDROCK_LOGS and log_s3:
        try:
            log_key = f"{BEDROCK_LOGS_S3_PREFIX.rstrip('/')}/{session_id}/chunk-{chunk_index:03d}.json"
            log_doc = {
                "ts_utc": iso_z(now_utc()),
                "chunk_index": chunk_index,
                "items_count": len(payload_items),
                "window": window_label,
                "response_preview": preview(out, 400)
            }
            log_s3.put_object(Bucket=BEDROCK_LOGS_S3_BUCKET, Key=log_key, Body=json.dumps(log_doc).encode('utf-8'), ContentType='application/json')
        except Exception as e:
            logger.error(f"Failed saving bedrock log: {e}")
    return out

# ---- Teams Posting ----
def post_to_teams(markdown: str) -> bool:
    try:
        data = json.dumps({"text": markdown}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(TEAMS_WEBHOOK, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = getattr(resp, "status", 200)
            logger.info(f"Teams post status={code}")
            return 200 <= code < 300
    except Exception as e:
        logger.error(f"Teams post error: {e}")
        return False

# ---- Lambda Handler ----
def lambda_handler(event, context):
    logger.info(f"Digest start event={json.dumps(event or {})}")

    override_start = (event or {}).get("override_start_iso")
    override_end = (event or {}).get("override_end_iso")
    if override_start and override_end:
        start_utc = parse_dt(override_start)
        end_utc = parse_dt(override_end)
        window_label = f"{start_utc.astimezone(IST).strftime('%d %b %Y %H:%M')} - {end_utc.astimezone(IST).strftime('%H:%M')} IST"
    else:
        day_ist = (event or {}).get("day_ist") or DAY_IST_DEFAULT or "today"
        start_utc, end_utc, window_label = to_ist_day_bounds(day_ist)

    alerts = collect_alerts_s3(start_utc, end_utc, MAX_ALERTS)
    logger.info(f"Collected {len(alerts)} candidate alerts for window {window_label}")

    if not alerts:
        md = f"**SRE Alert Digest - {window_label}**\n\n_No alerts/messages found in this window._"
        post_to_teams(md)
        return {"ok": True, "posted": True, "count": 0, "window": window_label}

    session_id = "s3-digest-" + now_utc().strftime("%Y%m%d%H%M%S")
    chunks = list(chunk_list(alerts, MAX_BODIES_PER_CALL))
    part_markdowns: List[str] = []
    for idx, chunk in enumerate(chunks):
        part = invoke_bedrock(session_id, window_label, chunk, idx)
        if part:
            part_markdowns.append(part)

    # Merge strategy: if multiple chunks, create a final consolidation call (optional). For simplicity now, just join.
    if len(part_markdowns) == 1:
        final_md = part_markdowns[0]
    else:
        # Provide a minimal merge instruction locally.
        final_md = ("\n\n---\n\n").join(part_markdowns)
        final_md = f"**SRE Alert Digest - {window_label} (Multi-chunk)**\n\n" + final_md

    # Fallback if Bedrock output empty
    if not final_md.strip():
        final_md = f"**SRE Alert Digest - {window_label}**\n\n_No actionable alerts identified (model returned empty response)._"

    posted = post_to_teams(final_md)

    return {
        "ok": True,
        "posted": posted,
        "window": window_label,
        "alerts_input": len(alerts),
        "chunks": len(chunks),
        "session_id": session_id,
        "debug": DEBUG_MODE
    }

# Local test
if __name__ == "__main__":
    # Minimal local dry-run (will fail without real AWS creds & objects)
    print(json.dumps(lambda_handler({}, None), indent=2))
