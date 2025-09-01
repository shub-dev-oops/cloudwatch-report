import os
import json
import gzip
import logging
import datetime as dt
from typing import List, Dict, Optional
import boto3
import urllib.request
import hashlib

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---- ENV ----
ALERTS_BUCKET = os.environ["ALERTS_BUCKET"]
AGENT_ID = os.environ["AGENT_ID"]
AGENT_ALIAS_ID = os.environ["AGENT_ALIAS_ID"]
TEAMS_WEBHOOK = os.environ["TEAMS_WEBHOOK"]
DAY_IST_DEFAULT = os.environ.get("DAY_IST")  # optional default day
MAX_ALERTS = int(os.environ.get("MAX_ALERTS", "1500"))
MAX_BODIES_PER_CALL = int(os.environ.get("MAX_BODIES_PER_CALL", "90"))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "true").lower() == "true"
SAVE_BEDROCK_LOGS = os.environ.get("SAVE_BEDROCK_LOGS", "false").lower() == "true"
BEDROCK_LOGS_S3_BUCKET = os.environ.get("BEDROCK_LOGS_S3_BUCKET", "")
BEDROCK_LOGS_S3_PREFIX = os.environ.get("BEDROCK_LOGS_S3_PREFIX", "bedrock/digests/")
LOG_ALERT_DETAIL = os.environ.get("LOG_ALERT_DETAIL", "true").lower() == "true"
ALERT_LOG_LIMIT = int(os.environ.get("ALERT_LOG_LIMIT", "100"))  # max per-run detail lines
LOG_BEDROCK_FULL = os.environ.get("LOG_BEDROCK_FULL", "false").lower() == "true"  # log model raw output (truncated)
BEDROCK_FULL_MAX_CHARS = int(os.environ.get("BEDROCK_FULL_MAX_CHARS", "4000"))
LOG_SKIPPED_TIME = os.environ.get("LOG_SKIPPED_TIME", "false").lower() == "true"  # log sample of time-skipped alerts
SKIPPED_TIME_LIMIT = int(os.environ.get("SKIPPED_TIME_LIMIT", "20"))

# ---- AWS Clients ----
s3 = boto3.client("s3")
agent_rt = boto3.client("bedrock-agent-runtime")
log_s3 = boto3.client("s3") if SAVE_BEDROCK_LOGS and BEDROCK_LOGS_S3_BUCKET else None

IST = dt.timezone(dt.timedelta(hours=5, minutes=30))
UTC = dt.timezone.utc

# ---- Custom JSON Encoder ----
class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (dt.datetime, dt.date)):
            return o.isoformat()
        return super().default(o)

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
            except Exception as e:
                if DEBUG_MODE:
                    logger.warning(f"JSON parse error {key}:{line_num}: {e}")
    except Exception as e:
        logger.error(f"Failed reading {key}: {e}")

# ---- Collect Alerts ----
def collect_alerts_s3(start_utc: dt.datetime, end_utc: dt.datetime, cap: int) -> List[Dict]:
    """Collect alerts within time window; returns list. Detailed stats logged separately."""
    alerts: List[Dict] = []
    stats = {
        "objects_listed": 0,
        "objects_read": 0,
        "lines_scanned": 0,
        "lines_valid": 0,
        "lines_skipped_blank": 0,
        "lines_skipped_time": 0,
        "lines_parse_errors": 0,
        "cap_hit": False,
    }
    skipped_time_samples = []  # capture a few examples of ts outside window
    day = start_utc.date()
    while day <= end_utc.date():
        for key, size in iter_day_objects(ALERTS_BUCKET, day):
            stats["objects_listed"] += 1
            if not (key.endswith('.jsonl') or key.endswith('.jsonl.gz')):
                continue
            stats["objects_read"] += 1
            if DEBUG_MODE:
                logger.info(f"Reading {key} ({size} bytes)")
            for rec in read_jsonl_object(ALERTS_BUCKET, key):
                stats["lines_scanned"] += 1
                body = rec.get("body", "")
                if not body or not body.strip():
                    stats["lines_skipped_blank"] += 1
                    continue
                ts_raw = rec.get("event_ts_utc") or rec.get("ingestion_ts_utc")
                try:
                    ts = parse_dt(ts_raw) if ts_raw else None
                except Exception:
                    ts = None
                    stats["lines_parse_errors"] += 1
                if ts is None or ts < start_utc or ts > end_utc:
                    stats["lines_skipped_time"] += 1
                    if LOG_SKIPPED_TIME and len(skipped_time_samples) < SKIPPED_TIME_LIMIT:
                        skipped_time_samples.append({
                            "messageId": rec.get("messageId"),
                            "event_ts_utc": ts_raw,
                            "parsed": iso_z(ts) if ts else None,
                            "reason": "null_or_outside_window",
                            "window_start_utc": iso_z(start_utc),
                            "window_end_utc": iso_z(end_utc)
                        })
                    continue
                alerts.append({
                    "messageId": rec.get("messageId", "unknown"),
                    "body": body,
                    "fromDisplay": rec.get("fromDisplay") or rec.get("source") or rec.get("source_system") or "",
                    "event_ts_utc": ts_raw
                })
                stats["lines_valid"] += 1
                if len(alerts) >= cap:
                    stats["cap_hit"] = True
                    if DEBUG_MODE:
                        logger.info(f"Hit cap {cap}, stopping collection")
                    _log_collection_stats(stats, start_utc, end_utc, skipped_time_samples)
                    collect_alerts_s3._last_stats = stats
                    return alerts
        day += dt.timedelta(days=1)
    _log_collection_stats(stats, start_utc, end_utc, skipped_time_samples)
    collect_alerts_s3._last_stats = stats
    return alerts

def _log_collection_stats(stats: Dict, start_utc: dt.datetime, end_utc: dt.datetime, skipped_time_samples=None):
    doc = {
        "tag": "DIGEST_COLLECTION_STATS",
        "window_start_utc": iso_z(start_utc),
        "window_end_utc": iso_z(end_utc),
        **stats
    }
    if skipped_time_samples:
        doc["skipped_time_samples"] = skipped_time_samples
    logger.info(json.dumps(doc, cls=DateTimeEncoder))

# ---- Debug Logging of Collected Alerts ----
def log_alert_details(alerts: List[Dict]):
    if not (DEBUG_MODE and LOG_ALERT_DETAIL):
        return
    limit = min(ALERT_LOG_LIMIT, len(alerts))
    logger.info(f"Logging first {limit} alerts (of {len(alerts)}) for digest debug")
    for i, a in enumerate(alerts[:limit]):
        body_preview = preview(a.get("body", ""), 140)
        logger.info(
            json.dumps({
                "tag": "ALERT_FOR_DIGEST",
                "idx": i,
                "messageId": a.get("messageId"),
                "event_ts_utc": a.get("event_ts_utc"),
                "from": a.get("fromDisplay"),
                "body_preview": body_preview,
                "body_hash": body_hash(a.get("body", ""))
            }, cls=DateTimeEncoder)
        )
    if len(alerts) > limit:
        logger.info(f"(Suppressed {len(alerts) - limit} additional alerts; increase ALERT_LOG_LIMIT to see more)")

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
    payload_items = [{
        "messageId": a["messageId"],
        "from": a.get("fromDisplay", ""),
        "body": a["body"],
        "event_ts_utc": a.get("event_ts_utc")
    } for a in alerts]
    instruction = BASE_INSTRUCTION + "\nWindow (IST): " + window_label + "\nRespond ONLY with the digest Markdown."
    payload = {"instruction": instruction, "items": payload_items}
    # Store full request payload for debug
    if DEBUG_MODE:
        if not hasattr(invoke_bedrock, '_last_requests'):
            invoke_bedrock._last_requests = {}
        invoke_bedrock._last_requests[chunk_index] = json.dumps(payload, indent=2, cls=DateTimeEncoder)
    if DEBUG_MODE and payload_items:
        logger.info(f"Bedrock chunk {chunk_index} items={len(payload_items)} sampleBody={preview(payload_items[0]['body'])}")
    req_url = None
    resp_url = None
    if DEBUG_MODE and log_s3:
        try:
            req_key = f"{BEDROCK_LOGS_S3_PREFIX.rstrip('/')}/{session_id}/request-chunk-{chunk_index:03d}.json"
            log_s3.put_object(Bucket=BEDROCK_LOGS_S3_BUCKET, Key=req_key, Body=json.dumps(payload, indent=2, cls=DateTimeEncoder).encode('utf-8'), ContentType='application/json')
            req_url = log_s3.generate_presigned_url('get_object', Params={'Bucket': BEDROCK_LOGS_S3_BUCKET, 'Key': req_key}, ExpiresIn=3600*24)
        except Exception as e:
            logger.error(f"Failed saving bedrock request: {e}")
    try:
        resp = agent_rt.invoke_agent(
            agentId=AGENT_ID,
            agentAliasId=AGENT_ALIAS_ID,
            sessionId=session_id,
            inputText=json.dumps(payload, cls=DateTimeEncoder),
            enableTrace=DEBUG_MODE  # Enable trace for debugging, logs to CloudWatch
        )
        out = ""
        trace_logs = []
        for event in resp.get('completion', []):
            if 'chunk' in event:
                chunk = event['chunk']
                if 'bytes' in chunk:
                    out += chunk['bytes'].decode('utf-8')
            elif 'trace' in event:
                trace_logs.append(event['trace'])
                if DEBUG_MODE:
                    logger.info(json.dumps({"tag": "BEDROCK_TRACE", "chunk_index": chunk_index, "trace": event['trace']}, cls=DateTimeEncoder))
            elif 'exception' in event:
                error_msg = str(event['exception'])
                logger.error(f"Bedrock stream exception chunk {chunk_index}: {error_msg}")
                return f"**Bedrock stream exception chunk {chunk_index}:** {error_msg}"
        out = out.strip()
        # Store full response for debug
        if DEBUG_MODE:
            if not hasattr(invoke_bedrock, '_last_responses'):
                invoke_bedrock._last_responses = {}
            invoke_bedrock._last_responses[chunk_index] = out
            if trace_logs:
                if not hasattr(invoke_bedrock, '_last_traces'):
                    invoke_bedrock._last_traces = {}
                invoke_bedrock._last_traces[chunk_index] = trace_logs
        if LOG_BEDROCK_FULL and out:
            # Safe truncation for CloudWatch logs
            resp_hash = body_hash(out)
            truncated = out[:BEDROCK_FULL_MAX_CHARS]
            logger.info(json.dumps({
                "tag": "BEDROCK_CHUNK_OUTPUT",
                "chunk_index": chunk_index,
                "chars": len(out),
                "truncated_to": len(truncated),
                "hash": resp_hash,
                "preview": preview(out, 240)
            }, cls=DateTimeEncoder))
            if len(out) > BEDROCK_FULL_MAX_CHARS:
                logger.info(f"Bedrock chunk {chunk_index} output truncated for log (max {BEDROCK_FULL_MAX_CHARS} chars)")
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
                if DEBUG_MODE and trace_logs:
                    log_doc["traces"] = trace_logs
                log_s3.put_object(Bucket=BEDROCK_LOGS_S3_BUCKET, Key=log_key, Body=json.dumps(log_doc, cls=DateTimeEncoder).encode('utf-8'), ContentType='application/json')
            except Exception as e:
                logger.error(f"Failed saving bedrock log: {e}")
        if DEBUG_MODE and log_s3:
            try:
                resp_key = f"{BEDROCK_LOGS_S3_PREFIX.rstrip('/')}/{session_id}/response-chunk-{chunk_index:03d}.md"
                log_s3.put_object(Bucket=BEDROCK_LOGS_S3_BUCKET, Key=resp_key, Body=out.encode('utf-8'), ContentType='text/markdown')
                resp_url = log_s3.generate_presigned_url('get_object', Params={'Bucket': BEDROCK_LOGS_S3_BUCKET, 'Key': resp_key}, ExpiresIn=3600*24)
            except Exception as e:
                logger.error(f"Failed saving bedrock response: {e}")
        # Store response stats for debug output
        stats = {
            "chunk_index": chunk_index,
            "chars": len(out),
            "hash": body_hash(out),
            "preview": preview(out, 240)
        }
        if not hasattr(invoke_bedrock, '_last_response_stats'):
            invoke_bedrock._last_response_stats = []
        invoke_bedrock._last_response_stats.append(stats)
        # Store urls
        if DEBUG_MODE:
            if not hasattr(invoke_bedrock, '_last_req_urls'):
                invoke_bedrock._last_req_urls = {}
            invoke_bedrock._last_req_urls[chunk_index] = req_url
            if not hasattr(invoke_bedrock, '_last_resp_urls'):
                invoke_bedrock._last_resp_urls = {}
            invoke_bedrock._last_resp_urls[chunk_index] = resp_url
        return out
    except Exception as e:
        logger.error(f"Bedrock invoke error: {e}")
        return f"**Bedrock error chunk {chunk_index}:** {e}"

def _build_debug_section(alerts: List[Dict], chunks: List[List[Dict]], session_id: str) -> str:
    """Build tightened debug section for Teams message, focusing on samples and first chunk for input/output."""
    lines = [
        "\n### Debug Information",
        f"- Total alerts collected: {len(alerts)}",
        f"- Chunks: {len(chunks)} (max {MAX_BODIES_PER_CALL} items per chunk)",
        f"- Session: {session_id}",
    ]
    # Sample alerts sent (first alert from first chunk only, and a few bodies)
    if alerts:
        lines.extend([
            "\n#### Sample Alerts Sent to Bedrock (First Chunk)",
            "```\n",
        ])
        if chunks:
            chunk = chunks[0]
            if chunk:
                lines.append(f"Chunk 0 (size {len(chunk)}): First 3 samples\n")
                for sample in chunk[:3]:
                    lines.extend([
                        f"messageId: {sample.get('messageId')}",
                        f"from: {sample.get('fromDisplay', '')}",
                        f"ts: {sample.get('event_ts_utc')}",
                        f"body: {preview(sample.get('body', ''), 200)}\n"
                    ])
        lines.append("```")
    # Collection stats (summary only)
    stats = getattr(collect_alerts_s3, '_last_stats', None)
    if stats:
        lines.extend([
            "\n#### Collection Stats Summary",
            "```\n",
            f"Objects: listed={stats.get('objects_listed', 0)}, read={stats.get('objects_read', 0)}\n",
            f"Lines: scanned={stats.get('lines_scanned', 0)}, valid={stats.get('lines_valid', 0)}, skipped_blank={stats.get('lines_skipped_blank', 0)}, skipped_time={stats.get('lines_skipped_time', 0)}\n",
            "```"
        ])
    # Bedrock response stats (all chunks, brief)
    bedrock_stats = getattr(invoke_bedrock, '_last_response_stats', [])
    if bedrock_stats:
        lines.extend([
            "\n#### Bedrock Response Stats",
            "```\n"
        ])
        for stat in bedrock_stats:
            lines.append(
                f"Chunk {stat.get('chunk_index', '?')}: chars={stat.get('chars', 0)}, hash={stat.get('hash', 'n/a')}, preview={stat.get('preview', 'n/a')}\n"
            )
        lines.append("```")
    # Bedrock Traces (first chunk only, truncated)
    bedrock_traces = getattr(invoke_bedrock, '_last_traces', {})
    if bedrock_traces and 0 in bedrock_traces:
        traces = bedrock_traces[0]
        truncated_traces = json.dumps(traces, indent=2, cls=DateTimeEncoder)[:3000]
        lines.extend([
            "\n#### Bedrock Stream Traces (Chunk 0, truncated)",
            "```json\n",
            truncated_traces,
            "\n```"
        ])
        if len(json.dumps(traces, cls=DateTimeEncoder)) > 3000:
            lines.append("(Traces truncated to 3000 chars for message size)")
    # Full debug links
    if DEBUG_MODE:
        lines.append("\n#### Full Debug Files")
        bedrock_req_urls = getattr(invoke_bedrock, '_last_req_urls', {})
        bedrock_resp_urls = getattr(invoke_bedrock, '_last_resp_urls', {})
        for chunk_index in sorted(bedrock_req_urls.keys()):
            req_url = bedrock_req_urls.get(chunk_index)
            resp_url = bedrock_resp_urls.get(chunk_index)
            if req_url or resp_url:
                lines.append(f"\n- Chunk {chunk_index}:")
                if req_url:
                    lines.append(f"  [Full Request]({req_url})")
                if resp_url:
                    lines.append(f"  [Full Response]({resp_url})")
    # Bedrock Request Payload (first chunk only, truncated)
    bedrock_requests = getattr(invoke_bedrock, '_last_requests', {})
    if bedrock_requests and 0 in bedrock_requests:
        request_payload = bedrock_requests[0]
        truncated_request = request_payload[:3000]  # Tighten truncation
        lines.extend([
            "\n#### Bedrock Exact Input (Chunk 0, truncated)",
            "```json\n",
            truncated_request,
            "\n```"
        ])
        if len(request_payload) > 3000:
            lines.append("(Input truncated to 3000 chars for message size)")
    # Bedrock Response (first chunk only, truncated)
    bedrock_responses = getattr(invoke_bedrock, '_last_responses', {})
    if bedrock_responses and 0 in bedrock_responses:
        response = bedrock_responses[0]
        truncated_response = response[:3000]  # Tighten truncation
        lines.extend([
            "\n#### Bedrock Exact Output (Chunk 0, truncated)",
            "```markdown\n",
            truncated_response,
            "\n```"
        ])
        if len(response) > 3000:
            lines.append("(Output truncated to 3000 chars for message size)")
    return "\n".join(lines)

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
    logger.info(f"Digest start event={json.dumps(event or {}, cls=DateTimeEncoder)}")
    override_start = (event or {}).get("override_start_iso")
    override_end = (event or {}).get("override_end_iso")
    if override_start and override_end:
        start_utc = parse_dt(override_start)
        end_utc = parse_dt(override_end)
        window_label = f"{start_utc.astimezone(IST).strftime('%d %b %Y %H:%M')} - {end_utc.astimezone(IST).strftime('%H:%M')} IST"
    else:
        day_ist = (event or {}).get("day_ist") or DAY_IST_DEFAULT or "today"
        start_utc, end_utc, window_label = to_ist_day_bounds(day_ist)
    # Warn if legacy module file still present (could cause handler confusion)
    try:
        if os.path.exists(os.path.join(os.path.dirname(__file__), 's3-digest.py')):
            logger.warning("Legacy file s3-digest.py present; ensure Lambda handler set to s3_digest.lambda_handler")
    except Exception:
        pass
    alerts = collect_alerts_s3(start_utc, end_utc, MAX_ALERTS)
    logger.info(f"Collected {len(alerts)} candidate alerts for window {window_label}")
    log_alert_details(alerts)
    if not alerts:
        md = f"**SRE Alert Digest - {window_label}**\n\n_No alerts/messages found in this window._"
        if DEBUG_MODE:
            md += _build_debug_section(alerts, [], "no-session")
        post_to_teams(md)
        return {"ok": True, "posted": True, "count": 0, "window": window_label}
    session_id = "s3-digest-" + now_utc().strftime("%Y%m%d%H%M%S")
    chunks = list(chunk_list(alerts, MAX_BODIES_PER_CALL))
    part_markdowns: List[str] = []
    for idx, chunk in enumerate(chunks):
        part = invoke_bedrock(session_id, window_label, chunk, idx)
        if part:
            part_markdowns.append(part)
    if len(part_markdowns) == 1:
        final_md = part_markdowns[0]
    else:
        final_md = ("\n\n---\n\n").join(part_markdowns)
        final_md = f"**SRE Alert Digest - {window_label} (Multi-chunk)**\n\n" + final_md
    if not final_md.strip():
        final_md = f"**SRE Alert Digest - {window_label}** _No actionable alerts identified (model returned empty response)._ "
    if DEBUG_MODE:
        final_md += _build_debug_section(alerts, chunks, session_id)
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

if __name__ == "__main__":
    print(json.dumps(lambda_handler({}, None), indent=2))