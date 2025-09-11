import os
import json
import gzip
import logging
import datetime as dt
from typing import List, Dict, Optional, Tuple
import boto3
import urllib.request
import hashlib
from dateutil import tz
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---- ENV ----
ALERTS_BUCKET = os.environ["ALERTS_BUCKET"]
MODEL_ID = os.environ.get("MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
TEAMS_WEBHOOK = os.environ["TEAMS_WEBHOOK"]

# Core behavior
DIGEST_INTERVAL_MINUTES_DEFAULT = int(os.environ.get("DIGEST_INTERVAL_MINUTES", "90"))
OUTPUT_TIMEZONE = os.environ.get("OUTPUT_TIMEZONE", "UTC")
MAX_ALERTS = int(os.environ.get("MAX_ALERTS", "1500"))
MAX_BODIES_PER_CALL = int(os.environ.get("MAX_BODIES_PER_CALL", "90"))
# Render style: set to false for full, true for ultra-compact
LITE_DIGEST = os.environ.get("LITE_DIGEST", "false").lower() == "true"

# Concurrency
BEDROCK_CONCURRENCY = int(os.environ.get("BEDROCK_CONCURRENCY", "4"))

# Logging & debug
DEBUG_MODE = os.environ.get("DEBUG_MODE", "true").lower() == "true"
SAVE_BEDROCK_LOGS = os.environ.get("SAVE_BEDROCK_LOGS", "false").lower() == "true"
BEDROCK_LOGS_S3_BUCKET = os.environ.get("BEDROCK_LOGS_S3_BUCKET", "")
BEDROCK_LOGS_S3_PREFIX = os.environ.get("BEDROCK_LOGS_S3_PREFIX", "bedrock/digests/")
LOG_ALERT_DETAIL = os.environ.get("LOG_ALERT_DETAIL", "true").lower() == "true"
ALERT_LOG_LIMIT = int(os.environ.get("ALERT_LOG_LIMIT", "100"))
LOG_BEDROCK_FULL = os.environ.get("LOG_BEDROCK_FULL", "false").lower() == "true"
BEDROCK_FULL_MAX_CHARS = int(os.environ.get("BEDROCK_FULL_MAX_CHARS", "4000"))
LOG_SKIPPED_TIME = os.environ.get("LOG_SKIPPED_TIME", "false").lower() == "true"
SKIPPED_TIME_LIMIT = int(os.environ.get("SKIPPED_TIME_LIMIT", "20"))

# State persistence (optional overrides)
DIGEST_STATE_BUCKET = os.environ.get("DIGEST_STATE_BUCKET") or ALERTS_BUCKET
DIGEST_STATE_KEY = os.environ.get("DIGEST_STATE_KEY", "state/sre-digest-state.json")
USE_PREV_WINDOW = os.environ.get("USE_PREV_WINDOW", "true").lower() == "true"
MAX_CATCHUP_MINUTES = int(os.environ.get("MAX_CATCHUP_MINUTES", "180"))

# Teams output mode
TEAMS_MAX_CHARS = int(os.environ.get("TEAMS_MAX_CHARS", "24000"))  # safety cap

# Channel-driven severity (no severity field needed)
CRITICAL_CHANNELS = [t.strip().lower() for t in os.environ.get("CRITICAL_CHANNELS", "").split(",") if t.strip()]
WARNING_CHANNELS  = [t.strip().lower() for t in os.environ.get("WARNING_CHANNELS", "").split(",") if t.strip()]
CRITICAL_CHANNEL_HINTS = [t.strip().lower() for t in os.environ.get("CRITICAL_CHANNEL_HINTS", "critical,crit,sev1,p1,urgent").split(",") if t.strip()]
WARNING_CHANNEL_HINTS  = [t.strip().lower() for t in os.environ.get("WARNING_CHANNEL_HINTS", "warning,warn,sev2,p2,alert").split(",") if t.strip()]

# Optional product inference hints: JSON like {"registrar": "Registrar", "govmeetings": "GovMeetings"}
PRODUCT_ALIAS_JSON = os.environ.get("PRODUCT_ALIAS_JSON", "{}")
try:
    PRODUCT_ALIASES: Dict[str, str] = json.loads(PRODUCT_ALIAS_JSON)
except Exception:
    PRODUCT_ALIASES = {}

# ---- AWS Clients ----
s3 = boto3.client("s3")
bedrock_rt = boto3.client("bedrock-runtime")
log_s3 = boto3.client("s3") if SAVE_BEDROCK_LOGS and BEDROCK_LOGS_S3_BUCKET else None

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


def iso_z(ts: Optional[dt.datetime]) -> Optional[str]:
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

# Timezone helpers

def get_output_tz():
    return tz.gettz(OUTPUT_TIMEZONE)


def fmt_in_tz(ts: dt.datetime, tz_obj) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(tz_obj).strftime("%d %b %Y %H:%M")


def fmt_in_tz_compact(ts: dt.datetime, tz_obj) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(tz_obj).strftime("%Y-%m-%d %H:%M")


def preview(txt: str, n: int = 120) -> str:
    t = (txt or "").strip().replace("\n", " ")
    return (t[:n] + "...") if len(t) > n else t


def body_hash(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8")).hexdigest()[:12]


def _add(lines: List[str], s: Optional[str] = None):
    """Append a line, avoiding accidental double blank lines."""
    if s is None or s == "":
        if not lines or lines[-1] != "":
            lines.append("")
    else:
        lines.append(s)

# ---- Severity & Product ----

def _norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def derive_severity(rec: Dict) -> str:
    # 1) Respect explicit normalized_severity if provided by upstream
    explicit = _norm(rec.get("normalized_severity"))
    if explicit in {"critical", "warning", "info"}:
        return explicit.capitalize()

    # 2) Otherwise infer from channel names/hints
    ch_name = _norm(rec.get("channel"))
    channelish = " ".join(filter(None, [
        rec.get("channel"), rec.get("teams_channel"), rec.get("fromDisplay"),
        rec.get("source"), rec.get("source_system"), rec.get("team"), rec.get("room")
    ])).lower()

    if CRITICAL_CHANNELS and ch_name in CRITICAL_CHANNELS:
        return "Critical"
    if WARNING_CHANNELS and ch_name in WARNING_CHANNELS:
        return "Warning"
    if any(h in channelish for h in CRITICAL_CHANNEL_HINTS):
        return "Critical"
    if any(h in channelish for h in WARNING_CHANNEL_HINTS):
        return "Warning"
    return "Unknown"


def infer_product(rec: Dict) -> str:
    p = rec.get("product") or rec.get("service")
    if p:
        return str(p)
    ch = (rec.get("channel") or "").lower()
    for key, val in PRODUCT_ALIASES.items():
        if key.lower() in ch:
            return val
    fr = rec.get("fromDisplay") or rec.get("source") or rec.get("source_system")
    return fr or "Unknown"

# ---- State (S3) ----

def load_digest_state() -> Optional[Dict]:
    """Load the last digest state (window cursor) from S3. Returns a dict or None."""
    try:
        obj = s3.get_object(Bucket=DIGEST_STATE_BUCKET, Key=DIGEST_STATE_KEY)
        raw = obj["Body"].read()
        return json.loads(raw)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "NoSuchKey":
            return None
        logger.warning(f"State load failed: {e}")
        return None
    except Exception as e:
        logger.warning(f"State load failed: {e}")
        return None


def save_digest_state(state: Dict):
    """Persist the last digest state (window cursor) to S3."""
    try:
        s3.put_object(
            Bucket=DIGEST_STATE_BUCKET,
            Key=DIGEST_STATE_KEY,
            Body=json.dumps(state, cls=DateTimeEncoder).encode("utf-8"),
            ContentType="application/json",
        )
    except Exception as e:
        logger.error(f"State save failed: {e}")

# ---- Window Calculation ----

def get_window_bounds(prev_end_utc: Optional[dt.datetime] = None, interval_minutes: int = None) -> Tuple[dt.datetime, dt.datetime, str]:
    if interval_minutes is None:
        interval_minutes = DIGEST_INTERVAL_MINUTES_DEFAULT
    end_utc = now_utc()
    if USE_PREV_WINDOW and prev_end_utc:
        start_utc = prev_end_utc + dt.timedelta(microseconds=1)
        max_lookback = end_utc - dt.timedelta(minutes=MAX_CATCHUP_MINUTES)
        if start_utc < max_lookback:
            logger.warning(
                f"Start capped by MAX_CATCHUP_MINUTES from {iso_z(start_utc)} to {iso_z(max_lookback)}"
            )
            start_utc = max_lookback
    else:
        start_utc = end_utc - dt.timedelta(minutes=interval_minutes)

    tz_obj = get_output_tz()
    # Use compact numeric label for readability and consistency
    label = f"{fmt_in_tz_compact(start_utc, tz_obj)} - {fmt_in_tz_compact(end_utc, tz_obj)} {OUTPUT_TIMEZONE}"
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

# ---- Entity Extraction from Bodies ----

HOST_PATTERNS = [
    r"\bip-\d{1,3}(?:-\d{1,3}){3}\b",
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    r"\bnode[-\w\.]+\b",
    r"\bhost[-\w\.]+\b",
    r"\bk8s[-\w\.]+\b",
    r"\bi-[0-9a-f]{17}\b"
]
MAG_PATTERNS = [
    r"\bswagit[-_ ]?mag[-_ ]?\d+\b",
    r"\bmag[-_ ]?\d+\b",
    r"\bMAG[-_ ]?\d+\b"
]
MEETING_NODE_PATTERNS = [
    r"\bmeeting[-_ ]?node[-_ ]?\d+\b",
    r"\bgovmeetings[-_\w]*node[-_ ]?\d+\b"
]
REBOOT_HINTS = [r"reboot(?:ed|ing)?", r"restart(?:ed|ing)?", r"cycled"]


def _extract_entities_from_body(body: str) -> Dict[str, List[str]]:
    txt = body or ""
    out = {"affected_hosts": [], "swagit_mag_ids": [], "rebooted_nodes": []}
    # generic hosts
    seen = set()
    for pat in HOST_PATTERNS:
        for m in re.findall(pat, txt, flags=re.IGNORECASE):
            k = m.strip()
            if k and k.lower() not in seen:
                seen.add(k.lower()); out["affected_hosts"].append(k)
    # swagit mags
    seen_mag = set()
    for pat in MAG_PATTERNS:
        for m in re.findall(pat, txt, flags=re.IGNORECASE):
            k = m.strip()
            if k and k.lower() not in seen_mag:
                seen_mag.add(k.lower()); out["swagit_mag_ids"].append(k)
    # meeting nodes + reboot context
    nodes = set()
    for pat in MEETING_NODE_PATTERNS:
        for m in re.findall(pat, txt, flags=re.IGNORECASE):
            nodes.add(m.strip())
    reboot_flag = any(re.search(h, txt, flags=re.IGNORECASE) for h in REBOOT_HINTS)
    if reboot_flag and nodes:
        out["rebooted_nodes"] = sorted(nodes)
    return out

# ---- Collect Alerts ----

def collect_alerts_s3(start_utc: dt.datetime, end_utc: dt.datetime, cap: int) -> List[Dict]:
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
    skipped_time_samples = []
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
                    ts = dt.datetime.fromisoformat((ts_raw or '').replace("Z", "+00:00")) if ts_raw else None
                    if ts and ts.tzinfo is None:
                        ts = ts.replace(tzinfo=UTC)
                    if ts:
                        ts = ts.astimezone(UTC)
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
                norm_sev = derive_severity({**rec, "body": body})
                alerts.append({
                    "messageId": rec.get("messageId", "unknown"),
                    "body": body,
                    "fromDisplay": rec.get("fromDisplay") or rec.get("source") or rec.get("source_system") or "",
                    "channel": rec.get("channel"),
                    "event_ts_utc": ts_raw,
                    "norm_severity": norm_sev,
                    "product": infer_product(rec)
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
                "channel": a.get("channel"),
                "norm_severity": a.get("norm_severity"),
                "product": a.get("product"),
                "body_preview": body_preview,
                "body_hash": body_hash(a.get("body", ""))
            }, cls=DateTimeEncoder)
        )
    if len(alerts) > limit:
        logger.info(f"(Suppressed {len(alerts) - limit} additional alerts; increase ALERT_LOG_LIMIT to see more)")

# ---- Bedrock Prompt (FULL JSON Schema) ----

JSON_INSTRUCTION = (
    "You are an SRE assistant summarizing alerts into structured JSON for a markdown digest.\n"
    "Rules: Do NOT invent facts. Use normalized_severity as-is.\n"
    "Group very similar items (same problem) into a single group.\n"
    "For each group, infer a concise title, a single-sentence summary, and up to 5 suggested_actions (clear, imperative).\n"
    "If product is blank or 'Unknown', infer from text if obvious, else leave as 'Unknown'.\n"
    "If you can spot a specific component/service from text, populate 'component'. Otherwise omit or set to null.\n"
    "Use the provided 'hints' per item (affected_hosts, swagit_mag_ids, rebooted_nodes) to populate 'entities' when corroborated by the text.\n"
    "Respond ONLY with JSON matching this schema: {\n"
    "  kpis: {critical:number, warning:number, info:number, unknown:number, noise:number},\n"
    "  groups: [{product:string, title:string, summary:string, severity:string, component?:string|null, first_seen_utc:string, last_seen_utc:string, occurrences:number, suggested_actions?:string[], appendix_previews?:string[], entities?:{affected_hosts?:string[], swagit_mag_ids?:string[], rebooted_nodes?:string[]}}]\n"
    "}\n"
)


def chunk_list(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]


def _build_bedrock_body(system: str, user_message: str) -> bytes:
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "system": system,
        "messages": [{"role": "user", "content": user_message}],
        "temperature": 0.0,
        "top_p": 1.0,
        "top_k": 250
    })
    return body.encode('utf-8')


def invoke_bedrock_json(session_id: str,
                        window_label: str,
                        alerts: List[Dict],
                        chunk_index: int,
                        output_tz_name: str,
                        prev_end_iso: Optional[str],
                        next_local_time: str,
                        interval_minutes: int) -> Dict:
    tz_obj = get_output_tz()
    current_local = fmt_in_tz(now_utc(), tz_obj)
    current_utc = now_utc().strftime("%Y-%m-%d %H:%M")

    payload_items = [{
        "messageId": a["messageId"],
        "from": a.get("fromDisplay", ""),
        "body": a["body"],
        "event_ts_utc": a.get("event_ts_utc"),
        "normalized_severity": a.get("norm_severity"),
        "product": a.get("product", "Unknown"),
        "hints": _extract_entities_from_body(a.get("body", ""))
    } for a in alerts]

    system = JSON_INSTRUCTION
    user_message = (
        f"Current time (local {output_tz_name}): {current_local}\n"
        f"Current time (UTC): {current_utc}\n"
        f"Digest interval: {interval_minutes} minutes\n"
        f"Window: {window_label}\n"
        f"Previous digest end (UTC): {prev_end_iso or 'n/a'}\n"
        f"Next update (local {output_tz_name}): {next_local_time}\n\n"
        f"Items:\n{json.dumps(payload_items, indent=2, cls=DateTimeEncoder)}\n\n"
        "Return only JSON."
    )

    body_bytes = _build_bedrock_body(system, user_message)

    req_url = None
    resp_url = None
    if DEBUG_MODE and log_s3:
        try:
            req_key = f"{BEDROCK_LOGS_S3_PREFIX.rstrip('/')}/{session_id}/request-chunk-{chunk_index:03d}.json"
            log_s3.put_object(Bucket=BEDROCK_LOGS_S3_BUCKET, Key=req_key, Body=body_bytes, ContentType='application/json')
            req_url = log_s3.generate_presigned_url('get_object', Params={'Bucket': BEDROCK_LOGS_S3_BUCKET, 'Key': req_key}, ExpiresIn=3600*24)
        except Exception as e:
            logger.error(f"Failed saving bedrock request: {e}")

    try:
        resp = bedrock_rt.invoke_model(
            modelId=MODEL_ID,
            body=body_bytes,
            contentType='application/json',
            accept='application/json'
        )
        response_body = json.loads(resp['body'].read())
        raw = response_body.get('content', [{}])[0].get('text', "").strip()
        if DEBUG_MODE and log_s3:
            try:
                resp_key = f"{BEDROCK_LOGS_S3_PREFIX.rstrip('/')}/{session_id}/response-chunk-{chunk_index:03d}.json"
                log_s3.put_object(Bucket=BEDROCK_LOGS_S3_BUCKET, Key=resp_key, Body=raw.encode('utf-8'), ContentType='application/json')
                resp_url = log_s3.generate_presigned_url('get_object', Params={'Bucket': BEDROCK_LOGS_S3_BUCKET, 'Key': resp_key}, ExpiresIn=3600*24)
            except Exception as e:
                logger.error(f"Failed saving bedrock response: {e}")

        try:
            parsed = json.loads(raw) if raw else {"kpis": {}, "groups": []}
        except Exception as e:
            logger.error(f"JSON parse error in chunk {chunk_index}: {e}; raw preview={preview(raw, 240)}")
            parsed = {"kpis": {}, "groups": []}

        if DEBUG_MODE:
            stat = {"chunk_index": chunk_index, "chars": len(raw), "hash": body_hash(raw), "groups": len(parsed.get('groups', []))}
            if not hasattr(invoke_bedrock_json, '_last_response_stats'):
                invoke_bedrock_json._last_response_stats = []
            invoke_bedrock_json._last_response_stats.append(stat)
            if not hasattr(invoke_bedrock_json, '_last_req_urls'):
                invoke_bedrock_json._last_req_urls = {}
            if not hasattr(invoke_bedrock_json, '_last_resp_urls'):
                invoke_bedrock_json._last_resp_urls = {}
            invoke_bedrock_json._last_req_urls[chunk_index] = req_url
            invoke_bedrock_json._last_resp_urls[chunk_index] = resp_url

        return parsed
    except Exception as e:
        logger.error(f"Bedrock invoke error: {e}")
        return {"kpis": {}, "groups": []}

# ---- Merge & Render ----

SEV_RANK = {"critical": 0, "warning": 1, "info": 2, "unknown": 3}


def _sev_emoji(sev: str) -> str:
    s = (sev or "").lower()
    if s == "critical":
        return "🔴"
    if s == "warning":
        return "🟠"
    if s == "info":
        return "🔵"
    return "⚪"


def _merge_lists(a: Optional[List[str]], b: Optional[List[str]], cap: int) -> List[str]:
    out, seen = [], set()
    for lst in (a or []), (b or []):
        for x in lst:
            if not x:
                continue
            key = x.strip()
            if key.lower() in seen:
                continue
            seen.add(key.lower()); out.append(key)
            if len(out) >= cap:
                return out
    return out


def merge_chunk_results(chunks: List[Dict]) -> Dict:
    agg = {
        "kpis": {"critical": 0, "warning": 0, "info": 0, "unknown": 0, "noise": 0},
        "groups": {}
    }
    for ch in chunks:
        k = ch.get("kpis", {})
        for key in agg["kpis"].keys():
            agg["kpis"][key] += int(k.get(key, 0) or 0)
        for g in ch.get("groups", []):
            product = g.get("product") or "Unknown"
            title = g.get("title") or preview(g.get("summary", ""), 60)
            sev = (g.get("severity") or "Unknown").capitalize()
            key = (product, title, sev)
            item = agg["groups"].get(key)
            if not item:
                agg["groups"][key] = {
                    "product": product,
                    "title": title,
                    "summary": g.get("summary", ""),
                    "severity": sev,
                    "component": g.get("component"),
                    "first_seen_utc": g.get("first_seen_utc"),
                    "last_seen_utc": g.get("last_seen_utc"),
                    "occurrences": int(g.get("occurrences", 1) or 1),
                    "suggested_actions": list((g.get("suggested_actions") or [])[:8]),
                    "appendix_previews": list((g.get("appendix_previews") or [])[:20]),
                    "entities": g.get("entities") or {}
                }
            else:
                item["occurrences"] += int(g.get("occurrences", 1) or 1)
                # earliest first_seen, latest last_seen
                try:
                    fs_existing = dt.datetime.fromisoformat((item["first_seen_utc"] or '').replace("Z", "+00:00")) if item.get("first_seen_utc") else None
                    if fs_existing and fs_existing.tzinfo is None:
                        fs_existing = fs_existing.replace(tzinfo=UTC)
                except Exception:
                    fs_existing = None
                try:
                    fs_new = dt.datetime.fromisoformat((g.get("first_seen_utc") or '').replace("Z", "+00:00")) if g.get("first_seen_utc") else None
                    if fs_new and fs_new.tzinfo is None:
                        fs_new = fs_new.replace(tzinfo=UTC)
                except Exception:
                    fs_new = None
                if fs_existing is None or (fs_new and fs_new < fs_existing):
                    item["first_seen_utc"] = g.get("first_seen_utc")
                try:
                    ls_existing = dt.datetime.fromisoformat((item["last_seen_utc"] or '').replace("Z", "+00:00")) if item.get("last_seen_utc") else None
                    if ls_existing and ls_existing.tzinfo is None:
                        ls_existing = ls_existing.replace(tzinfo=UTC)
                except Exception:
                    ls_existing = None
                try:
                    ls_new = dt.datetime.fromisoformat((g.get("last_seen_utc") or '').replace("Z", "+00:00")) if g.get("last_seen_utc") else None
                    if ls_new and ls_new.tzinfo is None:
                        ls_new = ls_new.replace(tzinfo=UTC)
                except Exception:
                    ls_new = None
                if ls_existing is None or (ls_new and ls_new > ls_existing):
                    item["last_seen_utc"] = g.get("last_seen_utc")
                # prefer longer summary
                if len(g.get("summary", "")) > len(item.get("summary", "")):
                    item["summary"] = g.get("summary")
                # merge actions and appendix (dedupe, cap)
                item["suggested_actions"] = _merge_lists(item.get("suggested_actions"), g.get("suggested_actions"), 8)
                item["appendix_previews"] = _merge_lists(item.get("appendix_previews"), g.get("appendix_previews"), 20)
                # merge entities
                ent = item.setdefault("entities", {})
                g_ent = g.get("entities") or {}
                for k_merge, capn in [("affected_hosts", 20), ("swagit_mag_ids", 20), ("rebooted_nodes", 20)]:
                    ent[k_merge] = _merge_lists(ent.get(k_merge), g_ent.get(k_merge), capn)
    return agg


def _rank_for_product(groups: List[Dict]) -> int:
    # worst severity rank within product
    worst = 9
    for g in groups:
        s = (g.get('severity') or '').lower()
        worst = min(worst, SEV_RANK.get(s, 9))
    return worst


def render_markdown_full(agg: Dict, window_label: str, interval_minutes: int) -> str:
    tz_obj = get_output_tz()
    now_local = fmt_in_tz_compact(now_utc(), tz_obj)
    next_local = fmt_in_tz_compact(now_utc() + dt.timedelta(minutes=interval_minutes), tz_obj)

    lines: List[str] = []
    _add(lines, "# 🛡️ SRE Digest")
    _add(lines)
    _add(lines, f"**Timestamp ({OUTPUT_TIMEZONE}):** {now_local}")
    _add(lines, f"**Window:** {window_label}")
    _add(lines, "**Deduplicated Alerts/Incidents:** ✅")
    _add(lines)

    k = agg.get("kpis", {})
    _add(lines, "## Summary KPIs")
    _add(lines, f"- **🔴 Critical:** {k.get('critical', 0)}")
    _add(lines, f"- **🟠 Warning:** {k.get('warning', 0)}")
    _add(lines, f"- **🔵 Info:** {k.get('info', 0)}")
    _add(lines, f"- **⚪ Other:** {k.get('unknown', 0)}  _(Noise: {k.get('noise', 0)})_")
    _add(lines)

    # group by product for display
    by_product: Dict[str, List[Dict]] = {}
    for (_, _, _), g in agg.get("groups", {}).items():
        by_product.setdefault(g["product"], []).append(g)

    # sort products by worst severity (Critical first), then name
    products_sorted = sorted(by_product.items(), key=lambda kv: (_rank_for_product(kv[1]), kv[0].lower()))

    for product, items in products_sorted:
        _add(lines, f"### 📦 Product — {product}")
        # sort Critical -> Warning -> Info -> Unknown, then occurrences desc, then title
        items.sort(key=lambda x: (SEV_RANK.get((x.get('severity') or '').lower(), 9), -int(x.get('occurrences', 1)), x.get('title','')))
        for g in items:
            emoji = _sev_emoji(g.get("severity"))
            title = g.get("title")
            summ = g.get("summary")
            occ = g.get("occurrences", 1)
            fs = g.get("first_seen_utc") or ""
            ls = g.get("last_seen_utc") or ""
            component = g.get("component") or "—"
            ent = g.get("entities") or {}
            nodes = ent.get("rebooted_nodes") or []
            mags = ent.get("swagit_mag_ids") or []
            hosts = ent.get("affected_hosts") or []

            _add(lines, f"#### {emoji} {title}")
            _add(lines, f"- **Severity:** {emoji} {g.get('severity')}")
            _add(lines, f"- **Component:** _{component}_")
            if nodes:
                _add(lines, f"- **Affected/Rebooted Nodes:** {', '.join(nodes)}")
            if mags:
                _add(lines, f"- **Swagit MAG:** {', '.join(mags)}")
            if hosts and not nodes:
                _add(lines, f"- **Affected Hosts:** {', '.join(hosts[:10])}")
            _add(lines, f"- **Occurrences:** {occ}")
            _add(lines, f"- **First Seen (UTC):** {fs}")
            _add(lines, f"- **Last Seen (UTC):** {ls}")
            _add(lines, f"- **Summary:** {summ}")

            actions = g.get("suggested_actions") or []
            if actions:
                _add(lines, "**Suggested Action Items**")
                for a in actions:
                    _add(lines, f"- [ ] {a}")
            _add(lines)
        _add(lines)

    # Appendix (flat list from all groups)
    all_previews = []
    for (_, _, _), g in agg.get("groups", {}).items():
        for p in (g.get("appendix_previews") or [])[:3]:  # keep it short per group
            all_previews.append(p)

    if all_previews:
        _add(lines, "## 📎 Appendix — Grouped Alert Previews")
        for p in all_previews[:50]:
            _add(lines, f"- {p}")
        _add(lines)

    _add(lines, f"🕒 Last update: {now_local} – next update at {next_local}")

    md = "\n".join(lines).strip()
    if len(md) > TEAMS_MAX_CHARS:
        md = md[:TEAMS_MAX_CHARS - 2000] + "\n\n_(truncated to fit Teams limit)_"
    return md


def render_markdown_lite(agg: Dict, window_label: str, interval_minutes: int) -> str:
    tz_obj = get_output_tz()
    now_local = fmt_in_tz_compact(now_utc(), tz_obj)
    next_local = fmt_in_tz_compact(now_utc() + dt.timedelta(minutes=interval_minutes), tz_obj)

    lines: List[str] = []
    _add(lines, "# 🛡️ SRE Digest (Lite)")
    _add(lines, f"Window: {window_label}")
    _add(lines, f"Last update: {now_local} • Next: {next_local}")
    _add(lines)

    k = agg.get("kpis", {})
    _add(lines, "**Summary**")
    _add(lines, f"- 🔴 Critical: {k.get('critical', 0)}")
    _add(lines, f"- 🟠 Warning: {k.get('warning', 0)}")
    _add(lines, f"- 🔵 Info: {k.get('info', 0)}")
    _add(lines, f"- ⚪ Other: {k.get('unknown', 0)}  (Noise: {k.get('noise', 0)})")
    _add(lines)

    by_product: Dict[str, List[Dict]] = {}
    for (_, _, _), g in agg.get("groups", {}).items():
        by_product.setdefault(g["product"], []).append(g)

    products_sorted = sorted(by_product.items(), key=lambda kv: (_rank_for_product(kv[1]), kv[0].lower()))
    for product, items in products_sorted:
        _add(lines, f"### 📦 {product}")
        items.sort(key=lambda x: (SEV_RANK.get((x.get('severity') or '').lower(), 9), -int(x.get('occurrences', 1))))
        for g in items:
            emoji = _sev_emoji(g.get("severity"))
            title = g.get("title")
            summ = g.get("summary")
            occ = g.get("occurrences", 1)
            fs = g.get("first_seen_utc") or ""
            ls = g.get("last_seen_utc") or ""
            _add(lines, f"- {emoji} **{title}** — {summ}  _(x{occ}; {fs} → {ls})_")
        _add(lines)

    md = "\n".join(lines).strip()
    if len(md) > TEAMS_MAX_CHARS:
        md = md[:TEAMS_MAX_CHARS - 2000] + "\n\n_(truncated to fit Teams limit)_"
    return md

# ---- Teams Posting ----

def post_markdown_to_teams(markdown: str) -> bool:
    try:
        data = json.dumps({"text": markdown}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(TEAMS_WEBHOOK, data=data, headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
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

    event = event or {}
    # Per-invocation interval override
    interval_minutes = int(event.get("minutes", DIGEST_INTERVAL_MINUTES_DEFAULT))

    # Load previous state
    state = load_digest_state()
    prev_end_utc = None
    prev_end_iso = None
    if state and state.get("last_end_utc"):
        try:
            prev_end_utc = dt.datetime.fromisoformat((state["last_end_utc"] or '').replace("Z", "+00:00"))
            if prev_end_utc and prev_end_utc.tzinfo is None:
                prev_end_utc = prev_end_utc.replace(tzinfo=UTC)
            prev_end_utc = prev_end_utc.astimezone(UTC)
            prev_end_iso = iso_z(prev_end_utc)
        except Exception as e:
            logger.warning(f"Invalid state.last_end_utc: {state.get('last_end_utc')} ({e})")

    # Compute window (allow override via event.window.start_utc/end_utc ISO8601)
    win_override = event.get("window") or {}
    if win_override.get("start_utc") and win_override.get("end_utc"):
        try:
            start_utc = dt.datetime.fromisoformat((win_override["start_utc"] or '').replace("Z", "+00:00")).astimezone(UTC)
            end_utc = dt.datetime.fromisoformat((win_override["end_utc"] or '').replace("Z", "+00:00")).astimezone(UTC)
            tz_obj = get_output_tz()
            window_label = f"{fmt_in_tz_compact(start_utc, tz_obj)} - {fmt_in_tz_compact(end_utc, tz_obj)} {OUTPUT_TIMEZONE}"
        except Exception as e:
            logger.warning(f"Invalid window override: {e}; falling back to computed window")
            start_utc, end_utc, window_label = get_window_bounds(prev_end_utc, interval_minutes)
    else:
        start_utc, end_utc, window_label = get_window_bounds(prev_end_utc, interval_minutes)

    tz_obj = get_output_tz()
    next_local_time = fmt_in_tz_compact(end_utc + dt.timedelta(minutes=interval_minutes), tz_obj)

    # Warn if legacy module file still present
    try:
        import os as _os
        if _os.path.exists(_os.path.join(_os.path.dirname(__file__), 's3-digest.py')):
            logger.warning("Legacy file s3-digest.py present; ensure Lambda handler set to s3_digest_lite.lambda_handler")
    except Exception:
        pass

    alerts = collect_alerts_s3(start_utc, end_utc, MAX_ALERTS)
    logger.info(f"Collected {len(alerts)} candidate alerts for window {window_label}")
    log_alert_details(alerts)

    if not alerts:
        md = "# 🛡️ SRE Digest\n\n_No alerts/messages found in this window._\n\n" + \
             f"🕒 Last update: {fmt_in_tz_compact(now_utc(), tz_obj)} – next update at {next_local_time}"
        posted = post_markdown_to_teams(md)
        save_digest_state({
            "last_start_utc": iso_z(start_utc),
            "last_end_utc": iso_z(end_utc),
            "last_window_label": window_label,
            "last_session_id": "no-session",
            "output_timezone": OUTPUT_TIMEZONE,
            "saved_at_utc": iso_z(now_utc())
        })
        return {"ok": True, "posted": posted, "count": 0, "window": window_label}

    session_id = "s3-digest-" + now_utc().strftime("%Y%m%d%H%M%S")
    chunks = list(chunk_list(alerts, MAX_BODIES_PER_CALL))

    # ---- PARALLEL Bedrock calls ----
    results: List[Dict] = [None] * len(chunks)
    max_workers = min(BEDROCK_CONCURRENCY, len(chunks)) or 1
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(
                invoke_bedrock_json,
                session_id,
                window_label,
                chunk,
                idx,
                OUTPUT_TIMEZONE,
                prev_end_iso,
                next_local_time,
                interval_minutes
            ): idx for idx, chunk in enumerate(chunks)
        }
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                results[idx] = fut.result()
            except Exception as e:
                logger.error(f"Chunk {idx} failed: {e}")
                results[idx] = {"kpis": {}, "groups": []}

    agg = merge_chunk_results([r or {"kpis": {}, "groups": []} for r in results])

    if LITE_DIGEST:
        final_md = render_markdown_lite(agg, window_label, interval_minutes)
    else:
        final_md = render_markdown_full(agg, window_label, interval_minutes)

    posted = post_markdown_to_teams(final_md)

    # Persist new state
    save_digest_state({
        "last_start_utc": iso_z(start_utc),
        "last_end_utc": iso_z(end_utc),
        "last_window_label": window_label,
        "last_session_id": session_id,
        "output_timezone": OUTPUT_TIMEZONE,
        "saved_at_utc": iso_z(now_utc())
    })

    out = {
        "ok": True,
        "posted": posted,
        "window": window_label,
        "alerts_input": len(alerts),
        "chunks": len(chunks),
        "session_id": session_id,
        "debug": DEBUG_MODE,
        "mode": "lite" if LITE_DIGEST else "full"
    }
    if DEBUG_MODE and final_md:
        out["markdown_chars"] = len(final_md)
    return out


if __name__ == "__main__":
    print(json.dumps(lambda_handler({}, None), indent=2))
