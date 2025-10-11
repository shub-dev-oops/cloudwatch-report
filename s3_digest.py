import os
import json
import gzip
import logging
import datetime as dt
from typing import List, Dict, Optional, Tuple, Any
import boto3
import urllib.request
import hashlib
from dateutil import tz
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---- ENV ----
ALERTS_BUCKET = os.environ["ALERTS_BUCKET"]
MODEL_ID = os.environ.get("MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
TEAMS_WEBHOOK = os.environ["TEAMS_WEBHOOK"]

# Core behavior
DIGEST_INTERVAL_MINUTES_DEFAULT = int(os.environ.get("DIGEST_INTERVAL_MINUTES", "90"))
OUTPUT_TIMEZONE = os.environ.get("OUTPUT_TIMEZONE", "Asia/Kolkata")
MAX_ALERTS = int(os.environ.get("MAX_ALERTS", "1500"))
MAX_BODIES_PER_CALL = int(os.environ.get("MAX_BODIES_PER_CALL", "90"))
LITE_DIGEST = os.environ.get("LITE_DIGEST", "false").lower() == "true"

# Concurrency & retries
BEDROCK_CONCURRENCY = int(os.environ.get("BEDROCK_CONCURRENCY", "6"))
BEDROCK_MAX_RETRIES = int(os.environ.get("BEDROCK_MAX_RETRIES", "4"))
BEDROCK_RETRY_BASE_DELAY = float(os.environ.get("BEDROCK_RETRY_BASE_DELAY", "0.75"))

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

# Executive summary
GENERATE_EXEC_SUMMARY = os.environ.get("GENERATE_EXEC_SUMMARY", "true").lower() == "true"
EXEC_SUMMARY_MODEL_ID = os.environ.get("EXEC_SUMMARY_MODEL_ID", MODEL_ID)

# Bedrock product+component enrichment (group level)
GENERATE_PRODUCT_COMPONENTS = os.environ.get("GENERATE_PRODUCT_COMPONENTS", "true").lower() == "true"
PRODUCT_COMPONENT_MODEL_ID = os.environ.get("PRODUCT_COMPONENT_MODEL_ID", MODEL_ID)

# Strict GovMeetings filter for alerts_prod channel
STRICT_GOVM_ONLY_IN_ALERTS_PROD = os.environ.get("STRICT_GOVM_ONLY_IN_ALERTS_PROD", "true").lower() == "true"
GOVM_EXTRA_KEYWORDS = [t.strip().lower() for t in os.environ.get("GOVM_EXTRA_KEYWORDS", "").split(",") if t.strip()]
# Optional denylist backstop for stray non-GovMeetings product tokens (normalized)
DISALLOWED_PRODUCT_TOKENS_RAW = [t.strip().lower() for t in os.environ.get("DISALLOWED_PRODUCT_TOKENS", "").split(",") if t.strip()]

# State persistence
DIGEST_STATE_BUCKET = os.environ.get("DIGEST_STATE_BUCKET") or ALERTS_BUCKET
DIGEST_STATE_KEY = os.environ.get("DIGEST_STATE_KEY", "state/sre-digest-state.json")
USE_PREV_WINDOW = os.environ.get("USE_PREV_WINDOW", "true").lower() == "true"
MAX_CATCHUP_MINUTES = int(os.environ.get("MAX_CATCHUP_MINUTES", "180"))

# Teams output mode
TEAMS_MAX_CHARS = int(os.environ.get("TEAMS_MAX_CHARS", "24000"))

# Channel-driven severity via ENV
CRITICAL_CHANNELS = [t.strip().lower() for t in os.environ.get("CRITICAL_CHANNELS", "").split(",") if t.strip()]
WARNING_CHANNELS  = [t.strip().lower() for t in os.environ.get("WARNING_CHANNELS", "").split(",") if t.strip()]
CRITICAL_CHANNEL_HINTS = [t.strip().lower() for t in os.environ.get("CRITICAL_CHANNEL_HINTS", "critical,crit,sev1,p1,urgent").split(",") if t.strip()]
WARNING_CHANNEL_HINTS  = [t.strip().lower() for t in os.environ.get("WARNING_CHANNEL_HINTS", "warning,warn,sev2,p2,alert").split(",") if t.strip()]

# Canonical GovMeetings subproducts (extensible via env)
# Example override: GOVM_SUBPRODUCTS_JSON='{"iqm":"IQM","hypitia":"Hypitia","legistar":"Legistar","ilegislate":"iLegislate","mediamanager":"MediaManager","peak":"Peak","ufc":"UFC","swagit":"Swagit","onemeeting":"OneMeeting"}'
GOVM_SUBPRODUCTS_JSON = os.environ.get("GOVM_SUBPRODUCTS_JSON", "{}")
try:
    GOVM_CANON: Dict[str, str] = json.loads(GOVM_SUBPRODUCTS_JSON)
except Exception:
    GOVM_CANON = {}
DEFAULT_GOVM = {
    "govmeetings": "GovMeetings",
    "govm": "GovMeetings",
    "gm": "GovMeetings",
    "onemeeting": "OneMeeting",
    "legistar": "Legistar",
    "ilegislate": "iLegislate",
    "mediamanager": "MediaManager",
    "peak": "Peak",
    "ufc": "UFC",
    "swagit": "Swagit",
    "iqm": "IQM",
    "hypitia": "Hypitia",
    "hytia": "Hypitia",  # common misspelling
}
if not GOVM_CANON:
    GOVM_CANON = DEFAULT_GOVM
else:
    base = DEFAULT_GOVM.copy()
    base.update(GOVM_CANON)
    GOVM_CANON = base

# Product aliases (outside canonical keys), e.g. {"gm:iqm":"IQM","esignnotify":"IQM"}
PRODUCT_ALIAS_JSON = os.environ.get("PRODUCT_ALIAS_JSON", "{}")
try:
    PRODUCT_ALIASES: Dict[str, str] = json.loads(PRODUCT_ALIAS_JSON)
except Exception:
    PRODUCT_ALIASES = {}

def _norm_key(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())

ALIAS_MAP_NORM = {_norm_key(k): v for k, v in PRODUCT_ALIASES.items()}
CANON_KEYS_NORM = {_norm_key(k): v for k, v in GOVM_CANON.items()}
ALL_GOVM_TOKENS = set(CANON_KEYS_NORM.keys())
# Normalize denylist tokens once
DISALLOWED_TOKENS_NORM = {_norm_key(t) for t in DISALLOWED_PRODUCT_TOKENS_RAW}

# ---- AWS Clients ----
s3 = boto3.client("s3")
bedrock_rt = boto3.client("bedrock-runtime")
log_s3 = boto3.client("s3") if SAVE_BEDROCK_LOGS and BEDROCK_LOGS_S3_BUCKET else None

UTC = dt.timezone.utc

# ---- Encoders & helpers ----
class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (dt.datetime, dt.date)):
            return o.isoformat()
        return super().default(o)

def now_utc():
    return dt.datetime.utcnow().replace(tzinfo=UTC, microsecond=0)

def iso_z(ts: Optional[dt.datetime]) -> Optional[str]:
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def get_output_tz():
    return tz.gettz(OUTPUT_TIMEZONE)

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
    if s is None or s == "":
        if not lines or lines[-1] != "":
            lines.append("")
    else:
        lines.append(s)

def _norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()

def _norm_product_name(p: Optional[str]) -> str:
    return (p or "Unknown").strip()

# ---- Severity ----
def _normalize_sev_name(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    sl = s.strip().lower()
    if sl in {"critical", "crit", "p1", "sev1"}:
        return "Critical"
    if sl in {"warning", "warn", "p2", "sev2"}:
        return "Warning"
    return None

def extract_channel(rec: Dict[str, Any]) -> str:
    ch = rec.get("channel") or (rec.get("raw_event") or {}).get("channel") or rec.get("teams_channel") or rec.get("room")
    return str(ch or "")

def derive_severity(rec: Dict) -> str:
    for candidate in [rec.get("severity"), (rec.get("raw_event") or {}).get("severity")]:
        sev_norm = _normalize_sev_name(candidate)
        if sev_norm:
            return sev_norm
    ch_name = extract_channel(rec).strip().lower()
    if ch_name in CRITICAL_CHANNELS:
        return "Critical"
    if ch_name in WARNING_CHANNELS:
        return "Warning"
    if any(h in ch_name for h in CRITICAL_CHANNEL_HINTS):
        return "Critical"
    if any(h in ch_name for h in WARNING_CHANNEL_HINTS):
        return "Warning"
    return "Unknown"

def _sev_emoji(sev: str) -> str:
    s = (sev or "").lower()
    if s == "critical":
        return "🔴"
    if s == "warning":
        return "🟠"
    return "⚪"

# ---- GovMeetings relevance & product parsing ----
GOVM_KEYWORDS = {"govmeeting", "govmeetings", "govm", "gm", "onemeeting", "legistar", "ilegislate", "mediamanager", "peak", "ufc", "swagit"} | set(GOVM_EXTRA_KEYWORDS)

def _is_relevant_to_govm_text(s: str) -> bool:
    sl = (s or "").lower()
    if any(k in sl for k in GOVM_KEYWORDS):
        return True
    for tok in ALL_GOVM_TOKENS:
        if tok and tok in re.sub(r"[^a-z0-9]+", "", sl):
            return True
    return False

def is_relevant_to_govm(rec: Dict) -> bool:
    ch = extract_channel(rec) or ""
    body = (rec.get("body") or (rec.get("raw_event") or {}).get("text") or "")
    p = (rec.get("product") or rec.get("service") or "")
    fr = rec.get("fromDisplay") or (rec.get("raw_event") or {}).get("fromDisplay") or ""
    combo = " | ".join([ch, p, fr, body])
    return _is_relevant_to_govm_text(combo)

def _alias_lookup_tokenized(fields: List[str]) -> Optional[str]:
    # Try canonical GovM subproduct first (embedded or token)
    for f in fields:
        m = re.search(r"(?:govmeetings?|gm|govm)[:-_ ]+([a-z0-9]+)", (f or "").lower())
        if m:
            key = _norm_key(m.group(1))
            if key in CANON_KEYS_NORM:
                return CANON_KEYS_NORM[key]
        for tok in re.split(r"[^A-Za-z0-9]+", f or ""):
            nk = _norm_key(tok)
            if nk in CANON_KEYS_NORM:
                return CANON_KEYS_NORM[nk]
    # Then non-canonical aliases provided by env
    for f in fields:
        for tok in re.split(r"[^A-Za-z0-9]+", f or ""):
            nk = _norm_key(tok)
            if nk in ALIAS_MAP_NORM:
                return ALIAS_MAP_NORM[nk]
    return None

def infer_product_subproduct(rec: Dict) -> str:
    """Return canonical GovM subproduct name if found; else 'Unknown' or 'GovMeetings' if only container is implied."""
    p = (rec.get("product") or rec.get("service") or "")
    ch = extract_channel(rec)
    fr = rec.get("fromDisplay") or (rec.get("raw_event") or {}).get("fromDisplay") or ""
    tags = rec.get("tags") or (rec.get("raw_event") or {}).get("tags") or []
    body = (rec.get("body") or (rec.get("raw_event") or {}).get("text") or "")

    alias = _alias_lookup_tokenized([p, fr, ch] + list(tags))
    if alias:
        return alias
    alias_body = _alias_lookup_tokenized([body])
    if alias_body:
        return alias_body
    if _is_relevant_to_govm_text(" | ".join([p, ch, fr, body])):
        return GOVM_CANON.get("govmeetings", "GovMeetings")
    return "Unknown"

def is_govm_subproduct(name: str) -> bool:
    if not name:
        return False
    nk = _norm_key(name)
    return nk in ALL_GOVM_TOKENS or nk in CANON_KEYS_NORM

# ---- State (S3) ----
def load_digest_state() -> Optional[Dict]:
    try:
        obj = s3.get_object(Bucket=DIGEST_STATE_BUCKET, Key=DIGEST_STATE_KEY)
        raw = obj["Body"].read()
        return json.loads(raw)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "NoSuchKey":
            return None
        logger.warning(f"State load failed: {e}")
        return None
    except Exception as e:
        logger.warning(f"State load failed: {e}")
        return None

def save_digest_state(state: Dict):
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
            logger.warning(f"Start capped by MAX_CATCHUP_MINUTES from {iso_z(start_utc)} to {iso_z(max_lookback)}")
            start_utc = max_lookback
    else:
        start_utc = end_utc - dt.timedelta(minutes=interval_minutes)
    tz_obj = get_output_tz()
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

# ---- Bedrock prompts ----
# Allowed GovMeetings product set for LLM guidance
ALLOWED_PRODUCTS_LIST = sorted(set(GOVM_CANON.values()))
ALLOWED_PRODUCTS_TXT = ", ".join(ALLOWED_PRODUCTS_LIST)
JSON_INSTRUCTION = (
    "You are an SRE assistant summarizing alerts into structured JSON for a markdown digest.\n"
    "Rules:\n"
    "- Do NOT invent facts.\n"
    "- Use the provided 'resolved_severity' as the severity for all items.\n"
    "- Extract hosts from free text (tokens that look like hostnames/IPs/FQDNs), and put them in entities.affected_hosts (dedup, cap 20).\n"
    "- If text hints like 'component:' or 'group:' exist, set 'component' concisely.\n"
    "- Group very similar items (same problem) into a single group.\n"
    "- For each group, produce a concise title, a single-sentence summary, and up to 5 suggested_actions.\n"
    "- If product is blank or 'Unknown', infer from text if obvious, else leave as 'Unknown'.\n"
    f"- For 'product', choose only from: {ALLOWED_PRODUCTS_TXT}. If unclear, use 'GovMeetings' or 'Unknown'.\n"
    "- IMPORTANT: Always include 'source_channels' for each group; derive by collecting distinct 'channel' values from items in that group. Never omit this field.\n"
    "- If an item's body contains HTML (rich-text), treat it as content (strip tags if needed for previews) but do not discard the information.\n"
    "Respond ONLY with JSON matching this schema: {\n"
    "  kpis: {critical:number, warning:number, unknown:number, noise:number},\n"
    "  groups: [{product:string, title:string, summary:string, severity:string, component?:string|null,\n"
    "           first_seen_utc:string, last_seen_utc:string, occurrences:number,\n"
    "           source_channels:string[],\n"
    "           suggested_actions?:string[], appendix_previews?:string[],\n"
    "           entities?:{affected_hosts?:string[], swagit_mag_ids?:string[], rebooted_nodes?:string[]}}]\n"
    "}\n"
)

EXEC_SUMMARY_INSTRUCTION = (
    "You are an expert SRE comms writer. Write an ultra-brief executive summary of the alert digest for senior leaders.\n"
    "Constraints:\n"
    "- 3 to 6 bullets or 2 short sentences.\n"
    "- Prioritize Critical issues, major customer impact, and any cross-product patterns.\n"
    "- Avoid jargon and metrics overload; keep it skimmable.\n"
    "- Max ~90 words. No markdown except bullets ('- ').\n"
    "Only output the summary text."
)

PRODUCT_COMPONENT_ENRICH_INSTRUCTION = (
    "You help normalize GovMeetings alert groups.\n"
    "For each group, return a canonical GovMeetings subproduct and a terse component.\n"
    "Use this canonical list (case-insensitive): "
    + ", ".join(sorted(set(GOVM_CANON.values()))).strip()
    + ".\n"
    "If the text only implies GovMeetings but no subproduct, return 'GovMeetings'.\n"
    "If unsure of component, return 'General'.\n"
    "Respond ONLY with JSON array: [{idx:number, product:string, component:string}]."
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

def _bedrock_invoke_with_retry(body_bytes: bytes, model_id: Optional[str] = None) -> Dict[str, Any]:
    last_err = None
    mid = model_id or MODEL_ID
    for attempt in range(1, BEDROCK_MAX_RETRIES + 1):
        try:
            resp = bedrock_rt.invoke_model(
                modelId=mid,
                body=body_bytes,
                contentType='application/json',
                accept='application/json'
            )
            return json.loads(resp['body'].read())
        except Exception as e:
            last_err = e
            delay = BEDROCK_RETRY_BASE_DELAY * (2 ** (attempt - 1))
            time.sleep(delay + 0.1 * delay)
    raise last_err if last_err else RuntimeError("Bedrock invoke failed")

def invoke_bedrock_json(session_id: str,
                        window_label: str,
                        alerts: List[Dict],
                        chunk_index: int,
                        output_tz_name: str,
                        prev_end_iso: Optional[str],
                        next_local_time: str,
                        interval_minutes: int) -> Dict:
    tz_obj = get_output_tz()
    current_local = fmt_in_tz_compact(now_utc(), tz_obj)
    current_utc = now_utc().strftime("%Y-%m-%d %H:%M")

    payload_items = [{
        "messageId": a["messageId"],
        "from": a.get("fromDisplay", ""),
        "channel": a.get("channel", ""),
        "body": a["body"],  # may be HTML
        "event_ts_utc": a.get("event_ts_utc"),
        "resolved_severity": a.get("norm_severity"),
        "product": a.get("product", "Unknown"),
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

    if DEBUG_MODE and log_s3:
        try:
            req_key = f"{BEDROCK_LOGS_S3_PREFIX.rstrip('/')}/{session_id}/request-chunk-{chunk_index:03d}.json"
            log_s3.put_object(Bucket=BEDROCK_LOGS_S3_BUCKET, Key=req_key, Body=body_bytes, ContentType='application/json')
        except Exception as e:
            logger.error(f"Failed saving bedrock request: {e}")

    try:
        response_body = _bedrock_invoke_with_retry(body_bytes)
        raw = response_body.get('content', [{}])[0].get('text', "").strip()
        if DEBUG_MODE and log_s3:
            try:
                resp_key = f"{BEDROCK_LOGS_S3_PREFIX.rstrip('/')}/{session_id}/response-chunk-{chunk_index:03d}.json"
                log_s3.put_object(Bucket=BEDROCK_LOGS_S3_BUCKET, Key=resp_key, Body=raw.encode('utf-8'), ContentType='application/json')
            except Exception as e:
                logger.error(f"Failed saving bedrock response: {e}")

        try:
            parsed = json.loads(raw) if raw else {"kpis": {}, "groups": []}
        except Exception as e:
            logger.error(f"JSON parse error in chunk {chunk_index}: {e}; raw preview={preview(raw, 240)}")
            parsed = {"kpis": {}, "groups": []}
        return parsed
    except Exception as e:
        logger.error(f"Bedrock invoke error: {e}")
        return {"kpis": {}, "groups": []}

def invoke_bedrock_exec_summary(session_id: str, window_label: str, agg: Dict) -> str:
    try:
        groups_list = []
        for (_, _, _), g in agg.get("groups", {}).items():
            groups_list.append({
                "product": g.get("product"),
                "title": g.get("title"),
                "severity": g.get("severity"),
                "occurrences": int(g.get("occurrences", 1) or 1)
            })
        payload = {
            "window": window_label,
            "kpis": agg.get("kpis", {}),
            "groups": sorted(groups_list, key=lambda x: (0 if (x.get("severity","").lower()=="critical") else 1, -x.get("occurrences", 1)))
        }
        user_message = json.dumps(payload, indent=2, cls=DateTimeEncoder)
        body_bytes = _build_bedrock_body(EXEC_SUMMARY_INSTRUCTION, user_message)
        response_body = _bedrock_invoke_with_retry(body_bytes, model_id=EXEC_SUMMARY_MODEL_ID)
        return response_body.get('content', [{}])[0].get('text', "").strip()
    except Exception as e:
        logger.error(f"Exec summary generation failed: {e}")
        return ""

def invoke_bedrock_product_component_enrich(groups_missing: List[Dict]) -> Dict[int, Tuple[str, str]]:
    """
    groups_missing: [{idx, title, summary, product_guess, channels}]
    returns: {idx: (product, component)}
    """
    if not groups_missing:
        return {}
    try:
        payload = [{"idx": g["idx"], "title": g.get("title",""), "summary": g.get("summary",""),
                    "product_guess": g.get("product",""), "channels": g.get("channels",[])} for g in groups_missing]
        user_message = json.dumps(payload, indent=2, cls=DateTimeEncoder)
        body_bytes = _build_bedrock_body(PRODUCT_COMPONENT_ENRICH_INSTRUCTION, user_message)
        response_body = _bedrock_invoke_with_retry(body_bytes, model_id=PRODUCT_COMPONENT_MODEL_ID)
        txt = response_body.get('content', [{}])[0].get('text', "").strip()
        mapping = {}
        try:
            arr = json.loads(txt)
            for obj in (arr or []):
                idx = int(obj.get("idx"))
                prod = (obj.get("product") or "").strip()
                comp = (obj.get("component") or "").strip() or "General"
                mapping[idx] = (prod, comp)
        except Exception as e:
            logger.error(f"Prod/Comp enrich parse error: {e}; raw={preview(txt,200)}")
        return mapping
    except Exception as e:
        logger.error(f"Prod/Comp enrich failed: {e}")
        return {}

# ---- Attachment/skip helpers ----
def is_trivial_text(txt: str) -> bool:
    t = (txt or "").strip()
    return t == "" or t in {"<p>\\</p>", "<p></p>", "\\", "-", "."}

def attachments_list(rec: Dict) -> List[Dict]:
    return (rec.get("attachments")
            or (rec.get("raw_event") or {}).get("attachments")
            or [])

def attachments_all_unknown(atts: List[Dict]) -> bool:
    if not atts:
        return True
    for a in atts:
        ct = (a.get("contentType") or "").strip().lower()
        name = (a.get("name") or "").strip()
        if ct and ct not in {"unknown", "application/octet-stream"}:
            return False
        if name:
            return False
    return True

def should_skip_unknown(rec: Dict, body: str, sev: str) -> bool:
    text = (rec.get("raw_event") or {}).get("text") or body
    atts = attachments_list(rec)
    return (sev == "Unknown") and is_trivial_text(text) and attachments_all_unknown(atts)

# ---- Collection from S3 (+ filtering) ----
def collect_alerts_s3(start_utc: dt.datetime, end_utc: dt.datetime, cap: int) -> List[Dict]:
    alerts: List[Dict] = []
    day = start_utc.date()
    while day <= end_utc.date():
        for key, _size in iter_day_objects(ALERTS_BUCKET, day):
            if not (key.endswith(".jsonl") or key.endswith(".jsonl.gz")):
                continue
            for rec in read_jsonl_object(ALERTS_BUCKET, key):
                body = rec.get("body", "") or (rec.get("raw_event") or {}).get("text", "") or ""
                if not body or not body.strip():
                    continue
                ts_raw = rec.get("event_ts_utc") or rec.get("ingestion_ts_utc")
                try:
                    ts = dt.datetime.fromisoformat((ts_raw or "").replace("Z", "+00:00")) if ts_raw else None
                    if ts and ts.tzinfo is None:
                        ts = ts.replace(tzinfo=UTC)
                    if ts:
                        ts = ts.astimezone(UTC)
                except Exception:
                    ts = None
                if ts is None or ts < start_utc or ts > end_utc:
                    continue

                ch = (extract_channel(rec) or "").strip().lower()

                # STRICT GovM-only for alerts_prod
                if STRICT_GOVM_ONLY_IN_ALERTS_PROD and ch == "alerts_prod" and not is_relevant_to_govm(rec):
                    continue

                norm_sev = derive_severity(rec)
                if should_skip_unknown(rec, body, norm_sev):
                    continue

                product_val = infer_product_subproduct(rec)

                # Global policy: Only GovMeetings & its subproducts make it to digest
                if not is_govm_subproduct(product_val) and _norm_key(product_val) != _norm_key(GOVM_CANON.get("govmeetings", "GovMeetings")):
                    continue

                alerts.append({
                    "messageId": rec.get("messageId", "unknown"),
                    "body": body,  # keep HTML if present
                    "fromDisplay": rec.get("fromDisplay")
                                   or (rec.get("raw_event") or {}).get("fromDisplay")
                                   or rec.get("source") or rec.get("source_system") or "",
                    "channel": extract_channel(rec),
                    "event_ts_utc": ts_raw,
                    "norm_severity": norm_sev,
                    "product": product_val
                })
                if len(alerts) >= cap:
                    return alerts
        day += dt.timedelta(days=1)
    return alerts

# ---- Merge, filter & KPI recompute ----
SEV_RANK = {"critical": 0, "warning": 1, "unknown": 2}

def _merge_lists(a: Optional[List[str]], b: Optional[List[str]], cap: int) -> List[str]:
    out, seen = [], set()
    for lst in (a or []), (b or []):
        for x in lst:
            if not x:
                continue
            key = x.strip()
            lk = key.lower()
            if lk in seen:
                continue
            seen.add(lk); out.append(key)
            if len(out) >= cap:
                return out
    return out

def merge_chunk_results(chunks: List[Dict]) -> Dict:
    agg = {"kpis": {"critical": 0, "warning": 0, "unknown": 0, "noise": 0}, "groups": {}}
    for ch in chunks:
        for g in ch.get("groups", []):
            product = g.get("product") or "Unknown"
            title = g.get("title") or preview(g.get("summary", ""), 60)
            sev = (g.get("severity") or "Unknown").capitalize()
            kkey = (product, title, sev)
            item = agg["groups"].get(kkey)
            if not item:
                agg["groups"][kkey] = {
                    "product": product,
                    "title": title,
                    "summary": g.get("summary", ""),
                    "severity": sev,
                    "component": (g.get("component") or "").strip(),
                    "first_seen_utc": g.get("first_seen_utc"),
                    "last_seen_utc": g.get("last_seen_utc"),
                    "occurrences": int(g.get("occurrences", 1) or 1),
                    "source_channels": list((g.get("source_channels") or [])[:12]),
                    "suggested_actions": list((g.get("suggested_actions") or [])[:8]),
                    "appendix_previews": list((g.get("appendix_previews") or [])[:20]),
                    "entities": g.get("entities") or {}
                }
            else:
                item["occurrences"] += int(g.get("occurrences", 1) or 1)
                def _p(s):
                    if not s: return None
                    try:
                        d = dt.datetime.fromisoformat(s.replace("Z","+00:00"))
                        if d.tzinfo is None: d = d.replace(tzinfo=UTC)
                        return d.astimezone(UTC)
                    except Exception:
                        return None
                fs_existing = _p(item.get("first_seen_utc"))
                fs_new = _p(g.get("first_seen_utc"))
                if fs_existing is None or (fs_new and fs_new < fs_existing):
                    item["first_seen_utc"] = g.get("first_seen_utc")
                ls_existing = _p(item.get("last_seen_utc"))
                ls_new = _p(g.get("last_seen_utc"))
                if ls_existing is None or (ls_new and ls_new > ls_existing):
                    item["last_seen_utc"] = g.get("last_seen_utc")

                if len(g.get("summary", "")) > len(item.get("summary", "")):
                    item["summary"] = g.get("summary")

                item["source_channels"] = _merge_lists(item.get("source_channels"), g.get("source_channels"), 12)
                item["suggested_actions"] = _merge_lists(item.get("suggested_actions"), g.get("suggested_actions"), 8)
                item["appendix_previews"] = _merge_lists(item.get("appendix_previews"), g.get("appendix_previews"), 20)
                ent = item.setdefault("entities", {})
                g_ent = g.get("entities") or {}
                for k_merge, capn in [("affected_hosts", 20), ("swagit_mag_ids", 20), ("rebooted_nodes", 20)]:
                    ent[k_merge] = _merge_lists(ent.get(k_merge), g_ent.get(k_merge), capn)
    return agg

def filter_groups_govm_only(groups_map: Dict[Tuple[str, str, str], Dict]) -> Dict[Tuple[str, str, str], Dict]:
    """Keep only GovMeetings and its subproducts; if we discover embedded subproduct, re-key accordingly."""
    out: Dict[Tuple[str, str, str], Dict] = {}
    for k, v in groups_map.items():
        prod = (v.get("product") or "").strip()
        title = v.get("title","")
        sev = v.get("severity","Unknown").capitalize()
        # Drop groups containing any explicitly disallowed product tokens
        blob_norm = _norm_key(" ".join([prod, title, v.get("summary", "")]))
        if any(tok and tok in blob_norm for tok in DISALLOWED_TOKENS_NORM):
            continue
        # Try to promote embedded subproduct from product/title/summary
        alias = _alias_lookup_tokenized([prod, title, v.get("summary","")]) or prod
        new_prod = alias
        # Keep only GovM family
        if is_govm_subproduct(new_prod) or _norm_key(new_prod) == _norm_key(GOVM_CANON.get("govmeetings","GovMeetings")):
            if new_prod != prod:
                v["product"] = new_prod
            new_key = (new_prod, title, sev)
            # Merge if collision
            if new_key in out:
                # merge fields (occurrences, lists)
                out[new_key]["occurrences"] += int(v.get("occurrences", 1) or 1)
                out[new_key]["source_channels"] = _merge_lists(out[new_key].get("source_channels"), v.get("source_channels"), 12)
                out[new_key]["suggested_actions"] = _merge_lists(out[new_key].get("suggested_actions"), v.get("suggested_actions"), 8)
                out[new_key]["appendix_previews"] = _merge_lists(out[new_key].get("appendix_previews"), v.get("appendix_previews"), 20)
                # prefer richer summary and component if empty
                if len(v.get("summary","")) > len(out[new_key].get("summary","")):
                    out[new_key]["summary"] = v.get("summary","")
                if not out[new_key].get("component") and v.get("component"):
                    out[new_key]["component"] = v.get("component")
            else:
                out[new_key] = v
    return out

# ---- replace the whole function ----
def recompute_group_kpis(groups: Dict[Tuple[str, str, str], Dict]) -> Dict[str, int]:
    """
    Severity buckets and Total alerts all count occurrences (not groups).
    """
    out = {"critical": 0, "warning": 0, "unknown": 0, "noise": 0}
    total_occ = 0
    for (_, _, _), g in groups.items():
        sev = (g.get("severity") or "Unknown").lower()
        occ = int(g.get("occurrences", 1) or 1)
        total_occ += occ
        if sev in out:
            out[sev] += occ
        else:
            out["unknown"] += occ
    out["total_alerts"] = total_occ
    return out

def _rank_for_product(groups: List[Dict]) -> int:
    worst = 9
    for g in groups:
        s = (g.get('severity') or '').lower()
        worst = min(worst, SEV_RANK.get(s, 9))
    return worst

def _govmeetings_first_key(item):
    prod, groups = item
    is_container = _norm_key(prod) == _norm_key(GOVM_CANON.get("govmeetings","GovMeetings"))
    return (1 if is_container else 0, _rank_for_product(groups), prod.lower())

# ---- Rendering ----
def render_markdown_full(agg: Dict, window_label: str, interval_minutes: int, exec_summary: str = "") -> str:
    tz_obj = get_output_tz()
    now_local = fmt_in_tz_compact(now_utc(), tz_obj)
    next_local = fmt_in_tz_compact(now_utc() + dt.timedelta(minutes=interval_minutes), tz_obj)

    lines: List[str] = []
    _add(lines, "## 🛡️ SRE Digest")
    _add(lines, f"**Window:** {window_label}")
    _add(lines, f"**Timestamp ({OUTPUT_TIMEZONE}):** {now_local}")
    _add(lines, "")

    k = agg.get("kpis", {})
    _add(lines, "### Summary KPIs")
    _add(lines, f"- 🔴 Critical : {k.get('critical', 0)}")
    _add(lines, f"- 🟠 Warning : {k.get('warning', 0)}")
    _add(lines, f"- ⚪ Other : {k.get('unknown', 0)}")
    _add(lines, f"- **Total alerts (occurrences): {k.get('total_alerts', 0)}**")
    _add(lines, "")
    if exec_summary:
        _add(lines, "### Executive Summary")
        for line in exec_summary.splitlines():
            _add(lines, line)
        _add(lines, "")

    # Group by product (GovM only at this point)
    by_product: Dict[str, List[Dict]] = {}
    for (_, _, _), g in agg.get("groups", {}).items():
        by_product.setdefault(g["product"], []).append(g)

    products_sorted = sorted(by_product.items(), key=_govmeetings_first_key)
    for product, items in products_sorted:
        _add(lines, f"### 📦 Product — {product}")
        items.sort(key=lambda x: (SEV_RANK.get((x.get('severity') or '').lower(), 9), x.get('title','')))
        for g in items:
            emoji = _sev_emoji(g.get("severity"))
            title = g.get("title")
            summ = g.get("summary")
            fs = g.get("first_seen_utc") or ""
            ls = g.get("last_seen_utc") or ""
            component = g.get("component") or "—"
            ent = g.get("entities") or {}
            hosts = ent.get("affected_hosts") or []
            nodes = ent.get("rebooted_nodes") or []
            mags = ent.get("swagit_mag_ids") or []
            src_channels = g.get("source_channels") or []

            _add(lines, f"**{emoji} {title}**")
            _add(lines, f"- **Severity:** {emoji} {g.get('severity')}")
            _add(lines, f"- **Component:** _{component}_")
            _add(lines, f"- **Occurrences:** {int(g.get('occurrences', 1) or 1)}")
            _add(lines, f"- **Source Channels:** {', '.join(src_channels[:8]) if src_channels else '—'}")
            if hosts: _add(lines, f"- **Affected Hosts:** {', '.join(hosts[:10])}")
            if nodes: _add(lines, f"- **Rebooted Nodes:** {', '.join(nodes)}")
            if mags:  _add(lines, f"- **Swagit MAG:** {', '.join(mags)}")
            _add(lines, f"- **First Seen (UTC):** {fs}")
            _add(lines, f"- **Last Seen (UTC):** {ls}")
            _add(lines, f"- **Summary:** {summ}")
            actions = g.get("suggested_actions") or []
            if actions:
                _add(lines, "")
                _add(lines, "**Suggested Action Items**")
                for a in actions:
                    _add(lines, f"- [ ] {a}")
            _add(lines, "")
        _add(lines, "")

    # Appendix (optional previews)
    all_previews = []
    for (_, _, _), g in agg.get("groups", {}).items():
        for p in (g.get("appendix_previews") or [])[:3]:
            all_previews.append(p)
    if all_previews:
        _add(lines, "### 📎 Appendix — Grouped Alert Previews")
        for p in all_previews[:50]:
            _add(lines, f"- {p}")
        _add(lines, "")

    _add(lines, f"🕒 Last update: {now_local} – next update at {next_local}")

    md = "\n".join(lines).strip()
    if len(md) > TEAMS_MAX_CHARS:
        md = md[:TEAMS_MAX_CHARS - 2000] + "\n\n_(truncated to fit Teams limit)_"
    return md

def render_markdown_lite(agg: Dict, window_label: str, interval_minutes: int, exec_summary: str = "") -> str:
    tz_obj = get_output_tz()
    now_local = fmt_in_tz_compact(now_utc(), tz_obj)
    next_local = fmt_in_tz_compact(now_utc() + dt.timedelta(minutes=interval_minutes), tz_obj)

    lines: List[str] = []
    _add(lines, "## 🛡️ SRE Digest (Lite)")
    _add(lines, f"Window: {window_label}")
    _add(lines, f"Last update: {now_local} • Next: {next_local}")
    _add(lines, "")

    k = agg.get("kpis", {})
    _add(lines, "**Summary**")
    _add(lines, f"- 🔴 Critical (groups): {k.get('critical', 0)}")
    _add(lines, f"- 🟠 Warning (groups): {k.get('warning', 0)}")
    _add(lines, f"- ⚪ Other (groups): {k.get('unknown', 0)}")
    _add(lines, f"- **Total alerts (occurrences): {k.get('total_alerts', 0)}**")
    _add(lines, "")
    if exec_summary:
        _add(lines, "**Executive Summary**")
        for line in exec_summary.splitlines():
            _add(lines, line)
        _add(lines, "")

    by_product: Dict[str, List[Dict]] = {}
    for (_, _, _), g in agg.get("groups", {}).items():
        by_product.setdefault(g["product"], []).append(g)

    products_sorted = sorted(by_product.items(), key=_govmeetings_first_key)
    for product, items in products_sorted:
        _add(lines, f"### 📦 {product}")
        items.sort(key=lambda x: (SEV_RANK.get((x.get('severity') or '').lower(), 9), x.get('title','')))
        for g in items:
            emoji = _sev_emoji(g.get("severity"))
            title = g.get("title")
            summ = g.get("summary")
            fs = g.get("first_seen_utc") or ""
            ls = g.get("last_seen_utc") or ""
            comp = g.get("component") or "—"
            occ = int(g.get("occurrences", 1) or 1)
            src_channels = g.get("source_channels") or []
            ent = g.get("entities") or {}
            hosts = ent.get("affected_hosts") or []
            host_txt = f" • Hosts: {', '.join(hosts[:5])}" if hosts else ""
            ch_txt = f" • Channels: {', '.join(src_channels[:3])}" if src_channels else " • Channels: —"
            meta_txt = f" • Component: {comp} • Occurrences: {occ}{host_txt}{ch_txt}"
            _add(lines, f"- {emoji} **{title}** — {summ}{meta_txt}  _({fs} → {ls})_")
        _add(lines, "")

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

    # Compute window
    win_override = event.get("window") or {}
    if win_override.get("start_utc") and win_override.get("end_utc"):
        try:
            start_utc = dt.datetime.fromisoformat((win_override["start_utc"] or '').replace("Z", "+00:00")).astimezone(UTC)
            end_utc = dt.datetime.fromisoformat((win_override["end_utc"] or '').replace("Z", "+00:00")).astimezone(UTC)
            tz_obj = get_output_tz()
            window_label = f"{fmt_in_tz_compact(start_utc, tz_obj)} - {fmt_in_tz_compact(end_utc, tz_obj)} {OUTPUT_TIMEZONE}"
        except Exception as e:
            logger.warning(f"Invalid window override: {e}; falling back")
            start_utc, end_utc, window_label = get_window_bounds(prev_end_utc, interval_minutes)
    else:
        start_utc, end_utc, window_label = get_window_bounds(prev_end_utc, interval_minutes)

    tz_obj = get_output_tz()
    next_local_time = fmt_in_tz_compact(end_utc + dt.timedelta(minutes=interval_minutes), tz_obj)

    # Collect alerts (GovM-only policy applied here)
    alerts = collect_alerts_s3(start_utc, end_utc, MAX_ALERTS)
    logger.info(f"Collected {len(alerts)} candidate alerts for window {window_label}")
    if DEBUG_MODE and LOG_ALERT_DETAIL:
        for i, a in enumerate(alerts[:min(ALERT_LOG_LIMIT, len(alerts))]):
            logger.info(json.dumps({"dbg":"alert", "i":i, "mid":a.get("messageId"), "channel":a.get("channel"), "product":a.get("product"), "sev":a.get("norm_severity")}, cls=DateTimeEncoder))

    if not alerts:
        md = "## 🛡️ SRE Digest\n\n_No GovMeetings alerts found in this window._\n\n" + \
             f"🕒 Last update: {fmt_in_tz_compact(now_utc(), tz_obj)} • Next: {next_local_time}"
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

    # ---- Parallel Bedrock calls (grouping) ----
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

    # Merge results
    agg = merge_chunk_results([r or {"kpis": {}, "groups": []} for r in results])

    # Keep GovM-only and promote embedded subproducts
    filtered_groups = filter_groups_govm_only(agg.get("groups", {}))
    agg["groups"] = filtered_groups

    # Bedrock pass to normalize product (subproduct) & component if missing/unclear
    if GENERATE_PRODUCT_COMPONENTS and agg["groups"]:
        groups_list = list(agg["groups"].items())  # [((prod,title,sev), dict), ...]
        missing_payload = []
        idx_map = {}
        for i, (k, g) in enumerate(groups_list):
            prod = (g.get("product") or "").strip()
            comp = (g.get("component") or "").strip()
            needs = (not is_govm_subproduct(prod)) or (prod.lower() in {"govmeetings", "gov meeting", "gm"}) or (not comp or comp == "—")
            if needs:
                idx = len(missing_payload)
                missing_payload.append({
                    "idx": idx,
                    "title": g.get("title",""),
                    "summary": g.get("summary",""),
                    "product": prod,
                    "channels": g.get("source_channels", [])
                })
                idx_map[idx] = k
        mapping = invoke_bedrock_product_component_enrich(missing_payload)
        for idx, (prod, comp) in mapping.items():
            k = idx_map.get(idx)
            if not k or k not in agg["groups"]:
                continue
            canon_prod = prod.strip() or (agg["groups"][k].get("product") or "")
            if is_govm_subproduct(canon_prod) or _norm_key(canon_prod) == _norm_key(GOVM_CANON.get("govmeetings","GovMeetings")):
                agg["groups"][k]["product"] = canon_prod
            if comp:
                agg["groups"][k]["component"] = comp

    # KPIs: severity by groups; total by occurrences
    kpis_display = recompute_group_kpis(agg.get("groups", {}))
    agg["kpis"] = kpis_display

    # Executive summary
    exec_summary = invoke_bedrock_exec_summary(session_id, window_label, agg) if GENERATE_EXEC_SUMMARY else ""

    # Render & post
    final_md = render_markdown_lite(agg, window_label, interval_minutes, exec_summary) if LITE_DIGEST else render_markdown_full(agg, window_label, interval_minutes, exec_summary)
    posted = post_markdown_to_teams(final_md)

    # Persist state
    save_digest_state({
        "last_start_utc": iso_z(start_utc),
        "last_end_utc": iso_z(end_utc),
        "last_window_label": window_label,
        "last_session_id": session_id,
        "output_timezone": OUTPUT_TIMEZONE,
        "saved_at_utc": iso_z(now_utc())
    })

    return {
        "ok": True,
        "posted": posted,
        "window": window_label,
        "alerts_input": len(alerts),
        "chunks": len(chunks),
        "session_id": session_id,
        "debug": DEBUG_MODE,
        "mode": "lite" if LITE_DIGEST else "full",
        "kpis": agg["kpis"]
    }

if __name__ == "__main__":
    print(json.dumps({"note": "module compiles"}, indent=2))
