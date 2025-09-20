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

# Exec summary
GENERATE_EXEC_SUMMARY = os.environ.get("GENERATE_EXEC_SUMMARY", "true").lower() == "true"
EXEC_SUMMARY_MODEL_ID = os.environ.get("EXEC_SUMMARY_MODEL_ID", MODEL_ID)

# Component enrichment
GENERATE_COMPONENTS = os.environ.get("GENERATE_COMPONENTS", "true").lower() == "true"
COMPONENT_MODEL_ID = os.environ.get("COMPONENT_MODEL_ID", MODEL_ID)

# Strict GovMeetings filter for alerts_prod channel (kept)
STRICT_GOVM_ONLY_IN_ALERTS_PROD = os.environ.get("STRICT_GOVM_ONLY_IN_ALERTS_PROD", "true").lower() == "true"
GOVM_EXTRA_KEYWORDS = [t.strip().lower() for t in os.environ.get("GOVM_EXTRA_KEYWORDS", "").split(",") if t.strip()]

# Global rule: Only GovMeetings subproducts appear in digest
ONLY_GOVM_SUBPRODUCTS = True  # hard requirement per spec

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

# ---------- GovMeetings subproduct aliases ----------
# You can extend/override with GOVM_SUBPRODUCT_ALIASES env var (JSON)
# Keys are alias tokens (case/format-insensitive), values are canonical subproduct names
DEFAULT_GOVM_SUBPRODUCT_ALIASES = {
    # Core family
    "govmeetings": "GovMeetings",
    "govmeeting": "GovMeetings",
    "onemeeting": "OneMeeting",
    "legistar": "Legistar",
    "ilegislate": "iLegislate",
    "mediamanager": "MediaManager",
    "peak": "Peak",
    "ufc": "UFC",
    "swagit": "Swagit",

    # Additional subproducts requested/observed
    "iqm": "IQM",
    "esignnotify": "IQM",     # often appears with IQM flows
    "hypitia": "Hypitia",
    "hytia": "Hypitia",       # common misspelling
    "hypatia": "Hypitia",     # safeguard
}
GOVM_SUBPRODUCT_ALIASES_JSON = os.environ.get("GOVM_SUBPRODUCT_ALIASES", "{}")
try:
    _extra = json.loads(GOVM_SUBPRODUCT_ALIASES_JSON)
    if isinstance(_extra, dict):
        DEFAULT_GOVM_SUBPRODUCT_ALIASES.update({str(k): str(v) for k, v in _extra.items()})
except Exception:
    pass

def _norm_key(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())

# Build a normalized alias map for token-level lookups
GOVM_ALIAS_MAP_NORM: Dict[str, str] = {_norm_key(k): v for k, v in DEFAULT_GOVM_SUBPRODUCT_ALIASES.items()}

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

# ---- GovMeetings relevance & subproduct detection ----
BASE_GOVM_KEYWORDS = {"govmeeting", "govmeetings", "onemeeting", "legistar", "ilegislate", "mediamanager", "peak", "ufc", "swagit", "iqm", "hypitia"}
BASE_GOVM_KEYWORDS |= set(GOVM_EXTRA_KEYWORDS)

def is_govmeetings_product(product_or_text: str) -> Tuple[bool, str]:
    """Detect GovMeetings family; return (is_govm, canonical_subproduct_or_text_or_Unknown)."""
    s = (product_or_text or "").strip()
    sl = s.lower()
    # Canonical subproduct mapping
    for alias_norm, canon in GOVM_ALIAS_MAP_NORM.items():
        if alias_norm and alias_norm in _norm_key(sl):
            # If alias is govmeetings/govmeeting, still return GovMeetings (family)
            return True, canon
    # Fallback quick heuristic
    if any(k in sl for k in BASE_GOVM_KEYWORDS):
        return True, "GovMeetings"
    return False, s or "Unknown"

def _alias_lookup_tokenized(fields: List[str]) -> Optional[str]:
    """Token-level alias resolution against GOVM subproducts, robust to separators and case."""
    for f in fields:
        # Try token splits AND normalized contiguous scan
        tokens = re.split(r"[^A-Za-z0-9]+", f or "")
        for tok in tokens:
            if not tok:
                continue
            nk = _norm_key(tok)
            if nk in GOVM_ALIAS_MAP_NORM:
                return GOVM_ALIAS_MAP_NORM[nk]
        # Embedded patterns like 'govmeetings-iqm-esignnotify' -> find any alias inside normalized string
        nf = _norm_key(f or "")
        for alias_norm, canon in GOVM_ALIAS_MAP_NORM.items():
            if alias_norm and alias_norm in nf:
                return canon
    return None

def infer_govm_subproduct(rec: Dict) -> Tuple[bool, str]:
    """
    Return (is_govm_subproduct, canonical_subproduct_name).
    Only canonical subproduct names are returned when True.
    """
    p = (rec.get("product") or rec.get("service") or "") or ""
    ch = extract_channel(rec)
    fr = rec.get("fromDisplay") or (rec.get("raw_event") or {}).get("fromDisplay") \
         or rec.get("source") or rec.get("source_system") or ""
    tags = rec.get("tags") or (rec.get("raw_event") or {}).get("tags") or []
    body = (rec.get("body") or (rec.get("raw_event") or {}).get("text") or "")

    # 1) Alias on explicit fields (highest priority)
    alias = _alias_lookup_tokenized([p, fr, ch] + list(tags))
    if alias:
        if alias == "GovMeetings":
            # Family tag alone isn't a subproduct; keep looking for a subproduct, else return family
            alias_body = _alias_lookup_tokenized([body])
            if alias_body and alias_body != "GovMeetings":
                return True, alias_body
            return True, "GovMeetings"
        return True, alias

    # 2) If explicit product string itself looks like a GM subproduct by embedded pattern
    if p:
        alias_p = _alias_lookup_tokenized([p])
        if alias_p:
            return True, alias_p

    # 3) Body scan (supports embedded names like govmeetings-iqm-*)
    alias_body = _alias_lookup_tokenized([body])
    if alias_body:
        return True, alias_body

    # 4) Generic GovM family detection
    is_gm, canon = is_govmeetings_product(" | ".join([p, ch, fr, body]))
    if is_gm:
        # If only family-level identified, surface GovMeetings (still acceptable if ONLY_GOVM_SUBPRODUCTS is True? -> keep but may be filtered later)
        return True, canon

    return False, "Unknown"

def is_relevant_to_govm(rec: Dict) -> bool:
    """Used for alerts_prod strict filter and the global GovM-only rule."""
    ok, _ = infer_govm_subproduct(rec)
    return ok

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
    "- Collect and return distinct source channels contributing to each group in 'source_channels' (strings) based on the 'channel' field of items.\n"
    "- If an item's body contains HTML (rich-text), treat it as content (strip tags if needed for previews) but do not discard the information.\n"
    "Respond ONLY with JSON matching this schema: {\n"
    "  kpis: {critical:number, warning:number, unknown:number, noise:number},\n"
    "  groups: [{product:string, title:string, summary:string, severity:string, component?:string|null,\n"
    "           first_seen_utc:string, last_seen_utc:string, occurrences:number,\n"
    "           source_channels?:string[],\n"
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

COMPONENT_ENRICH_INSTRUCTION = (
    "You are a production SRE. For each item, infer a short 'component' label from title/summary/context.\n"
    "Keep labels terse and technical, e.g., 'API Gateway', 'Auth', 'K8s/Node', 'Transcoder', 'DB', 'Cache', 'Queues', 'Ingress', 'Storage'.\n"
    "If unsure, use 'General'. Respond ONLY with JSON array of objects: [{idx:number, component:string}]."
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

def invoke_bedrock_component_enrich(groups_missing: List[Dict]) -> Dict[int, str]:
    """
    groups_missing: list of dicts each with {idx:int, title:str, summary:str, product:str}
    returns: {idx: component}
    """
    if not groups_missing:
        return {}
    try:
        payload = [{"idx": g["idx"], "title": g.get("title",""), "summary": g.get("summary",""), "product": g.get("product","")} for g in groups_missing]
        user_message = json.dumps(payload, indent=2, cls=DateTimeEncoder)
        body_bytes = _build_bedrock_body(COMPONENT_ENRICH_INSTRUCTION, user_message)
        response_body = _bedrock_invoke_with_retry(body_bytes, model_id=COMPONENT_MODEL_ID)
        txt = response_body.get('content', [{}])[0].get('text', "").strip()
        mapping = {}
        try:
            arr = json.loads(txt)
            for obj in (arr or []):
                idx = int(obj.get("idx"))
                comp = (obj.get("component") or "").strip() or "General"
                mapping[idx] = comp
        except Exception as e:
            logger.error(f"Component enrich parse error: {e}; raw={preview(txt,200)}")
        return mapping
    except Exception as e:
        logger.error(f"Component enrich failed: {e}")
        return {}

# ---- Merge, filter & KPI recompute ----
SEV_RANK = {"critical": 0, "warning": 1, "unknown": 2}

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
                    "component": g.get("component"),
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

def filter_groups_to_govm_subproducts(groups_map: Dict[Tuple[str, str, str], Dict]) -> Dict[Tuple[str, str, str], Dict]:
    """Keep only groups where product is a known GovM subproduct (or GovMeetings family if nothing better)."""
    out = {}
    for k, v in groups_map.items():
        prod = (v.get("product") or "").strip()
        nk = _norm_key(prod)
        # Accept if canonical value found in alias values
        if prod in set(GOVM_ALIAS_MAP_NORM.values()):
            out[k] = v
            continue
        # Accept if normalized key itself maps to a canonical GovM subproduct
        if nk in GOVM_ALIAS_MAP_NORM and GOVM_ALIAS_MAP_NORM[nk] in set(GOVM_ALIAS_MAP_NORM.values()):
            out[k] = v
            continue
        # Accept if product equals 'GovMeetings' (family) — optional; keep for visibility
        if prod.lower() == "govmeetings":
            out[k] = v
            continue
        # else drop
    return out

def recompute_group_kpis(groups: Dict[Tuple[str, str, str], Dict]) -> Dict[str, int]:
    """
    KPIs should count distinct listed alerts (groups), NOT sum of occurrences.
    """
    out = {"critical": 0, "warning": 0, "unknown": 0, "noise": 0}
    for (_, _, _), g in groups.items():
        sev = (g.get("severity") or "Unknown").lower()
        if sev in out:
            out[sev] += 1
        else:
            out["unknown"] += 1
    out["total_alerts"] = out["critical"] + out["warning"] + out["unknown"]
    return out

def _rank_for_product(groups: List[Dict]) -> int:
    worst = 9
    for g in groups:
        s = (g.get('severity') or '').lower()
        worst = min(worst, SEV_RANK.get(s, 9))
    return worst

def _govmeetings_first_key(item):
    prod, groups = item
    is_gm, _canon = is_govmeetings_product(prod)
    return (0 if is_gm else 1, _rank_for_product(groups), prod.lower())

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
    _add(lines, f"- 🔴 Critical: {k.get('critical', 0)}")
    _add(lines, f"- 🟠 Warning: {k.get('warning', 0)}")
    _add(lines, f"- ⚪ Other: {k.get('unknown', 0)}")
    _add(lines, f"- **Total alerts:** {k.get('total_alerts', 0)}")
    _add(lines, "")
    if exec_summary:
        _add(lines, "### Executive Summary")
        for line in exec_summary.splitlines():
            _add(lines, line)
        _add(lines, "")

    # Group by product (GovM subproducts only have been filtered)
    by_product: Dict[str, List[Dict]] = {}
    for (_, _, _), g in agg.get("groups", {}).items():
        by_product.setdefault(g["product"], []).append(g)

    gm_set = set()
    other_set = set()
    for prod in by_product.keys():
        is_gm, canon = is_govmeetings_product(prod)
        if is_gm:
            gm_set.add(canon)
        else:
            other_set.add(prod)

    _add(lines, "### GovMeetings products in this window")
    _add(lines, "- " + (", ".join(sorted(gm_set)) if gm_set else "_None detected_"))
    _add(lines, "### Other products")
    _add(lines, "- " + (", ".join(sorted(other_set)) if other_set else "_None_"))
    _add(lines, "")

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

            is_gm, _canon = is_govmeetings_product(product)
            display_title = f"GovMeetings - {product}: {title}" if is_gm else title

            _add(lines, f"**{emoji} {display_title}**")
            _add(lines, f"- **Severity:** {emoji} {g.get('severity')}")
            _add(lines, f"- **Component:** _{component}_")
            if src_channels: _add(lines, f"- **Source Channels:** {', '.join(src_channels[:8])}")
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

    # Appendix
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
    _add(lines, "**Summary (grouped, unique alerts)**")
    _add(lines, f"- 🔴 Critical: {k.get('critical', 0)}")
    _add(lines, f"- 🟠 Warning: {k.get('warning', 0)}")
    _add(lines, f"- ⚪ Other: {k.get('unknown', 0)}")
    _add(lines, f"- **Total alerts:** {k.get('total_alerts', 0)}")
    _add(lines, "")
    if exec_summary:
        _add(lines, "**Executive Summary**")
        for line in exec_summary.splitlines():
            _add(lines, line)
        _add(lines, "")

    by_product: Dict[str, List[Dict]] = {}
    for (_, _, _), g in agg.get("groups", {}).items():
        by_product.setdefault(g["product"], []).append(g)

    gm_set = set()
    other_set = set()
    for prod in by_product.keys():
        is_gm, canon = is_govmeetings_product(prod)
        if is_gm:
            gm_set.add(canon)
        else:
            other_set.add(prod)

    _add(lines, "### GovMeetings products in this window")
    _add(lines, "- " + (", ".join(sorted(gm_set)) if gm_set else "_None detected_"))
    _add(lines, "### Other products")
    _add(lines, "- " + (", ".join(sorted(other_set)) if other_set else "_None_"))
    _add(lines, "")

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
            ent = g.get("entities") or {}
            hosts = ent.get("affected_hosts") or []
            src_channels = g.get("source_channels") or []
            host_txt = f" • Hosts: {', '.join(hosts[:5])}" if hosts else ""
            ch_txt = f" • Channels: {', '.join(src_channels[:3])}" if src_channels else ""

            is_gm, _canon = is_govmeetings_product(product)
            display_title = f"GovMeetings - {product}: {title}" if is_gm else title

            _add(lines, f"- {emoji} **{display_title}** — {summ}{host_txt}{ch_txt}  _({fs} → {ls})_")
        _add(lines, "")

    md = "\n".join(lines).strip()
    if len(md) > TEAMS_MAX_CHARS:
        md = md[:TEAMS_MAX_CHARS - 2000] + "\n\n_(truncated to fit Teams limit)_"
    return md

# ---- Debug Logging of Collected Alerts ----
def log_alert_details(alerts: List[Dict]):
    if not (DEBUG_MODE and LOG_ALERT_DETAIL):
        return
    limit = min(ALERT_LOG_LIMIT, len(alerts))
    logger.info(f"Logging first {limit} alerts (of {len(alerts)}) for digest debug")
    for i, a in enumerate(alerts[:limit]):
        body_preview = preview(a.get("body", ""), 140)
        logger.info(json.dumps({
            "tag": "ALERT_FOR_DIGEST",
            "idx": i,
            "messageId": a.get("messageId"),
            "event_ts_utc": a.get("event_ts_utc"),
            "from": a.get("fromDisplay"),
            "channel": a.get("channel"),
            "norm_severity": a.get("norm_severity"),
            "product": a.get("product"),
            "body_preview": body_preview,
            "body_hash": body_hash(a.get("body", "")),
        }, cls=DateTimeEncoder))
    if len(alerts) > limit:
        logger.info(f"(Suppressed {len(alerts) - limit} additional alerts; increase ALERT_LOG_LIMIT to see more)")

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

# ---- Collection from S3 ----
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
    day = start_utc.date()
    while day <= end_utc.date():
        for key, size in iter_day_objects(ALERTS_BUCKET, day):
            stats["objects_listed"] += 1
            if not (key.endswith(".jsonl") or key.endswith(".jsonl.gz")):
                continue
            stats["objects_read"] += 1
            if DEBUG_MODE:
                logger.info(f"Reading {key} ({size} bytes)")
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

                # ---- per-record filters & enrich ----
                ch = (extract_channel(rec) or "").strip().lower()

                # STRICT GovM-only for alerts_prod (kept)
                if STRICT_GOVM_ONLY_IN_ALERTS_PROD and ch == "alerts_prod":
                    if not is_relevant_to_govm(rec):
                        continue

                # Global rule: only GovM subproducts make it into digest
                is_gm, canon_sub = infer_govm_subproduct(rec)
                if not is_gm:
                    continue  # drop non-GovM entirely
                # Use canonical subproduct if available; else family
                product_val = canon_sub

                norm_sev = derive_severity(rec)
                if should_skip_unknown(rec, body, norm_sev):
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

    # Collect alerts
    alerts = collect_alerts_s3(start_utc, end_utc, MAX_ALERTS)
    if DEBUG_MODE:
        logger.info(f"Collected {len(alerts)} candidate alerts for window {window_label}")

    if not alerts:
        md = "## 🛡️ SRE Digest\n\n_No GovMeetings alerts in this window._\n\n" + \
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

    # ---- Parallel Bedrock calls ----
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

    # Keep only GovM subproducts/groups
    agg["groups"] = filter_groups_to_govm_subproducts(agg.get("groups", {}))

    # KPI recompute: counts unique groups per severity (no occurrence inflation)
    agg["kpis"] = recompute_group_kpis(agg.get("groups", {}))

    # Optional: Component enrichment
    if GENERATE_COMPONENTS:
        groups_list = list(agg["groups"].items())
        missing_payload = []
        idx_map = {}
        for i, (k, g) in enumerate(groups_list):
            comp = (g.get("component") or "").strip()
            if not comp or comp == "—":
                idx = len(missing_payload)
                missing_payload.append({"idx": idx, "title": g.get("title",""), "summary": g.get("summary",""), "product": g.get("product","")})
                idx_map[idx] = k
        mapping = invoke_bedrock_component_enrich(missing_payload)
        for idx, comp in mapping.items():
            k = idx_map.get(idx)
            if k and k in agg["groups"]:
                agg["groups"][k]["component"] = comp

    # Exec summary
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
