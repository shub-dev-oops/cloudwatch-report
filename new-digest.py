import os
import json
import re
import hashlib
import datetime as dt
from typing import List, Dict

import boto3
from boto3.dynamodb.conditions import Attr

# =========================
# Environment Variables
# =========================
DDB_TABLE             = os.environ["DDB_TABLE"]                 # e.g., "sre-alerts"
AGENT_ID              = os.environ["AGENT_ID"]                  # Bedrock Agent ID
AGENT_ALIAS_ID        = os.environ["AGENT_ALIAS_ID"]            # Bedrock Agent Alias ID
TEAMS_WEBHOOK         = os.environ["TEAMS_WEBHOOK"]             # Teams Incoming Webhook URL
PARAM_LAST_RUN        = os.environ.get("PARAM_LAST_RUN", "/sre-digest/last_run_utc")
DEFAULT_LOOKBACK_MIN  = int(os.environ.get("DEFAULT_LOOKBACK_MIN", "60"))
MAX_ITEMS             = int(os.environ.get("MAX_ITEMS", "200"))               # safety cap per run
MAX_BODIES_PER_CALL   = int(os.environ.get("MAX_BODIES_PER_CALL", "80"))      # chunking to control tokens

# Audit / behavior flags
AUDIT_SUMMARY_IN_TEAMS = os.environ.get("AUDIT_SUMMARY_IN_TEAMS", "false").lower() == "true"
AUDIT_MAX_IDS          = int(os.environ.get("AUDIT_MAX_IDS", "20"))
STRICT_BODY_ONLY       = os.environ.get("STRICT_BODY_ONLY", "true").lower() == "true"

# =========================
# AWS Clients
# =========================
ddb        = boto3.resource("dynamodb")
table      = ddb.Table(DDB_TABLE)
ssm        = boto3.client("ssm")
agent_rt   = boto3.client("bedrock-agent-runtime")

IST = dt.timezone(dt.timedelta(hours=5, minutes=30))  # Asia/Kolkata


# =========================
# Utilities
# =========================
def now_utc() -> dt.datetime:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc, microsecond=0)

def iso_z(ts: dt.datetime) -> str:
    """Return ISO8601 Z string."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def parse_dt(s: str) -> dt.datetime:
    """Parse basic ISO string with or without Z; default to now if parse fails."""
    try:
        s = s.strip()
        if s.endswith("Z"):
            s = s[:-1]
            return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)
        return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)
    except Exception:
        return now_utc()

def to_ist_label(start_utc: dt.datetime, end_utc: dt.datetime) -> str:
    s_ist = start_utc.astimezone(IST)
    e_ist = end_utc.astimezone(IST)
    if s_ist.date() == e_ist.date():
        return f"{s_ist.strftime('%d %b %Y %H:%M')} – {e_ist.strftime('%H:%M')} IST"
    return f"{s_ist.strftime('%d %b %Y %H:%M')} – {e_ist.strftime('%d %b %Y %H:%M')} IST"

def body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


# =========================
# SSM Watermark
# =========================
def get_last_run_iso() -> str:
    try:
        r = ssm.get_parameter(Name=PARAM_LAST_RUN)
        return r["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        # Create a starting watermark = now-DEFAULT_LOOKBACK_MIN
        start = now_utc() - dt.timedelta(minutes=DEFAULT_LOOKBACK_MIN)
        start_iso = iso_z(start)
        # seed parameter so next run is consistent
        ssm.put_parameter(Name=PARAM_LAST_RUN, Value=start_iso, Type="String", Overwrite=True)
        return start_iso

def set_last_run_iso(ts_iso: str) -> None:
    ssm.put_parameter(Name=PARAM_LAST_RUN, Value=ts_iso, Type="String", Overwrite=True)


# =========================
# DynamoDB Fetch (body-only)
# =========================
def fetch_recent_items(start_iso: str, end_iso: str) -> List[Dict]:
    """
    MVP: Scan with FilterExpression on 'created' (string ISO).
    For production, add a GSI on 'created' and use Query.
    """
    items: List[Dict] = []
    filt = Attr("created").between(start_iso, end_iso)

    resp = table.scan(FilterExpression=filt, Limit=MAX_ITEMS)
    items.extend(resp.get("Items", []))
    while "LastEvaluatedKey" in resp and len(items) < MAX_ITEMS:
        resp = table.scan(
            FilterExpression=filt,
            ExclusiveStartKey=resp["LastEvaluatedKey"],
            Limit=MAX_ITEMS - len(items),
        )
        items.extend(resp.get("Items", []))

    # Keep minimal fields for audit; digest will use ONLY 'body'
    kept = []
    for it in items:
        b = it.get("body")
        if isinstance(b, str) and b.strip():
            kept.append({
                "messageId": it.get("messageId") or it.get("messageld") or it.get("id") or it.get("incidentKey") or "unknown",
                "created": it.get("created") or it.get("receivedAt") or "",
                "body": b
            })
    return kept

def normalize_body_for_bedrock(bodies: List[str]) -> List[str]:
    """Light cleanup only; Agent prompt will parse/format."""
    out = []
    for b in bodies:
        bb = re.sub(r"\s+", " ", (b or "")).strip()
        if bb:
            out.append(bb)
    return out


# =========================
# Bedrock Agent Call
# =========================
def call_bedrock_agent(bodies: List[str], window_label_ist: str) -> str:
    """
    Sends ONLY 'body' strings to the Agent.
    The Agent's System Prompt must enforce:
      - body-only parsing,
      - emoji sections,
      - Markdown output.
    """
    payload = {
        "instruction": (
            f"Create an SRE manager digest for this window (IST): {window_label_ist}. "
            f"Use ONLY the HTML 'body' of each item below; ignore any other fields. "
            f"Output clean Markdown with emoji sections."
        ),
        "items": [{"body": b} for b in bodies]
    }

    session_id = "sre-digest-" + now_utc().strftime("%Y%m%d%H%M%S")

    resp = agent_rt.invoke_agent(
        agentId=AGENT_ID,
        agentAliasId=AGENT_ALIAS_ID,
        sessionId=session_id,
        inputText=json.dumps(payload),
    )

    # Collect streamed or direct text
    result_text = ""
    if "completion" in resp and isinstance(resp["completion"], list):
        for ev in resp["completion"]:
            if isinstance(ev, dict) and "data" in ev:
                result_text += ev["data"]
    elif "outputText" in resp:
        result_text = resp["outputText"]
    elif "message" in resp:
        result_text = resp["message"].get("content", "")

    return (result_text or "").strip()


# =========================
# Teams Webhook
# =========================
def post_markdown_to_teams(markdown_text: str) -> None:
    import urllib.request
    body = json.dumps({"text": markdown_text}).encode("utf-8")
    req = urllib.request.Request(
        TEAMS_WEBHOOK,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        _ = resp.read()


# =========================
# Lambda Handler
# =========================
def lambda_handler(event, context):
    """
    EventBridge (cron hourly) friendly.
    Supports manual override:
      {
        "override_start_iso": "2025-08-21T13:00:00Z",
        "override_end_iso":   "2025-08-21T14:00:00Z"
      }
    """
    end_utc = now_utc()

    override_start = (event or {}).get("override_start_iso")
    override_end   = (event or {}).get("override_end_iso")

    if override_start and override_end:
        start_iso = override_start
        end_iso   = override_end
    else:
        start_iso = get_last_run_iso()
        end_iso   = iso_z(end_utc)

    start_utc = parse_dt(start_iso)
    end_utc   = parse_dt(end_iso)

    window_label_ist = to_ist_label(start_utc, end_utc)

    # Fetch recent items
    items = fetch_recent_items(iso_z(start_utc), iso_z(end_utc))

    # Intake / audit bookkeeping
    audit = {
        "window": window_label_ist,
        "fetched_count": len(items),
        "with_body_count": 0,
        "deduped_unique_bodies": 0,
        "forwarded_ids": [],
        "skipped_no_body": [],
        "dedup_groups": {}  # h -> {count, sample_ids}
    }

    if not items:
        set_last_run_iso(iso_z(end_utc))
        return {"ok": True, "message": "No items in window.", "window": window_label_ist}

    # Build dedupe map by body content
    by_hash: Dict[str, Dict] = {}
    for it in items:
        b = (it["body"] or "").strip()
        mid = it.get("messageId", "unknown")
        if not b:
            audit["skipped_no_body"].append(mid)
            continue
        audit["with_body_count"] += 1
        h = body_hash(b)
        g = by_hash.setdefault(h, {"body": b, "ids": [], "created": []})
        g["ids"].append(mid)
        g["created"].append(it.get("created", ""))

    audit["deduped_unique_bodies"] = len(by_hash)

    # Forward exactly one representative per identical body to Bedrock
    bodies_all = [g["body"] for g in by_hash.values()]
    bodies_all = normalize_body_for_bedrock(bodies_all)

    # Track which IDs are covered by the forwarded bodies
    covered_ids = []
    for g in by_hash.values():
        covered_ids.extend(g["ids"])
    audit["forwarded_ids"] = covered_ids[:AUDIT_MAX_IDS]

    for h, g in by_hash.items():
        audit["dedup_groups"][h] = {
            "count": len(g["ids"]),
            "sample_ids": g["ids"][:min(5, AUDIT_MAX_IDS)]
        }

    # Call Bedrock Agent in chunks if needed
    digests: List[str] = []
    for i in range(0, len(bodies_all), MAX_BODIES_PER_CALL):
        chunk = bodies_all[i:i + MAX_BODIES_PER_CALL]
        md = call_bedrock_agent(chunk, window_label_ist)
        if md:
            digests.append(md)

    final_md = "\n\n---\n\n".join(digests).strip()
    if not final_md:
        final_md = f"**SRE Digest – {window_label_ist}**\n\n_No actionable items parsed from alert bodies in this window._"

    # Optional intake/audit summary appended to Teams
    if AUDIT_SUMMARY_IN_TEAMS:
        def join_ids(lst):
            return ", ".join(str(x) for x in lst[:AUDIT_MAX_IDS]) + ("..." if len(lst) > AUDIT_MAX_IDS else "")
        final_md += "\n\n---\n\n"
        final_md += f"**🧾 Intake Summary**\n"
        final_md += f"- Window: {audit['window']}\n"
        final_md += f"- Fetched: {audit['fetched_count']} | With body: {audit['with_body_count']} | Unique bodies (after dedupe): {audit['deduped_unique_bodies']}\n"
        if audit["skipped_no_body"]:
            final_md += f"- Skipped (no body): {join_ids(audit['skipped_no_body'])}\n"
        if audit["forwarded_ids"]:
            final_md += f"- Covered IDs (forwarded via dedupe): {join_ids(audit['forwarded_ids'])}\n"

    # Post to Teams
    post_markdown_to_teams(final_md)

    # Advance watermark
    set_last_run_iso(iso_z(end_utc))

    # Return details (and log full audit to CW)
    ret = {
        "ok": True,
        "posted": True,
        "window": window_label_ist,
        "items_fetched": audit["fetched_count"],
        "items_with_body": audit["with_body_count"],
        "unique_bodies_forwarded": audit["deduped_unique_bodies"],
        "forwarded_ids_sample": audit["forwarded_ids"],
        "skipped_no_body_sample": audit["skipped_no_body"][:AUDIT_MAX_IDS]
    }
    print("AUDIT:", json.dumps(audit)[:8000])  # truncated for log safety
    return ret
