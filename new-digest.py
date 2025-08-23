import os
import json
import re
import hashlib
import datetime as dt
from typing import List, Dict, Optional

import boto3

# =========================
# Environment Variables
# =========================
DDB_TABLE                = os.environ["DDB_TABLE"]                 # e.g., "sre-alerts"
AGENT_ID                 = os.environ["AGENT_ID"]                  # Bedrock Agent ID
AGENT_ALIAS_ID           = os.environ["AGENT_ALIAS_ID"]            # Bedrock Agent Alias ID
TEAMS_WEBHOOK            = os.environ["TEAMS_WEBHOOK"]             # Teams Incoming Webhook URL

# Scan & batching controls
MAX_ITEMS                = int(os.environ.get("MAX_ITEMS", "5000"))
MAX_BODIES_PER_CALL      = int(os.environ.get("MAX_BODIES_PER_CALL", "120"))

# Behavior flags
AUDIT_SUMMARY_IN_TEAMS   = os.environ.get("AUDIT_SUMMARY_IN_TEAMS", "false").lower() == "true"
AUDIT_MAX_IDS            = int(os.environ.get("AUDIT_MAX_IDS", "20"))
STRICT_BODY_ONLY         = os.environ.get("STRICT_BODY_ONLY", "true").lower() == "true"
TRIM_TODAY_TO_NOW        = os.environ.get("TRIM_TODAY_TO_NOW", "true").lower() == "true"

# 🔧 DEBUG controls
DEBUG_MODE               = os.environ.get("DEBUG_MODE", "false").lower() == "true"
DEBUG_FORCE_FULL_DAY     = os.environ.get("DEBUG_FORCE_FULL_DAY", "true").lower() == "true"  # if true and DEBUG_MODE, never trim today's day to now
DEBUG_PREVIEW_LEN        = int(os.environ.get("DEBUG_PREVIEW_LEN", "65"))                    # chars to show from body
SAVE_BEDROCK_LOGS        = os.environ.get("SAVE_BEDROCK_LOGS", "false").lower() == "true"
BEDROCK_LOGS_S3_BUCKET   = os.environ.get("BEDROCK_LOGS_S3_BUCKET", "")
BEDROCK_LOGS_S3_PREFIX   = os.environ.get("BEDROCK_LOGS_S3_PREFIX", "bedrock/digests/")

# =========================
# AWS Clients
# =========================
ddb        = boto3.resource("dynamodb")
table      = ddb.Table(DDB_TABLE)
agent_rt   = boto3.client("bedrock-agent-runtime")
s3         = boto3.client("s3") if SAVE_BEDROCK_LOGS and BEDROCK_LOGS_S3_BUCKET else None

IST = dt.timezone(dt.timedelta(hours=5, minutes=30))  # Asia/Kolkata


# =========================
# Utilities
# =========================
def now_utc() -> dt.datetime:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc, microsecond=0)

def iso_z(ts: dt.datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def parse_dt(s: str) -> dt.datetime:
    """Parse ISO with/without Z; default to now if parse fails."""
    try:
        s = s.strip()
        if s.endswith("Z"):
            s = s[:-1]
            return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)
        return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)
    except Exception:
        return now_utc()

def body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]

def preview(s: str, n: int) -> str:
    s = (s or "").strip().replace("\n", " ")
    return (s[:n] + "…") if len(s) > n else s

def to_ist_day_bounds(day_ist_str: Optional[str]) -> (dt.datetime, dt.datetime, str):
    """
    Returns (start_utc, end_utc, window_label_ist) for a full IST day.
    If DEBUG_MODE & DEBUG_FORCE_FULL_DAY, end is always 23:59:59 IST even for 'today'.
    Else if TRIM_TODAY_TO_NOW=true and day is today, end is 'now'.
    """
    now = now_utc().astimezone(IST)
    if not day_ist_str or day_ist_str.lower() == "today":
        day_date = now.date()
    elif day_ist_str.lower() == "yesterday":
        day_date = (now - dt.timedelta(days=1)).date()
    else:
        y, m, d = map(int, day_ist_str.split("-"))
        day_date = dt.date(y, m, d)

    start_ist = dt.datetime(day_date.year, day_date.month, day_date.day, 0, 0, 0, tzinfo=IST)
    end_ist_full = start_ist + dt.timedelta(days=1)

    if DEBUG_MODE and DEBUG_FORCE_FULL_DAY:
        # Always full-day for the chosen date
        end_ist = end_ist_full - dt.timedelta(seconds=1)
    else:
        if TRIM_TODAY_TO_NOW and day_date == now.date() and now < end_ist_full:
            end_ist = now
        else:
            end_ist = end_ist_full - dt.timedelta(seconds=1)

    start_utc = start_ist.astimezone(dt.timezone.utc)
    end_utc = end_ist.astimezone(dt.timezone.utc)
    label = f"{start_ist.strftime('%d %b %Y 00:00')} – {end_ist.strftime('%H:%M')} IST"
    return start_utc, end_utc, label


# =========================
# Robust Timestamp Coercion
# =========================
def _parse_messy_created_str(s: str) -> Optional[dt.datetime]:
    """
    Accepts '2025-08-21714:33:32.8052' or '2025-08-21T14:33:32.8052' and coerces to UTC dt.
    """
    if not s or not isinstance(s, str):
        return None
    s = s.strip().replace(" ", "")
    if "T" not in s and len(s) >= 15 and s[4] == "-" and s[7] == "-":
        s = s[:10] + "T" + s[10:]
    s = re.sub(r"(IST|UTC)$", "", s, flags=re.I).strip()
    if not re.search(r"[zZ]|[+\-]\d\d:\d\d$", s):
        s = s + "Z"
    try:
        return parse_dt(s)
    except Exception:
        return None

def coerce_item_ts_utc(it: Dict) -> Optional[dt.datetime]:
    """Prefer 'created' string; else 'receivedAt' epoch seconds."""
    created = it.get("created")
    if isinstance(created, str):
        dtc = _parse_messy_created_str(created)
        if dtc:
            return dtc
    recv = it.get("receivedAt")
    try:
        if isinstance(recv, (int, float)):
            return dt.datetime.fromtimestamp(int(recv), tz=dt.timezone.utc)
        if isinstance(recv, str) and recv.isdigit():
            return dt.datetime.fromtimestamp(int(recv), tz=dt.timezone.utc)
    except Exception:
        pass
    return None


# =========================
# DynamoDB Fetch (whole-day, body-only)
# =========================
def fetch_items_for_window(start_utc: dt.datetime, end_utc: dt.datetime) -> List[Dict]:
    """
    Full table scan (capped) + local filtering by coerce_item_ts_utc(it).
    For production scale, use a GSI on a clean timestamp and Query.
    """
    items: List[Dict] = []
    resp = table.scan(Limit=MAX_ITEMS)
    items.extend(resp.get("Items", []))
    while "LastEvaluatedKey" in resp and len(items) < MAX_ITEMS:
        resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"], Limit=MAX_ITEMS - len(items))
        items.extend(resp.get("Items", []))

    kept = []
    for it in items:
        ts = coerce_item_ts_utc(it)
        if ts is None:
            continue
        if start_utc <= ts <= end_utc:
            b = it.get("body")
            if isinstance(b, str) and b.strip():
                kept.append({
                    "messageId": it.get("messageId") or it.get("messageld") or it.get("id") or it.get("incidentKey") or "unknown",
                    "created": iso_z(ts),
                    "body": b
                })
    return kept

def normalize_body_for_bedrock(bodies: List[str]) -> List[str]:
    out = []
    for b in bodies:
        bb = re.sub(r"\s+", " ", (b or "")).strip()
        if bb:
            out.append(bb)
    return out


# =========================
# Bedrock Agent Call (body-only) + S3 logging
# =========================
def call_bedrock_agent(bodies: List[str], window_label_ist: str, session_id: str, chunk_idx: int) -> str:
    payload = {
        "instruction": (
            f"Create an SRE manager digest for this window (IST): {window_label_ist}. "
            f"Use ONLY the HTML 'body' of each item below; ignore any other fields. "
            f"Output clean Markdown with emoji sections."
        ),
        "items": [{"body": b} for b in bodies]
    }

    resp = agent_rt.invoke_agent(
        agentId=AGENT_ID,
        agentAliasId=AGENT_ALIAS_ID,
        sessionId=session_id,
        inputText=json.dumps(payload),
    )

    result_text = ""
    if "completion" in resp and isinstance(resp["completion"], list):
        for ev in resp["completion"]:
            if isinstance(ev, dict) and "data" in ev:
                result_text += ev["data"]
    elif "outputText" in resp:
        result_text = resp["outputText"]
    elif "message" in resp:
        result_text = resp["message"].get("content", "")

    result_text = (result_text or "").strip()

    # Optional: Save Bedrock logs to S3 (payload previews + response)
    if SAVE_BEDROCK_LOGS and s3:
        try:
            body_previews = [preview(b, 200) for b in bodies]
            log_obj = {
                "ts_utc": iso_z(now_utc()),
                "session_id": session_id,
                "chunk_index": chunk_idx,
                "window_label_ist": window_label_ist,
                "items_count": len(bodies),
                "bodies_preview": body_previews,
                "response_preview": preview(result_text, 1000)
            }
            key = f"{BEDROCK_LOGS_S3_PREFIX.rstrip('/')}/{session_id}/chunk-{chunk_idx:03d}.json"
            s3.put_object(
                Bucket=BEDROCK_LOGS_S3_BUCKET,
                Key=key,
                Body=json.dumps(log_obj, ensure_ascii=False).encode("utf-8"),
                ContentType="application/json"
            )
        except Exception as e:
            print(f"BEDROCK_LOG_SAVE_ERR: {e}")

    return result_text


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
# Lambda Handler (Whole-day with Debug)
# =========================
def lambda_handler(event, context):
    """
    Whole-day IST digest (body-only), with debug mode & Bedrock S3 logging.

    Overrides in event:
      - {"day_ist": "YYYY-MM-DD" | "today" | "yesterday"}  # default: today
      - {"override_start_iso": "...Z", "override_end_iso": "...Z"}  # absolute UTC window for debugging
    """
    # Build window
    override_start = (event or {}).get("override_start_iso")
    override_end   = (event or {}).get("override_end_iso")
    if override_start and override_end:
        start_utc = parse_dt(override_start)
        end_utc   = parse_dt(override_end)
        window_label_ist = f"{start_utc.astimezone(IST).strftime('%d %b %Y %H:%M')} – {end_utc.astimezone(IST).strftime('%H:%M')} IST"
    else:
        day_ist_str = (event or {}).get("day_ist")
        start_utc, end_utc, window_label_ist = to_ist_day_bounds(day_ist_str)

    # Fetch and filter by window
    items = fetch_items_for_window(start_utc, end_utc)

    # Intake / audit bookkeeping
    audit = {
        "window": window_label_ist,
        "debug_mode": DEBUG_MODE,
        "fetched_count": len(items),
        "with_body_count": 0,
        "deduped_unique_bodies": 0,
        "forwarded_ids": [],
        "skipped_no_body": [],
        "dedup_groups": {},         # h -> {count, sample_ids, preview}
        "debug_previews": []        # list of lines for Teams debug section
    }

    if not items:
        md = f"**SRE Digest – {window_label_ist}**\n\n_No alert bodies found in this window._"
        if DEBUG_MODE:
            md += "\n\n**🧪 Debug**\n• Window forced full-day: " + ("yes" if (DEBUG_MODE and DEBUG_FORCE_FULL_DAY) else "no")
        post_markdown_to_teams(md)
        return {"ok": True, "posted": True, "window": window_label_ist, "items_fetched": 0, "debug": DEBUG_MODE}

    # Deduplicate by exact body content
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

    # Prepare bodies for Bedrock & collect debug preview lines
    bodies_all = []
    for h, g in by_hash.items():
        bodies_all.append(g["body"])
        if DEBUG_MODE:
            pv = preview(g["body"], DEBUG_PREVIEW_LEN)
            ids = ", ".join(g["ids"][:min(5, AUDIT_MAX_IDS)])
            audit["dedup_groups"][h] = {"count": len(g["ids"]), "sample_ids": g["ids"][:min(5, AUDIT_MAX_IDS)], "preview": pv}
            audit["debug_previews"].append(f"• [{len(g['ids'])}×] {h}: “{pv}” IDs: {ids}{'…' if len(g['ids']) > 5 else ''}")

    bodies_all = normalize_body_for_bedrock(bodies_all)

    # Track covered IDs
    covered_ids = []
    for g in by_hash.values():
        covered_ids.extend(g["ids"])
    audit["forwarded_ids"] = covered_ids[:AUDIT_MAX_IDS]

    # Invoke Bedrock in chunks, saving logs per chunk if enabled
    session_id = "sre-digest-" + now_utc().strftime("%Y%m%d%H%M%S")
    digests: List[str] = []
    for i in range(0, len(bodies_all), MAX_BODIES_PER_CALL):
        chunk = bodies_all[i:i + MAX_BODIES_PER_CALL]
        md = call_bedrock_agent(chunk, window_label_ist, session_id, i // MAX_BODIES_PER_CALL)
        if md:
            digests.append(md)

    final_md = "\n\n---\n\n".join(digests).strip()
    if not final_md:
        final_md = f"**SRE Digest – {window_label_ist}**\n\n_No actionable items parsed from alert bodies in this window._"

    # Optional Audit footer
    if AUDIT_SUMMARY_IN_TEAMS:
        def join_ids(lst):
            return ", ".join(str(x) for x in lst[:AUDIT_MAX_IDS]) + ("..." if len(lst) > AUDIT_MAX_IDS else "")
        final_md += "\n\n---\n\n"
        final_md += f"**🧾 Intake Summary**\n"
        final_md += f"- Window: {audit['window']} | Debug: {'on' if DEBUG_MODE else 'off'}\n"
        final_md += f"- Fetched: {audit['fetched_count']} | With body: {audit['with_body_count']} | Unique bodies (dedup): {audit['deduped_unique_bodies']}\n"
        if audit["skipped_no_body"]:
            final_md += f"- Skipped (no body): {join_ids(audit['skipped_no_body'])}\n"
        if audit["forwarded_ids"]:
            final_md += f"- Covered IDs: {join_ids(audit['forwarded_ids'])}\n"

    # Optional Debug section with 65-char previews
    if DEBUG_MODE and audit["debug_previews"]:
        final_md += "\n\n**🧪 Debug (processed bodies)**\n"
        # Cap lines to avoid giant posts
        dbg_lines = audit["debug_previews"][:AUDIT_MAX_IDS]
        final_md += "\n".join(dbg_lines)

    # Post to Teams
    post_markdown_to_teams(final_md)

    # Return + log to CloudWatch
    ret = {
        "ok": True,
        "posted": True,
        "window": window_label_ist,
        "items_fetched": audit["fetched_count"],
        "items_with_body": audit["with_body_count"],
        "unique_bodies_forwarded": audit["deduped_unique_bodies"],
        "forwarded_ids_sample": audit["forwarded_ids"],
        "debug_mode": DEBUG_MODE
    }
    print("AUDIT:", json.dumps(audit)[:8000])
    return ret
