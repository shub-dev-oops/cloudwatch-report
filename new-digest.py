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
DEBUG_FORCE_FULL_DAY     = os.environ.get("DEBUG_FORCE_FULL_DAY", "true").lower() == "true"
DEBUG_PREVIEW_LEN        = int(os.environ.get("DEBUG_PREVIEW_LEN", "65"))
SAVE_BEDROCK_LOGS        = os.environ.get("SAVE_BEDROCK_LOGS", "false").lower() == "true"
BEDROCK_LOGS_S3_BUCKET   = os.environ.get("BEDROCK_LOGS_S3_BUCKET", "")
BEDROCK_LOGS_S3_PREFIX   = os.environ.get("BEDROCK_LOGS_S3_PREFIX", "bedrock/digests/")

# =========================
# Environment Validation
# =========================
def validate_environment():
    required_vars = ["DDB_TABLE", "AGENT_ID", "AGENT_ALIAS_ID", "TEAMS_WEBHOOK"]
    missing = [var for var in required_vars if not os.environ.get(var)]
    if missing:
        raise ValueError(f"Missing required environment variables: {missing}")
    
    webhook_url = os.environ["TEAMS_WEBHOOK"]
    if not webhook_url.startswith("https://"):
        raise ValueError("TEAMS_WEBHOOK must be HTTPS URL")

validate_environment()

# =========================
# AWS Clients
# =========================
ddb        = boto3.resource("dynamodb")
table      = ddb.Table(DDB_TABLE)
agent_rt   = boto3.client("bedrock-agent-runtime")
s3         = boto3.client("s3") if SAVE_BEDROCK_LOGS and BEDROCK_LOGS_S3_BUCKET else None
cloudwatch = boto3.client('cloudwatch')

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

def put_custom_metric(metric_name: str, value: float, unit: str = 'Count'):
    try:
        cloudwatch.put_metric_data(
            Namespace='SRE/AlertDigest',
            MetricData=[
                {
                    'MetricName': metric_name,
                    'Value': value,
                    'Unit': unit,
                    'Timestamp': now_utc()
                }
            ]
        )
    except Exception as e:
        print(f"METRIC_ERROR: {e}")

def to_ist_day_bounds(day_ist_str: Optional[str]) -> (dt.datetime, dt.datetime, str):
    """
    Returns (start_utc, end_utc, window_label_ist) for a full IST day.
    """
    now = now_utc().astimezone(IST)
    if not day_ist_str or day_ist_str.lower() == "today":
        day_date = now.date()
    elif day_ist_str.lower() == "yesterday":
        day_date = (now - dt.timedelta(days=1)).date()
    else:
        try:
            y, m, d = map(int, day_ist_str.split("-"))
            day_date = dt.date(y, m, d)
        except Exception:
            print(f"Invalid date format: {day_ist_str}, using today")
            day_date = now.date()

    start_ist = dt.datetime(day_date.year, day_date.month, day_date.day, 0, 0, 0, tzinfo=IST)
    end_ist_full = start_ist + dt.timedelta(days=1)

    if DEBUG_MODE and DEBUG_FORCE_FULL_DAY:
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
# Robust Timestamp Coercion - FIXED
# =========================
def _parse_messy_created_str(s: str) -> Optional[dt.datetime]:
    """
    Accepts '2025-08-2316:56:33.3692' or '2025-08-23T16:56:33.3692' and coerces to UTC dt.
    """
    if not s or not isinstance(s, str):
        return None
    
    s = s.strip().replace(" ", "")
    
    # Fix missing T separator
    if "T" not in s and len(s) >= 15 and s[4] == "-" and s[7] == "-":
        # Find where time portion starts (look for digits after date)
        for i in range(10, len(s)):
            if s[i].isdigit():
                s = s[:i] + "T" + s[i:]
                break
    
    # Remove timezone suffixes
    s = re.sub(r"(IST|UTC)$", "", s, flags=re.I).strip()
    
    # Add Z if no timezone info
    if not re.search(r"[zZ]|[+\-]\d\d:\d\d$", s):
        s = s + "Z"
    
    try:
        return parse_dt(s)
    except Exception as e:
        print(f"Failed to parse timestamp '{s}': {e}")
        return None

def coerce_item_ts_utc(it: Dict) -> Optional[dt.datetime]:
    """Extract timestamp from DynamoDB item - handles both created string and receivedAt epoch."""
    
    # First try 'created' field
    created = it.get("created")
    if isinstance(created, str) and created.strip():
        dtc = _parse_messy_created_str(created)
        if dtc:
            return dtc
    
    # Fallback to 'receivedAt' epoch seconds
    recv = it.get("receivedAt")
    if recv is not None:
        try:
            if isinstance(recv, (int, float)):
                return dt.datetime.fromtimestamp(int(recv), tz=dt.timezone.utc)
            if isinstance(recv, str) and recv.isdigit():
                return dt.datetime.fromtimestamp(int(recv), tz=dt.timezone.utc)
        except (ValueError, OSError) as e:
            print(f"Invalid receivedAt timestamp {recv}: {e}")
    
    print(f"No valid timestamp found in item: {it.keys()}")
    return None

# =========================
# DynamoDB Fetch - FIXED for your table structure
# =========================
def fetch_items_for_window(start_utc: dt.datetime, end_utc: dt.datetime) -> List[Dict]:
    """
    Full table scan + local filtering. Fixed to handle your table structure.
    """
    items: List[Dict] = []
    
    try:
        print(f"Scanning DDB table for window: {start_utc} to {end_utc}")
        
        resp = table.scan(Limit=MAX_ITEMS)
        items.extend(resp.get("Items", []))
        
        while "LastEvaluatedKey" in resp and len(items) < MAX_ITEMS:
            resp = table.scan(
                ExclusiveStartKey=resp["LastEvaluatedKey"], 
                Limit=MAX_ITEMS - len(items)
            )
            items.extend(resp.get("Items", []))
            
        print(f"Scanned {len(items)} total items from DDB")
        
    except Exception as e:
        print(f"DDB_SCAN_ERROR: {e}")
        raise

    kept = []
    debug_items = []
    
    for it in items:
        # Extract message ID - handle the typo in your table (messageld vs messageId)
        mid = (it.get("messageId") or 
               it.get("messageld") or  # Handle your table's typo
               it.get("id") or 
               it.get("incidentKey") or 
               "unknown")
        
        # Get timestamp
        ts = coerce_item_ts_utc(it)
        if ts is None:
            debug_items.append(f"No timestamp: {mid}")
            continue
            
        # Get body content
        body = it.get("body")
        if not isinstance(body, str) or not body.strip():
            debug_items.append(f"No body: {mid} @ {ts}")
            continue
        
        # Check if in time window
        if start_utc <= ts <= end_utc:
            kept.append({
                "messageId": mid,
                "created": iso_z(ts),
                "body": body.strip()
            })
            debug_items.append(f"KEPT: {mid} @ {ts}")
        else:
            debug_items.append(f"Out of window: {mid} @ {ts}")
    
    if DEBUG_MODE:
        print("DEBUG_ITEMS (first 10):")
        for line in debug_items[:10]:
            print(f"  {line}")
        if len(debug_items) > 10:
            print(f"  ... and {len(debug_items) - 10} more")
    
    print(f"Kept {len(kept)} items in window {start_utc} to {end_utc}")
    return kept

def normalize_body_for_bedrock(bodies: List[str]) -> List[str]:
    out = []
    for b in bodies:
        # Clean up HTML and normalize whitespace
        bb = re.sub(r"<[^>]+>", " ", b or "")  # Remove HTML tags
        bb = re.sub(r"\s+", " ", bb).strip()   # Normalize whitespace
        if bb:
            out.append(bb)
    return out

# =========================
# Bedrock Agent Call - With Error Handling
# =========================
def call_bedrock_agent(bodies: List[str], window_label_ist: str, session_id: str, chunk_idx: int) -> str:
    payload = {
        "instruction": (
            f"Create an SRE manager digest for this window (IST): {window_label_ist}. "
            f"Use ONLY the text content of each alert below; ignore any other fields. "
            f"Output clean Markdown with emoji sections. Group similar alerts together."
        ),
        "items": [{"body": b} for b in bodies]
    }

    try:
        resp = agent_rt.invoke_agent(
            agentId=AGENT_ID,
            agentAliasId=AGENT_ALIAS_ID,
            sessionId=session_id,
            inputText=json.dumps(payload),
        )
    except Exception as e:
        print(f"BEDROCK_AGENT_ERROR chunk-{chunk_idx}: {e}")
        return f"⚠️ Failed to process chunk {chunk_idx + 1}: {str(e)}"

    result_text = ""
    try:
        if "completion" in resp and isinstance(resp["completion"], list):
            for ev in resp["completion"]:
                if isinstance(ev, dict) and "data" in ev:
                    result_text += ev["data"]
        elif "outputText" in resp:
            result_text = resp["outputText"]
        elif "message" in resp:
            result_text = resp["message"].get("content", "")
    except Exception as e:
        print(f"BEDROCK_RESPONSE_PARSE_ERROR: {e}")
        return f"⚠️ Failed to parse response for chunk {chunk_idx + 1}"

    result_text = (result_text or "").strip()

    # Optional: Save Bedrock logs to S3
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
# Teams Webhook - With Error Handling
# =========================
def post_markdown_to_teams(markdown_text: str) -> bool:
    import urllib.request
    
    try:
        # Truncate if too long (Teams has limits)
        if len(markdown_text) > 28000:
            markdown_text = markdown_text[:27500] + "\n\n_[Content truncated due to length]_"
            
        body = json.dumps({"text": markdown_text}).encode("utf-8")
        req = urllib.request.Request(
            TEAMS_WEBHOOK,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status >= 400:
                raise Exception(f"Teams webhook failed: {resp.status}")
            print(f"Teams message posted successfully (status: {resp.status})")
            return True
            
    except Exception as e:
        print(f"TEAMS_POST_ERROR: {e}")
        return False

# =========================
# Lambda Handler - ENHANCED
# =========================
def lambda_handler(event, context):
    """
    Enhanced whole-day IST digest with better error handling and debugging.
    """
    
    # Validate event structure
    if event and not isinstance(event, dict):
        return {"error": "Event must be a dictionary", "ok": False}

    try:
        # Build time window
        override_start = (event or {}).get("override_start_iso")
        override_end   = (event or {}).get("override_end_iso")
        
        if override_start and override_end:
            try:
                start_utc = parse_dt(override_start)
                end_utc   = parse_dt(override_end)
                if start_utc >= end_utc:
                    return {"error": "override_start_iso must be before override_end_iso", "ok": False}
                window_label_ist = f"{start_utc.astimezone(IST).strftime('%d %b %Y %H:%M')} – {end_utc.astimezone(IST).strftime('%H:%M')} IST"
            except Exception as e:
                return {"error": f"Invalid date format in overrides: {e}", "ok": False}
        else:
            day_ist_str = (event or {}).get("day_ist")
            start_utc, end_utc, window_label_ist = to_ist_day_bounds(day_ist_str)

        print(f"Processing window: {window_label_ist}")
        print(f"UTC range: {start_utc} to {end_utc}")

        # Fetch and filter by window
        items = fetch_items_for_window(start_utc, end_utc)

        # Metrics
        put_custom_metric('ItemsFetched', len(items))

        # Audit tracking
        audit = {
            "window": window_label_ist,
            "debug_mode": DEBUG_MODE,
            "utc_start": iso_z(start_utc),
            "utc_end": iso_z(end_utc),
            "fetched_count": len(items),
            "with_body_count": 0,
            "deduped_unique_bodies": 0,
            "forwarded_ids": [],
            "skipped_no_body": [],
            "dedup_groups": {},
            "debug_previews": []
        }

        if not items:
            md = f"**SRE Digest – {window_label_ist}**\n\n_No alert bodies found in this window._"
            if DEBUG_MODE:
                md += f"\n\n**🧪 Debug Info**\n"
                md += f"• Window forced full-day: {DEBUG_MODE and DEBUG_FORCE_FULL_DAY}\n"
                md += f"• UTC range: `{start_utc}` to `{end_utc}`\n"
                md += f"• Total items scanned: {len(items)}"
            
            success = post_markdown_to_teams(md)
            return {
                "ok": True, 
                "posted": success, 
                "window": window_label_ist, 
                "items_fetched": 0, 
                "debug": DEBUG_MODE
            }

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
        put_custom_metric('UniqueAlerts', audit["deduped_unique_bodies"])

        # Prepare bodies for Bedrock
        bodies_all = []
        for h, g in by_hash.items():
            bodies_all.append(g["body"])
            if DEBUG_MODE:
                pv = preview(g["body"], DEBUG_PREVIEW_LEN)
                ids = ", ".join(g["ids"][:min(5, AUDIT_MAX_IDS)])
                audit["dedup_groups"][h] = {
                    "count": len(g["ids"]), 
                    "sample_ids": g["ids"][:min(5, AUDIT_MAX_IDS)], 
                    "preview": pv
                }
                audit["debug_previews"].append(
                    f"• [{len(g['ids'])}×] {h}: "{pv}" IDs: {ids}{'…' if len(g['ids']) > 5 else ''}"
                )

        bodies_all = normalize_body_for_bedrock(bodies_all)

        # Track covered IDs
        covered_ids = []
        for g in by_hash.values():
            covered_ids.extend(g["ids"])
        audit["forwarded_ids"] = covered_ids[:AUDIT_MAX_IDS]

        # Invoke Bedrock in chunks
        session_id = "sre-digest-" + now_utc().strftime("%Y%m%d%H%M%S")
        digests: List[str] = []
        
        for i in range(0, len(bodies_all), MAX_BODIES_PER_CALL):
            chunk = bodies_all[i:i + MAX_BODIES_PER_CALL]
            md = call_bedrock_agent(chunk, window_label_ist, session_id, i // MAX_BODIES_PER_CALL)
            if md:
                digests.append(md)

        final_md = "\n\n---\n\n".join(digests).strip()
        if not final_md:
            final_md = f"**SRE Digest – {window_label_ist}**\n\n_No actionable content generated from {len(bodies_all)} alert bodies._"

        # Add audit summary if enabled
        if AUDIT_SUMMARY_IN_TEAMS:
            def join_ids(lst):
                return ", ".join(str(x) for x in lst[:AUDIT_MAX_IDS]) + ("..." if len(lst) > AUDIT_MAX_IDS else "")
            
            final_md += "\n\n---\n\n"
            final_md += f"**🧾 Intake Summary**\n"
            final_md += f"- Window: {audit['window']} | Debug: {'on' if DEBUG_MODE else 'off'}\n"
            final_md += f"- Fetched: {audit['fetched_count']} | With body: {audit['with_body_count']} | Unique bodies: {audit['deduped_unique_bodies']}\n"
            if audit["skipped_no_body"]:
                final_md += f"- Skipped (no body): {join_ids(audit['skipped_no_body'])}\n"
            if audit["forwarded_ids"]:
                final_md += f"- Covered IDs: {join_ids(audit['forwarded_ids'])}\n"

        # Add debug section
        if DEBUG_MODE and audit["debug_previews"]:
            final_md += "\n\n**🧪 Debug (processed bodies)**\n"
            dbg_lines = audit["debug_previews"][:AUDIT_MAX_IDS]
            final_md += "\n".join(dbg_lines)
            final_md += f"\n\n_UTC range: `{audit['utc_start']}` to `{audit['utc_end']}`_"

        # Post to Teams
        success = post_markdown_to_teams(final_md)

        # Return result
        ret = {
            "ok": True,
            "posted": success,
            "window": window_label_ist,
            "items_fetched": audit["fetched_count"],
            "items_with_body": audit["with_body_count"],
            "unique_bodies_forwarded": audit["deduped_unique_bodies"],
            "forwarded_ids_sample": audit["forwarded_ids"],
            "debug_mode": DEBUG_MODE,
            "audit": audit if DEBUG_MODE else None
        }
        
        print("AUDIT:", json.dumps(audit, default=str)[:8000])
        return ret

    except Exception as e:
        error_msg = f"LAMBDA_ERROR: {str(e)}"
        print(error_msg)
        
        # Try to send error to Teams
        try:
            error_md = f"**❌ SRE Digest Error**\n\n```\n{error_msg}\n```\n\n_Check CloudWatch logs for details._"
            post_markdown_to_teams(error_md)
        except:
            pass
            
        return {"error": error_msg, "ok": False}
