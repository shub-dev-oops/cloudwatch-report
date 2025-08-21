import os
import json
import re
import datetime as dt
from typing import List, Dict

import boto3
from boto3.dynamodb.conditions import Attr

# ----------- ENV VARS -----------
DDB_TABLE             = os.environ["DDB_TABLE"]                 # e.g., "sre-alerts"
AGENT_ID              = os.environ["AGENT_ID"]                  # bedrock agent id
AGENT_ALIAS_ID        = os.environ["AGENT_ALIAS_ID"]            # bedrock agent alias id
TEAMS_WEBHOOK         = os.environ["TEAMS_WEBHOOK"]             # Teams Incoming Webhook URL
PARAM_LAST_RUN        = os.environ.get("PARAM_LAST_RUN", "/sre-digest/last_run_utc")
DEFAULT_LOOKBACK_MIN  = int(os.environ.get("DEFAULT_LOOKBACK_MIN", "60"))
MAX_ITEMS             = int(os.environ.get("MAX_ITEMS", "200")) # safety cap per run
MAX_BODIES_PER_CALL   = int(os.environ.get("MAX_BODIES_PER_CALL", "80")) # chunking for large volumes

# ----------- CLIENTS -----------
ddb        = boto3.resource("dynamodb")
table      = ddb.Table(DDB_TABLE)
ssm        = boto3.client("ssm")
agent_rt   = boto3.client("bedrock-agent-runtime")

IST = dt.timezone(dt.timedelta(hours=5, minutes=30))  # Asia/Kolkata


# ----------------- UTILITIES -----------------
def now_utc() -> dt.datetime:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc, microsecond=0)

def iso_z(ts: dt.datetime) -> str:
    """Return ISO8601 Z string."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def parse_dt(s: str) -> dt.datetime:
    """Parse basic ISO string with or without Z."""
    try:
        s = s.strip()
        if s.endswith("Z"):
            s = s[:-1]
            return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)
        # naive -> assume UTC
        return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)
    except Exception:
        return now_utc()

def to_ist_label(start_utc: dt.datetime, end_utc: dt.datetime) -> str:
    s_ist = start_utc.astimezone(IST)
    e_ist = end_utc.astimezone(IST)
    # e.g., "22 Aug 2025 09:00 – 10:00 IST"
    same_day = s_ist.date() == e_ist.date()
    if same_day:
        return f"{s_ist.strftime('%d %b %Y %H:%M')} – {e_ist.strftime('%H:%M')} IST"
    else:
        return f"{s_ist.strftime('%d %b %Y %H:%M')} – {e_ist.strftime('%d %b %Y %H:%M')} IST"


# ----------------- STATE (SSM) -----------------
def get_last_run_iso() -> str:
    try:
        r = ssm.get_parameter(Name=PARAM_LAST_RUN)
        return r["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        # default: look back DEFAULT_LOOKBACK_MIN minutes
        start = now_utc() - dt.timedelta(minutes=DEFAULT_LOOKBACK_MIN)
        return iso_z(start)

def set_last_run_iso(ts_iso: str) -> None:
    ssm.put_parameter(Name=PARAM_LAST_RUN, Value=ts_iso, Type="String", Overwrite=True)


# ----------------- DATA FETCH -----------------
def fetch_recent_items(start_iso: str, end_iso: str) -> List[Dict]:
    """
    MVP: Scan with FilterExpression on 'created' time string (ISO).
    For prod scale, create a GSI on 'created' (String) and Query it.
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

    # We only keep items that actually have a 'body'
    return [it for it in items if "body" in it and isinstance(it["body"], str) and it["body"].strip()]


def normalize_body_for_bedrock(bodies: List[str]) -> List[str]:
    """
    Optional pre-clean: trim, collapse whitespace. We do NOT parse fields—
    the Agent prompt handles HTML/body parsing exactly as requested.
    """
    out = []
    for b in bodies:
        # Trivial cleanup: unify whitespace, remove accidental nulls
        bb = re.sub(r"\s+", " ", b or "").strip()
        if bb:
            out.append(bb)
    return out


# ----------------- BEDROCK CALL -----------------
def call_bedrock_agent(bodies: List[str], window_label_ist: str) -> str:
    """
    Sends a single instruction + array of 'body' strings to the Bedrock Agent.
    Assumes the Agent's System Prompt is already configured to:
    - use only `body`,
    - output a Markdown digest with emoji sections,
    - no hallucinations.
    """
    # Keep payload compact; Agent prompt handles formatting.
    payload = {
        "instruction": f"Create an SRE manager digest for this window (IST): {window_label_ist}. "
                       f"Use ONLY the HTML body of each item below; ignore any other fields. "
                       f"Output clean Markdown with emoji sections as per your instructions.",
        "items": [{"body": b} for b in bodies]
    }

    # Bedrock Agent requires a sessionId
    session_id = "sre-digest-" + now_utc().strftime("%Y%m%d%H%M%S")

    # Invoke Agent (text input)
    resp = agent_rt.invoke_agent(
        agentId=AGENT_ID,
        agentAliasId=AGENT_ALIAS_ID,
        sessionId=session_id,
        inputText=json.dumps(payload),
    )

    # Collect streamed text if present; else try outputText
    result_text = ""
    # Some SDKs return a 'completion' event list; others expose a 'completion' stream iterator.
    # We try both patterns defensively.
    if "completion" in resp and isinstance(resp["completion"], list):
        for ev in resp["completion"]:
            if "data" in ev:
                result_text += ev["data"]
    elif "outputText" in resp:
        result_text = resp["outputText"]
    elif "message" in resp:
        # Fallback: some runtimes wrap it differently
        result_text = resp["message"].get("content", "")

    return (result_text or "").strip()


# ----------------- TEAMS -----------------
def post_markdown_to_teams(markdown_text: str) -> None:
    """
    Posts Markdown text to a Teams incoming webhook.
    Keep payload minimal; Teams processes 'text' as basic markdown.
    """
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


# ----------------- HANDLER -----------------
def lambda_handler(event, context):
    """
    EventBridge (cron hourly) friendly.
    Also supports manual override window:
      event = {
        "override_start_iso": "2025-08-21T13:00:00Z",
        "override_end_iso":   "2025-08-21T14:00:00Z"
      }
    """
    end_utc = now_utc()
    start_iso = None

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

    # Window label for digest header (IST)
    window_label_ist = to_ist_label(start_utc, end_utc)

    # Fetch items and extract bodies
    items = fetch_recent_items(iso_z(start_utc), iso_z(end_utc))
    if not items:
        # Nothing to do; still advance watermark
        set_last_run_iso(iso_z(end_utc))
        return {"ok": True, "message": "No items in window.", "window": window_label_ist}

    bodies = normalize_body_for_bedrock([it["body"] for it in items])

    # Chunk if too many bodies (to keep token use reasonable)
    digests: List[str] = []
    for i in range(0, len(bodies), MAX_BODIES_PER_CALL):
        chunk = bodies[i:i + MAX_BODIES_PER_CALL]
        md = call_bedrock_agent(chunk, window_label_ist)
        if md:
            digests.append(md)

    final_md = "\n\n---\n\n".join(digests).strip()

    if not final_md:
        # Failsafe minimal output so managers see *something* if agent had an issue
        final_md = f"**SRE Digest – {window_label_ist}**\n\n_No actionable items parsed from alert bodies in this window._"

    # Post to Teams
    post_markdown_to_teams(final_md)

    # Advance watermark
    set_last_run_iso(iso_z(end_utc))

    return {
        "ok": True,
        "posted": True,
        "window": window_label_ist,
        "items_processed": len(bodies)
    }
