# app.py
import os, json, time, re, logging
import boto3

# --- Settings (env) ---
TABLE = os.environ["DDB_TABLE"]
DEBUG_JSON = os.getenv("DEBUG_JSON", "true").lower() == "true"

# Optional: JSON map of product keywords (lowercase) to product name
# e.g. {"govmeetings":["govmeetings","open cities","swagit"], "onemeeting":["onemeeting"]}
PRODUCT_KEYWORDS = json.loads(os.getenv("PRODUCT_KEYWORDS_JSON", "{}"))

ddb = boto3.client("dynamodb")

log = logging.getLogger()
log.setLevel(logging.INFO)

# ---- utility ---------------------------------------------------------------

def _first_match(patterns, text, flags=re.I):
    if isinstance(patterns, str):
        patterns = [patterns]
    for p in patterns:
        m = re.search(p, text, flags)
        if m:
            return m
    return None

def detect_source(text):
    t = text.lower()
    if "pagerduty" in t or re.search(r"\bpd\b", t):
        return "pagerduty"
    if "elastic" in t or "kibana" in t or "workflows" in t:
        return "elastic"
    if "pingdom" in t or "my.pingdom.com" in t:
        return "pingdom"
    return "unknown"

def detect_severity(text):
    # Prefer explicit sev, else critical/warning, else guess by keywords
    m = _first_match(r"\bsev(?:erity)?\s*[:=]?\s*([0-3])\b", text)
    if m: return f"sev{m.group(1)}"
    if re.search(r"\bcritical|crit\b", text, re.I): return "crit"
    if re.search(r"\bhigh\b", text, re.I): return "sev2"
    if re.search(r"\bwarning|warn\b", text, re.I): return "warn"
    if re.search(r"\blower\b", text, re.I): return "sev3"
    return "unknown"

def detect_status(text):
    if re.search(r"\bresolved\b", text, re.I): return "resolved"
    if re.search(r"\back(?:nowledged)?\b", text, re.I): return "ack"
    if re.search(r"\bopen\b", text, re.I): return "open"
    if re.search(r"\brecovered\b", text, re.I): return "recovered"
    return "unknown"

def detect_env(text):
    if re.search(r"\bprod(?:uction)?\b", text, re.I): return "prod"
    if re.search(r"\bstage|staging|preprod\b", text, re.I): return "stage"
    if re.search(r"\bdev(elopment)?\b", text, re.I): return "dev"
    return "unknown"

def detect_incident_key(text, fallback_id):
    # PagerDuty incident numbers / IDs
    m = _first_match([r"\b(?:INCIDENT|#)\s*(\d{4,})\b",
                      r"\bincident[:\s]*([A-Z0-9-]{6,})\b"], text)
    if m: return m.group(1)

    # Elastic rule/alert IDs
    m = _first_match([r"rule\.id[^\w-]*([a-z0-9-]{6,})",
                      r"alert(?:InstanceId)?[^\w-]*([a-z0-9-]{6,})"], text)
    if m: return m.group(1)

    # Pingdom check IDs / URLs
    m = _first_match([r"\bcheck(?:\s*id)?\s*[:=]\s*(\d{5,})\b",
                      r"my\.pingdom\.com[^ ]*check=(\d{5,})"], text)
    if m: return m.group(1)

    # Elastic APM / monitor IDs
    m = _first_match(r"\b(apm|synthetics)[-: ]([A-Za-z0-9_-]{4,})", text)
    if m: return f"{m.group(1)}-{m.group(2)}"

    return fallback_id

def detect_service(text):
    # Grab common "Service:" or "Application:" fields
    m = _first_match([r"\bservice\s*[:]\s*([^\n|]+)",
                      r"\bapplication\s*[:]\s*([^\n|]+)"], text)
    if m: return m.group(1).strip()[:120]
    # Fallback: component-like tokens
    m = _first_match(r"\b(component|host|dataset)\s*[:]\s*([^\n|]+)", text)
    if m: return m.group(2).strip()[:120]
    return "unknown"

def extract_links(text):
    return re.findall(r"https?://[^\s\)>]+", text)

def detect_product(text):
    t = text.lower()
    # Use configured keyword map first
    for product, keywords in PRODUCT_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in t:
                return product
    # Heuristics based on your channels/messages
    if re.search(r"\bgov\s*meetings|\bgovmeetings\b|\bopen\s*cities\b", t): return "govmeetings"
    if "swagit" in t: return "govmeetings-swagit"
    if "onemeeting" in t: return "onemeeting"
    return "unknown"

def normalize_from_flow(body: dict) -> dict:
    # Flow POST body we asked you to send
    message_id = body.get("id") or body.get("messageId") or f"m-{int(time.time()*1000)}"
    created    = body.get("createdDateTime") or "-"
    from_name  = body.get("fromDisplay") or body.get("from") or "-"
    # body/body/content may contain HTML; Flow gives plain too — we keep what we got
    text       = (body.get("text") or body.get("html") or "").strip()
    text_short = text[:3800]

    product = detect_product(text)
    source  = detect_source(text)
    severity= detect_severity(text)
    status  = detect_status(text)
    env     = detect_env(text)
    service = detect_service(text)
    inc_key = detect_incident_key(text, message_id)
    links   = extract_links(text)

    # Debug JSON (single line) for CloudWatch
    if DEBUG_JSON:
        log.info(json.dumps({
            "kind": "parsed_message",
            "messageId": message_id,
            "product": product,
            "source": source,
            "severity": severity,
            "status": status,
            "env": env,
            "service": service,
            "incidentKey": inc_key,
            "links": links[:5],
            "from": from_name,
            "created": created
        }))

    # DynamoDB item (no channelId dependency)
    now = int(time.time())
    ttl_epoch = now + 48*3600
    item = {
        "messageId":   {"S": message_id},
        "incidentKey": {"S": inc_key},
        "product":     {"S": product},
        "source":      {"S": source},
        "severity":    {"S": severity},
        "status":      {"S": status},
        "environment": {"S": env},
        "service":     {"S": service},
        "body":        {"S": text_short},
        "fromDisplay": {"S": from_name},
        "created":     {"S": created},
        "receivedAt":  {"N": str(now)},
        "#ttl":        {"N": str(ttl_epoch)}  # placeholder key; will alias in UpdateExpression
    }
    return item, links

# ---- handler ---------------------------------------------------------------

def handler(event, ctx):
    # API Gateway HTTP API → Lambda proxy event
    # Power Automate HTTP action POSTs JSON body
    try:
        body = json.loads(event.get("body") or "{}")
    except Exception:
        return {"statusCode": 400, "body": "bad json"}

    item, links = normalize_from_flow(body)
    message_id = item["messageId"]["S"]

    # Idempotent upsert; alias reserved word 'ttl'
    ddb.update_item(
        TableName=TABLE,
        Key={"messageId": {"S": message_id}},
        UpdateExpression=(
            "SET #incidentKey=:ik, #product=:p, #source=:s, #severity=:sev, "
            "#status=:st, #environment=:env, #service=:svc, #body=:b, "
            "#fromDisplay=:fd, #created=:cr, #receivedAt=:ra, #ttl=:ttl"
        ),
        ExpressionAttributeValues={
            ":ik":  item["incidentKey"],
            ":p":   item["product"],
            ":s":   item["source"],
            ":sev": item["severity"],
            ":st":  item["status"],
            ":env": item["environment"],
            ":svc": item["service"],
            ":b":   item["body"],
            ":fd":  item["fromDisplay"],
            ":cr":  item["created"],
            ":ra":  item["receivedAt"],
            ":ttl": item["#ttl"],
        },
        ExpressionAttributeNames={
            "#incidentKey": "incidentKey",
            "#product": "product",
            "#source": "source",
            "#severity": "severity",
            "#status": "status",
            "#environment": "environment",
            "#service": "service",
            "#body": "body",
            "#fromDisplay": "fromDisplay",
            "#created": "created",
            "#receivedAt": "receivedAt",
            "#ttl": "ttl"
        }
    )

    # Optional: store first 3 links into a lightweight side attribute (no list types to keep it simple)
    if links:
        for i, url in enumerate(links[:3], start=1):
            ddb.update_item(
                TableName=TABLE,
                Key={"messageId": {"S": message_id}},
                UpdateExpression=f"SET link{i}=:u",
                ExpressionAttributeValues={":u": {"S": url[:500]}}
            )

    return {"statusCode": 202, "body": ""}
