# app.py
import os, json, time, logging, urllib.parse, urllib.request
import boto3

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

SECRETS_ARN = os.environ["SECRET_ID"]
DDB_TABLE   = os.environ["DDB_TABLE"]

sm  = boto3.client("secretsmanager")
ddb = boto3.client("dynamodb")

# Cache secrets & token in-memory for this container
_secret_cache = None
_token_cache = {"value": None, "exp": 0}

def get_secret():
    global _secret_cache
    if _secret_cache:
        return _secret_cache
    s = sm.get_secret_value(SecretId=SECRETS_ARN)["SecretString"]
    _secret_cache = json.loads(s)
    return _secret_cache

def get_app_token():
    """Client-credentials token for Graph; cached for ~50 min."""
    if _token_cache["value"] and _token_cache["exp"] > time.time() + 60:
        return _token_cache["value"]
    sec = get_secret()
    form = urllib.parse.urlencode({
        "client_id": sec["client_id"],
        "client_secret": sec["client_secret"],
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }).encode()
    url = f"https://login.microsoftonline.com/{sec['tenant_id']}/oauth2/v2.0/token"
    req = urllib.request.Request(url, data=form, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read())
    _token_cache["value"] = data["access_token"]
    # default lifetime ~3600s
    _token_cache["exp"] = time.time() + int(data.get("expires_in", "3600")) - 60
    return _token_cache["value"]

def graph_get_message(resource_path: str) -> dict:
    """Fetch full message JSON using the resource path from the notification."""
    token = get_app_token()
    url = "https://graph.microsoft.com/v1.0" + resource_path
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def normalize_message(msg: dict) -> dict:
    """Map Graph chatMessage to our DynamoDB shape (minimal; refine later)."""
    msg_id   = msg.get("id", "")
    body     = (msg.get("body") or {}).get("content") or ""
    created  = msg.get("createdDateTime") or "-"
    frm      = ((msg.get("from") or {}).get("user") or {}).get("displayName") or "-"
    # For dedupe/state: prefer explicit IDs per source; fallback to replyToId or msg id
    incident_key = msg.get("replyToId") or msg_id

    item = {
        "messageId":   {"S": msg_id},
        "incidentKey": {"S": incident_key},
        "body":        {"S": body[:3800]},  # keep item small
        "fromDisplay": {"S": frm},
        "created":     {"S": created},
        "receivedAt":  {"N": str(int(time.time()))},
        "ttl":         {"N": str(int(time.time()) + 48*3600)}
    }
    return item

def respond(status=200, body="", headers=None, ctype="text/plain"):
    return {
        "statusCode": status,
        "headers": {"Content-Type": ctype, **(headers or {})},
        "body": body,
    }

def handler(event, context):
    """
    Supports:
     - GET  with ?validationToken=...   (Graph handshake; must echo token)
     - POST notifications from Graph    (expects query ?token=<shared>)
    """
    log.info("event: %s", json.dumps(event)[:2000])

    http = (event.get("requestContext", {}) or {}).get("http", {})
    method = http.get("method", "POST")
    qs = event.get("queryStringParameters") or {}

    # 1) Graph validation handshake (no auth possible here; echo token immediately)
    if method == "GET" and "validationToken" in qs:
        vt = qs["validationToken"]
        log.info("Validation handshake OK")
        return respond(200, vt, ctype="text/plain")

    # 2) Basic shared-secret check on POSTs (our own query param)
    sec = get_secret()
    if method == "POST":
        if qs.get("token") != sec.get("url_token"):
            log.warning("Forbidden: bad token")
            return respond(403, "forbidden")

        # 3) Process notifications
        try:
            body = json.loads(event.get("body") or "{}")
            notifications = body.get("value", [])
        except Exception as e:
            log.exception("Bad body")
            return respond(400, "bad request")

        if not notifications:
            return respond(202, "")

        # If you later use includeResourceData=true, decrypt here instead of GET
        for n in notifications:
            resource = n.get("resource")  # like /teams/{tid}/channels/{cid}/messages/{mid}
            if not resource:
                continue
            msg = graph_get_message(resource)
            ddb.put_item(TableName=DDB_TABLE, Item=normalize_message(msg))

        return respond(202, "")

    # Fallback
    return respond(405, "method not allowed")
