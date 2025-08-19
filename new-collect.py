# app.py
import os, json, time, logging, urllib.parse, urllib.request
import boto3

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

SECRETS_ARN = os.environ["SECRET_ID"]
DDB_TABLE   = os.environ["DDB_TABLE"]

sm  = boto3.client("secretsmanager")
ddb = boto3.client("dynamodb")

_secret_cache = None
_token_cache = {"value": None, "exp": 0}

def get_secret():
    global _secret_cache
    if _secret_cache:
        return _secret_cache
    s = sm.get_secret_value(SecretId=SECRETS_ARN)["SecretString"]
    _secret_cache = json.loads(s)
    return _secret_cache

def get_method(event):
    # HTTP API v2
    m = (event.get("requestContext", {}).get("http", {}) or {}).get("method")
    if m: return m
    # REST API (v1)
    return event.get("httpMethod") or "POST"

def get_query(event):
    return event.get("queryStringParameters") or {}

def get_app_token():
    sec = get_secret()
    if _token_cache["value"] and _token_cache["exp"] > time.time() + 60:
        return _token_cache["value"]
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
    _token_cache["exp"]   = time.time() + int(data.get("expires_in", "3600")) - 60
    return _token_cache["value"]

def graph_get_message(resource_path):
    token = get_app_token()
    url = "https://graph.microsoft.com/v1.0" + resource_path
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def normalize_message(msg):
    msg_id  = msg.get("id", "")
    body    = (msg.get("body") or {}).get("content") or ""
    created = msg.get("createdDateTime") or "-"
    frm     = ((msg.get("from") or {}).get("user") or {}).get("displayName") or "-"
    incident_key = msg.get("replyToId") or msg_id
    return {
        "messageId":   {"S": msg_id},
        "incidentKey": {"S": incident_key},
        "body":        {"S": body[:3800]},
        "fromDisplay": {"S": frm},
        "created":     {"S": created},
        "receivedAt":  {"N": str(int(time.time()))},
        "ttl":         {"N": str(int(time.time()) + 48*3600)}
    }

def respond(code=200, body="", ctype="text/plain"):
    return {"statusCode": code, "headers": {"Content-Type": ctype}, "body": body}

def handler(event, context):
    log.info("event: %s", json.dumps(event)[:1500])
    method = get_method(event)
    qs = get_query(event)

    # 1) Graph validation handshake (GET ?validationToken=...)
    vt = qs.get("validationToken")
    if method.upper() == "GET" and vt:
        return respond(200, vt, "text/plain")

    # 2) Notifications (POST ...?token=<shared>)
    if method.upper() == "POST":
        sec = get_secret()
        if qs.get("token") != sec.get("url_token"):
            return respond(403, "forbidden")
        body = json.loads(event.get("body") or "{}")
        notifications = body.get("value", [])
        if not notifications:
            return respond(202, "")
        for n in notifications:
            resource = n.get("resource")
            if not resource:
                continue
            msg = graph_get_message(resource)
            ddb.put_item(TableName=DDB_TABLE, Item=normalize_message(msg))
        return respond(202, "")

    return respond(405, "method not allowed")
