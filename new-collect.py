import os
import json
import time
import logging
import urllib.parse
import urllib.request
import boto3

log = logging.getLogger()
log.setLevel(logging.DEBUG)

SECRETS_ARN = os.environ["SECRET_ID"]
DDB_TABLE = os.environ["DDB_TABLE"]

sm = boto3.client("secretsmanager")
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
    if m:
        log.debug(f"Detected HTTP method from v2 event: {m}")
        return m
    # REST API (v1)
    m = event.get("httpMethod")
    log.debug(f"Detected HTTP method from v1 event: {m}")
    return m or "POST"

def get_query(event):
    qs = event.get("queryStringParameters") or {}
    log.debug(f"Query parameters: {qs}")
    return qs

def get_app_token():
    sec = get_secret()
    if _token_cache["value"] and _token_cache["exp"] > time.time() + 60:
        log.debug("Using cached token")
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
    _token_cache["exp"] = time.time() + int(data.get("expires_in", "3600")) - 60
    log.debug("Fetched new app token")
    return _token_cache["value"]

def graph_get_message(resource_path):
    token = get_app_token()
    url = "https://graph.microsoft.com/v1.0" + resource_path
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def normalize_message(msg):
    msg_id = msg.get("id", "")
    body = (msg.get("body") or {}).get("content") or ""
    created = msg.get("createdDateTime") or "-"
    frm = ((msg.get("from") or {}).get("user") or {}).get("displayName") or "-"
    incident_key = msg.get("replyToId") or msg_id
    return {
        "messageId": {"S": msg_id},
        "incidentKey": {"S": incident_key},
        "body": {"S": body[:3800]},
        "fromDisplay": {"S": frm},
        "created": {"S": created},
        "receivedAt": {"N": str(int(time.time()))},
        "ttl": {"N": str(int(time.time()) + 48 * 3600)}
    }

def respond(code=200, body="", ctype="text/plain"):
    log.debug(f"Responding with status {code}, Content-Type: {ctype}, body: {body[:100]}")
    return {"statusCode": code, "headers": {"Content-Type": ctype}, "body": body}

def handler(event, context):
    log.info(f"Received event: {json.dumps(event)[:1500]}")
    method = get_method(event)
    qs = get_query(event)
    vt = qs.get("validationToken")

    # Validation handshake — accept GET or POST if validationToken is present
    if vt:
        log.info(f"Validation token received: {vt}. Responding with 200 OK for validation handshake.")
        return respond(200, vt, "text/plain")

    if method.upper() == "POST":
        sec = get_secret()
        token_param = qs.get("token")
        log.debug(f"Token received in query: {token_param}")
        if token_param != sec.get("url_token"):
            log.warning(f"Forbidden: token mismatch (expected {sec.get('url_token')}, got {token_param})")
            return respond(403, "forbidden")
        try:
            body = json.loads(event.get("body") or "{}")
            notifications = body.get("value", [])
            log.info(f"Received {len(notifications)} notification(s)")
            if not notifications:
                return respond(202, "")
            for n in notifications:
                resource = n.get("resource")
                if not resource:
                    log.warning("Notification missing resource field, skipping")
                    continue
                log.debug(f"Fetching message for resource: {resource}")
                msg = graph_get_message(resource)
                ddb.put_item(TableName=DDB_TABLE, Item=normalize_message(msg))
                log.info(f"Stored message {msg.get('id')} in DynamoDB")
            return respond(202, "")
        except Exception as e:
            log.error(f"Error processing notifications: {e}", exc_info=True)
            return respond(500, f"Internal server error: {e}")
    else:
        log.warning(f"Method {method} not allowed")
        return respond(405, "method not allowed")
