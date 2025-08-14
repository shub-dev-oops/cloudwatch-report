import os, json, time, base64, urllib.parse
import boto3, urllib.request

SECRETS_ARN = os.environ["SECRET_ID"]
DDB_TABLE = os.environ["DDB_TABLE"]
sm = boto3.client("secretsmanager")
ddb = boto3.client("dynamodb")

_secret = None
def get_secret():
    global _secret
    if _secret: return _secret
    val = sm.get_secret_value(SecretId=SECRETS_ARN)["SecretString"]
    _secret = json.loads(val)
    return _secret

def get_app_token(tenant, client_id, client_secret):
    data = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default"
    }).encode()
    req = urllib.request.Request(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data=data, method="POST",
        headers={"Content-Type":"application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]

def graph_get(token, url):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())

def normalize(graph_msg):
    # Minimal normalizer: keep IDs + raw text; incidentKey is best-effort
    msg_id = graph_msg["id"]
    body = graph_msg.get("body", {}).get("content", "") or ""
    created = graph_msg.get("createdDateTime")
    from_user = (graph_msg.get("from", {}) or {}).get("user", {}) or {}
    display = from_user.get("displayName")
    # crude incidentKey fallback (you will refine later)
    incident_key = graph_msg.get("replyToId") or msg_id
    return {
        "messageId": {"S": msg_id},
        "incidentKey": {"S": incident_key},
        "body": {"S": body[:3800]},
        "fromDisplay": {"S": display or "-"},
        "created": {"S": created or "-"},
        "receivedAt": {"N": str(int(time.time()))},
        "ttl": {"N": str(int(time.time()) + 48*3600)}
    }

def handler(event, context):
    secret = get_secret()
    # 1) Graph validation handshake
    qs = (event.get("queryStringParameters") or {})
    if "validationToken" in qs:
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": qs["validationToken"]
        }
    # 2) Basic shared-secret check on URL
    tok = qs.get("token")
    if not tok or tok != secret.get("url_token"):
        return {"statusCode": 403, "body": "forbidden"}

    # 3) Normal notifications
    body = json.loads(event.get("body") or "{}")
    items = body.get("value", [])
    if not items:
        return {"statusCode": 202, "body": ""}

    token = get_app_token(secret["tenant_id"], secret["client_id"], secret["client_secret"])
    for n in items:
        # n["resource"] looks like: /teams/{tid}/channels/{cid}/messages/{mid}
        resource = n.get("resource")
        # lazy: call Graph to fetch full message
        url = "https://graph.microsoft.com/v1.0" + resource
        msg = graph_get(token, url)
        put = normalize(msg)
        ddb.put_item(TableName=DDB_TABLE, Item=put)

    return {"statusCode": 202, "body": ""}
