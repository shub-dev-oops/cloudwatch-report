# app.py
import os, json, time, re
import boto3

TABLE = os.environ["DDB_TABLE"]
ddb = boto3.client("dynamodb")

def derive_incident_key(text: str, mid: str) -> str:
    # Try to pull PD/Elastic/Pingdom IDs; fall back to message id
    for pat in [
        r"(?:INCIDENT|#)\s*([0-9]{4,})",               # PD incident number
        r"rule\.id[^\w-]*([a-z0-9-]{6,})",             # Elastic rule id
        r"Pingdom.*check.*?(\d{5,})",                  # Pingdom check id
    ]:
        m = re.search(pat, text, re.I)
        if m: return m.group(1)
    return mid

def handler(event, ctx):
    # API Gateway HTTP API sends: headers, body (JSON), isBase64Encoded, etc.
    # 1) Simple API key protection is handled by API Gateway; no code needed here.
    body = json.loads(event.get("body") or "{}")

    # Expecting fields from Flow (see section 3)
    message_id = body.get("id") or body.get("messageId")
    if not message_id:
        return {"statusCode": 400, "body": "missing message id"}

    text = (body.get("text") or body.get("html") or "")[:3800]
    team_id = body.get("teamId", "-")
    channel_id = body.get("channelId", "-")
    created = body.get("createdDateTime") or "-"
    from_name = body.get("fromDisplay") or body.get("from") or "-"

    inc_key = body.get("incidentKey") or derive_incident_key(text, message_id)

    now = int(time.time())
    ttl = now + 48*3600

    # 2) Idempotent upsert (no duplicates if Flow retries)
    ddb.update_item(
        TableName=TABLE,
        Key={"messageId": {"S": message_id}},
        UpdateExpression="""
            SET teamId=:t, channelId=:c, body=:b, created=:cr, fromDisplay=:fd,
                incidentKey=:ik, receivedAt=:ra, ttl=:ttl
        """,
        ExpressionAttributeValues={
            ":t":{"S":team_id}, ":c":{"S":channel_id}, ":b":{"S":text},
            ":cr":{"S":created}, ":fd":{"S":from_name}, ":ik":{"S":inc_key},
            ":ra":{"N":str(now)}, ":ttl":{"N":str(ttl)}
        }
    )

    return {"statusCode": 202, "body": ""}
