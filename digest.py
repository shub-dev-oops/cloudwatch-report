import os
import json
import uuid
import boto3
import datetime
import urllib3
from decimal import Decimal
from dateutil.tz import tzutc

# AWS clients
table    = boto3.resource("dynamodb").Table(os.environ["TABLE"])
bedrock  = boto3.client("bedrock-agent-runtime")
http     = urllib3.PoolManager()

# Env vars
TEAMS_URL       = os.environ["TEAMS_URL"]
AGENT_ID        = os.environ["AGENT_ID"]
AGENT_ALIAS_ID  = os.environ["AGENT_ALIAS_ID"]

def decimal_to_native(obj):
    """Convert Decimal to int or float for JSON serialization."""
    if isinstance(obj, Decimal):
        if obj == obj.to_integral_value():
            return int(obj)
        return float(obj)
    raise TypeError(f"Unserializable object {obj} ({type(obj)})")

def lambda_handler(event, context):
    # 1) Compute time window
    now   = int(datetime.datetime.utcnow().timestamp())
    since = now - 600  # last 10 minutes
    resp = table.scan()
    items = resp.get("Items", [])
    
    print(f"Found {len(items)} items in DynamoDB:")
for it in items:
    print(json.dumps(it, indent=2))
    # 2) Fetch all items newer than 'since'
    resp = table.scan(
        FilterExpression="SK > :t",
        ExpressionAttributeValues={":t": since}
    )
    raw_items = resp.get("Items", [])

    if not raw_items:
        return {"msg": "no alerts in window"}

    # 3) Extract and clean payloads (strip Decimal)
    alerts = json.loads(
        json.dumps([item["payload"] for item in raw_items],
                   default=decimal_to_native)
    )

    # 4) Prepare Bedrock Agent input
    bedrock_input = {
        "time_window": "last 10 minutes",
        "alerts": alerts
    }
    prompt = json.dumps(bedrock_input)

    # 5) Invoke the agent correctly
    session_id = str(uuid.uuid4())
    response = bedrock.invoke_agent(
        agentId=AGENT_ID,
        agentAliasId=AGENT_ALIAS_ID,
        sessionId=session_id,
        inputText=prompt,
        enableTrace=False
    )

    # 6) Reconstruct the streamed completion
    completion = ""
    for event in response.get("completion", []):
        chunk = event.get("chunk", {})
        # 'bytes' is a base64-encoded chunk; decode it
        completion += chunk.get("bytes", b"").decode()

    # 7) Post summary to Teams
    teams_resp = http.request(
        "POST",
        TEAMS_URL,
        body=json.dumps({"text": completion}),
        headers={"Content-Type": "application/json"},
        timeout=4.0
    )
    if teams_resp.status != 200:
        raise Exception(f"Teams webhook failed: {teams_resp.status}")

    return {"alerts_summarized": len(alerts)}
