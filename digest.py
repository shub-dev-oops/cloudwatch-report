import os
import json
import boto3
import datetime
import urllib3
from decimal import Decimal
from dateutil.tz import tzutc

# DynamoDB + Bedrock clients
table    = boto3.resource("dynamodb").Table(os.environ["TABLE"])
bedrock  = boto3.client("bedrock-agent-runtime")

# HTTP client (no extra deps)
http     = urllib3.PoolManager()

# Env vars
TEAMS_URL = os.environ["TEAMS_URL"]
AGENT_ID  = os.environ["AGENT_ID"]

def decimal_to_native(obj):
    """Helper: convert Decimal to int/float for JSON."""
    if isinstance(obj, Decimal):
        if obj == obj.to_integral_value():
            return int(obj)
        return float(obj)
    raise TypeError(f"Unserializable object {obj} ({type(obj)})")

def lambda_handler(event, context):
    # 1) Determine time window
    now   = int(datetime.datetime.utcnow().timestamp())
    since = now - 600  # last 10 minutes

    # 2) Fetch raw items from DynamoDB
    resp = table.scan(
        FilterExpression="SK > :t",
        ExpressionAttributeValues={":t": since}
    )
    raw_items = resp.get("Items", [])

    if not raw_items:
        return {"msg": "no alerts in window"}

    # 3) Extract payloads and strip Decimals
    alerts = json.loads(
        json.dumps([item["payload"] for item in raw_items],
                   default=decimal_to_native)
    )

    # 4) Prepare Bedrock input
    bedrock_input = {
        "input": {
            "time_window": "last 10 minutes",
            "alerts": alerts
        }
    }

    # 5) Invoke the Bedrock Agent
    summary = bedrock.invoke_agent(
        agentId=AGENT_ID,
        input=json.dumps(bedrock_input),
        enableTrace=False
    )["completion"]

    # 6) POST summary to Teams
    resp = http.request(
        "POST",
        TEAMS_URL,
        body=json.dumps({"text": summary}),
        headers={"Content-Type": "application/json"},
        timeout=3.0
    )
    if resp.status != 200:
        raise Exception(f"Teams webhook failed: {resp.status}")

    # 7) Return success
    return {"alerts_summarized": len(alerts)}
