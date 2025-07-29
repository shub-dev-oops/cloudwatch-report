import os
import json
import uuid
import boto3
import datetime
import urllib3
from decimal import Decimal
from dateutil.tz import tzutc

# Clients and helpers at top level
table    = boto3.resource("dynamodb").Table(os.environ["TABLE"])
bedrock  = boto3.client("bedrock-agent-runtime")
http     = urllib3.PoolManager()

TEAMS_URL      = os.environ["TEAMS_URL"]
AGENT_ID       = os.environ["AGENT_ID"]
AGENT_ALIAS_ID = os.environ["AGENT_ALIAS_ID"]

def decimal_to_native(obj):
    if isinstance(obj, Decimal):
        if obj == obj.to_integral_value():
            return int(obj)
        return float(obj)
    raise TypeError(f"Unserializable object {obj} ({type(obj)})")

def lambda_handler(event, context):
    # 1) Compute the time window cutoff
    now = int(datetime.datetime.utcnow().timestamp())
    since = now - 600  # last 10 minutes

    # 2) Query DynamoDB for recent alarms
    resp = table.scan(
        FilterExpression="SK > :t",
        ExpressionAttributeValues={":t": since}
    )
    raw_items = resp.get("Items", [])

    if not raw_items:
        # <-- This return is inside lambda_handler!
        return {"msg": "no alerts in window"}

    # 3) Strip Decimal types
    alerts = json.loads(
        json.dumps([item["payload"] for item in raw_items],
                   default=decimal_to_native)
    )

    # 4) Build the prompt for Bedrock
    bedrock_input = {
        "time_window": "last 10 minutes",
        "alerts": alerts
    }
    prompt = json.dumps(bedrock_input)

    # 5) Invoke the agent
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
        completion += chunk.get("bytes", b"").decode()

    # 7) Post to Teams
    resp = http.request(
        "POST",
        TEAMS_URL,
        body=json.dumps({"text": completion}),
        headers={"Content-Type": "application/json"},
        timeout=4.0
    )
    if resp.status != 200:
        raise Exception(f"Teams webhook failed with status {resp.status}")

    # Final return inside lambda_handler
    return {"alerts_summarized": len(alerts)}
