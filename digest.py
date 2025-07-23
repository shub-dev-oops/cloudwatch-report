import os, json, boto3, datetime, urllib3
from decimal import Decimal
from dateutil.tz import tzutc

# DynamoDB + Bedrock clients
table    = boto3.resource("dynamodb").Table(os.environ["TABLE"])
bedrock  = boto3.client("bedrock-agent-runtime")

# HTTP client
http     = urllib3.PoolManager()

# Env vars
TEAMS_URL = os.environ["TEAMS_URL"]
AGENT_ID  = os.environ["AGENT_ID"]

# Helper to convert Decimal → int/float
def decimal_to_native(obj):
    if isinstance(obj, Decimal):
        # if whole number, cast to int; otherwise to float
        if obj == obj.to_integral_value():
            return int(obj)
        return float(obj)
    # Let the normal JSON encoder raise on other bad types
    raise TypeError(f"Unserializable object {obj} of type {type(obj)}")

def lambda_handler(event, _):
    now   = int(datetime.datetime.utcnow().timestamp())
    since = now - 600  # last 10 minutes

    # 1) Fetch raw items from DynamoDB
    resp = table.scan(
        FilterExpression="SK > :t",
        ExpressionAttributeValues={":t": since}
    )
    raw_items = resp.get("Items", [])

    if not raw_items:
        return {"msg": "no alerts in window"}

    # 2) Extract payloads and convert Decimals
    #    We dump & load with our helper to turn Decimals into ints/floats
    alerts = json.loads(
        json.dumps([item["payload"] for item in raw_items], default=decimal_to_native)
    )

    # 3) Build Bedrock input
    bedrock_input = {
        "input": {
            "time_window": "last 10 minutes",
            "alerts": alerts
        }
    }

    # 4) Invoke Bedrock Agent
    summary = bedrock.invoke_agent(
        agentId=AGENT_ID,
        input=json.dumps(bedrock_input),
        enableTrace=False
    )["completion"]

    # 5) POST to Teams
    resp = http.request(
        "POST",
        TEAMS_URL,
        body=json.dumps({"text": summary}),
        headers={"Content-Type": "application/json"},
        timeout=3.0
    )
    if resp.status != 200:
        raise Exception(f"Teams webhook failed with status {resp.status}")

    return {"alerts_summarized": len(alerts)}
