import os, json, boto3, datetime, urllib3
from dateutil.tz import tzutc

# AWS clients
table      = boto3.resource("dynamodb").Table(os.environ["TABLE"])
bedrock    = boto3.client("bedrock-agent-runtime")

# HTTP client (no extra deps!)
http       = urllib3.PoolManager()

# Env vars
TEAMS_URL  = os.environ["TEAMS_URL"]
AGENT_ID   = os.environ["AGENT_ID"]




def lambda_handler(event, _):
    now   = int(datetime.datetime.utcnow().timestamp())
    since = now - 600  # 10 minutes
    # 1) Scan all items
    resp = table.scan()
    items = resp.get("Items", [])

    # 2) Log count and items
    print(f"Found {len(items)} items in DynamoDB:")
    for it in items:
        print(json.dumps(it, indent=2))

    # 3) Return count so the console shows something
    return {"found_items": len(items)}
    # 1) Fetch alerts from DynamoDB
    resp = table.scan(
        FilterExpression="SK > :t",
        ExpressionAttributeValues={":t": since}
    )
    alerts = [item["payload"] for item in resp.get("Items", [])]

    if not alerts:
        return {"msg": "no alerts in window"}

    # 2) Build the input for Bedrock
    payload = {
        "input": {
            "time_window": "last 10 minutes",
            "alerts": alerts
        }
    }

    # 3) Invoke the Bedrock Agent
    summary = bedrock.invoke_agent(
        agentId=AGENT_ID,
        input=json.dumps(payload),
        enableTrace=False
    )["completion"]

    # 4) POST to Teams via webhook
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
