import os, json, boto3, datetime, requests

table      = boto3.resource("dynamodb").Table(os.environ["TABLE"])
bedrock    = boto3.client("bedrock-agent-runtime")
TEAMS_URL  = os.environ["TEAMS_URL"]
AGENT_ID   = os.environ["AGENT_ID"]

def lambda_handler(event, _):
    now   = int(datetime.datetime.utcnow().timestamp())
    since = now - 600  # 10 minutes

    # DynamoDB query: SK > since (uses range key)
    resp = table.scan(
        FilterExpression="SK > :t",
        ExpressionAttributeValues={":t": since}
    )
    alerts = [item["payload"] for item in resp.get("Items", [])]

    if not alerts:
        return {"msg": "no alerts"}

    prompt_input = json.dumps({"time_window": "10min", "alerts": alerts})

    summary = bedrock.invoke_agent(
        agentId=AGENT_ID,
        input=prompt_input,
        enableTrace=False
    )["completion"]

    requests.post(TEAMS_URL, json={"text": summary}, timeout=4)
    return {"alerts": len(alerts)}
