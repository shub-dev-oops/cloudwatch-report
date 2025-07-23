import json, boto3, datetime, os

dynamodb = boto3.resource("dynamodb")
table    = dynamodb.Table(os.environ["TABLE"])

def lambda_handler(event, _):
    for rec in event["Records"]:
        msg  = json.loads(rec["Sns"]["Message"])
        now  = int(datetime.datetime.utcnow().timestamp())
        pk   = f"{msg['AlarmName']}#{msg['NewStateValue']}"
        table.put_item(Item={
            "PK"   : pk,
            "SK"   : now,
            "ttl"  : now + 900,
            "payload": msg
        })
    return {"status": "ok", "records": len(event["Records"])}
