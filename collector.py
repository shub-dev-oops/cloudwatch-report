import json
from decimal import Decimal
import boto3
import datetime
import os

# DynamoDB setup
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["TABLE"])

def lambda_handler(event, context):
    for record in event["Records"]:
        # Parse SNS message; convert JSON floats to Decimal
        msg = json.loads(record["Sns"]["Message"], parse_float=Decimal)
        
        # Current timestamp for SK and TTL
        now = int(datetime.datetime.utcnow().timestamp())
        
        # Partition key: unique per alarmName + state
        pk = f"{msg.get('AlarmName')}#{msg.get('NewStateValue')}"
        
        # Write to DynamoDB with Decimal-safe payload
        table.put_item(Item={
            "PK": pk,
            "SK": now,
            "ttl": now + 900,  # 15-minute TTL
            "payload": msg
        })
        
    return {"status": "ok", "records": len(event["Records"])}
