import boto3, os, json

table = boto3.resource("dynamodb").Table(os.environ["TABLE"])

# Plain scan with no FilterExpression
resp = table.scan()
items = resp.get("Items", [])

print(f"Found {len(items)} items in DynamoDB:")
for it in items:
    print(json.dumps(it, indent=2))
