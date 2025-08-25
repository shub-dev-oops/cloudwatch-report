# SQS-based Alert Management Architecture

## 🏗️ **Architecture Flow**
```
Teams Workflow → API Gateway → Lambda (sqs-ingest-lambda.py) → SQS → Lambda (sqs-s3-writer.py) → S3 (JSONL)
                                                                                                      ↓
Daily EventBridge → Lambda (new-digest.py) → Bedrock Agent → Teams
```

## 📦 **Components**

### 1. **SQS Ingest Lambda** (`sqs-ingest-lambda.py`)
- **Trigger**: API Gateway HTTP POST
- **Purpose**: Receives Teams webhook alerts, enriches metadata, sends to SQS
- **Features**: 
  - ✅ Alert enrichment (severity, product, environment detection)
  - ✅ Message deduplication for FIFO queues
  - ✅ Message attributes for filtering
  - ✅ Comprehensive error handling

### 2. **SQS to S3 Writer** (`sqs-s3-writer.py`)  
- **Trigger**: SQS messages (batch processing)
- **Purpose**: Processes SQS messages and writes partitioned JSONL to S3
- **Features**:
  - ✅ Date-based partitioning: `year=2025/month=08/day=25/`
  - ✅ Batch processing for efficiency
  - ✅ Optional gzip compression
  - ✅ Partial failure handling
  - ✅ Rich S3 metadata

### 3. **Daily Digest** (use existing `new-digest.py` with S3 source)
- **Trigger**: EventBridge daily schedule
- **Purpose**: Reads S3 data, generates digest via Bedrock, posts to Teams

## 🚀 **AWS Resources Setup**

### 1. SQS Queue (Simple Setup)
```bash
# Simple standard queue - easy to set up and manage
aws sqs create-queue \
  --queue-name sre-alerts-queue \
  --attributes '{
    "VisibilityTimeoutSeconds":"300",
    "MessageRetentionPeriod":"1209600",
    "ReceiveMessageWaitTimeSeconds":"20"
  }'
```

### 2. S3 Bucket with Lifecycle Policy
```bash
aws s3 mb s3://sre-alerts-data

# Lifecycle policy for cost optimization
aws s3api put-bucket-lifecycle-configuration \
  --bucket sre-alerts-data \
  --lifecycle-configuration file://s3-lifecycle.json
```

`s3-lifecycle.json`:
```json
{
  "Rules": [
    {
      "ID": "AlertsLifecycle",
      "Status": "Enabled",
      "Filter": {"Prefix": "alerts/"},
      "Transitions": [
        {
          "Days": 30,
          "StorageClass": "STANDARD_IA"
        },
        {
          "Days": 90,
          "StorageClass": "GLACIER"
        }
      ],
      "Expiration": {
        "Days": 2555
      }
    }
  ]
}
```

## ⚙️ **Environment Variables**

### SQS Ingest Lambda
```bash
SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789/sre-alerts-queue
DEBUG_JSON=true
```

### SQS S3 Writer Lambda
```bash
ALERTS_BUCKET=sre-alerts-data
COMPRESSION_ENABLED=false
MAX_BATCH_SIZE=100
BATCH_TIMEOUT_SECONDS=30
```

### Digest Lambda (update existing)
```bash
DATA_SOURCE=s3
ALERTS_BUCKET=sre-alerts-data
# ... existing Bedrock/Teams variables
```

## 🔧 **Lambda Configuration**

### 1. SQS Ingest Lambda
- **Runtime**: Python 3.11
- **Memory**: 512 MB
- **Timeout**: 30 seconds
- **Trigger**: API Gateway
- **IAM Permissions**: `sqs:SendMessage`

### 2. SQS S3 Writer Lambda  
- **Runtime**: Python 3.11
- **Memory**: 1024 MB (for batch processing)
- **Timeout**: 5 minutes
- **Trigger**: SQS (batch size: 10, window: 20 seconds)
- **IAM Permissions**: `s3:PutObject`, `sqs:ReceiveMessage`, `sqs:DeleteMessage`

### 3. API Gateway Setup
```bash
# Create REST API
aws apigateway create-rest-api --name sre-alerts-ingest

# Create resource and method
aws apigateway put-method \
  --rest-api-id <api-id> \
  --resource-id <resource-id> \
  --http-method POST \
  --authorization-type NONE

# Configure Lambda integration
aws apigateway put-integration \
  --rest-api-id <api-id> \
  --resource-id <resource-id> \
  --http-method POST \
  --type AWS_PROXY \
  --integration-http-method POST \
  --uri arn:aws:apigateway:region:lambda:path/2015-03-31/functions/arn:aws:lambda:region:account:function:sqs-ingest-lambda/invocations
```

## 📊 **S3 Data Structure**

### Partition Layout
```
s3://sre-alerts-data/
├── alerts/
│   ├── year=2025/
│   │   ├── month=08/
│   │   │   ├── day=24/
│   │   │   │   ├── alerts-1724505600-abc12345-001.jsonl
│   │   │   │   ├── alerts-1724505660-def67890-002.jsonl
│   │   │   │   └── ...
│   │   │   ├── day=25/
│   │   │   └── ...
│   │   └── ...
│   └── ...
```

### JSONL Record Format
```json
{
  "messageId": "alert-12345",
  "incidentKey": "PD-12345", 
  "event_ts_utc": "2025-08-25T10:30:00Z",
  "ingestion_ts_utc": "2025-08-25T10:30:05Z",
  "body": "CRITICAL: Database connection failed...",
  "fromDisplay": "PagerDuty",
  "source": "pagerduty",
  "severity": "critical",
  "status": "triggered",
  "environment": "production", 
  "product": "govmeetings",
  "ingestion_source": "teams-workflow",
  "lambda_request_id": "req-abc-123",
  "sqs_metadata": {
    "sqs_message_id": "sqs-msg-456",
    "receive_count": "1",
    "processed_at": "2025-08-25T10:30:06Z"
  },
  "raw_event": {...}
}
```

## 🔍 **Monitoring & Observability**

### CloudWatch Metrics to Monitor
- SQS: `ApproximateNumberOfMessages`, `NumberOfMessagesSent`, `NumberOfMessagesReceived`
- Lambda: `Duration`, `Errors`, `Throttles`, `ConcurrentExecutions`
- S3: `NumberOfObjects`, `BucketSizeBytes`

### CloudWatch Alarms
```bash
# SQS queue depth alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "SRE-Alerts-Queue-Depth" \
  --alarm-description "Alert when SQS queue has too many messages" \
  --metric-name ApproximateNumberOfMessages \
  --namespace AWS/SQS \
  --statistic Average \
  --period 300 \
  --threshold 100 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=QueueName,Value=sre-alerts-queue

# Lambda error rate alarm  
aws cloudwatch put-metric-alarm \
  --alarm-name "SRE-Alerts-Lambda-Errors" \
  --alarm-description "Alert on Lambda processing errors" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=FunctionName,Value=sqs-s3-writer
```

## 🧪 **Testing**

### Test SQS Ingest
```bash
curl -X POST https://your-api-gateway.execute-api.region.amazonaws.com/prod/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "messageId": "test-123",
    "text": "CRITICAL: Test alert from govmeetings production",
    "fromDisplay": "Test System",
    "receivedAt": 1692876600
  }'
```

### Test S3 Writer (send SQS message)
```bash
aws sqs send-message \
  --queue-url https://sqs.region.amazonaws.com/account/sre-alerts-queue \
  --message-body '{
    "messageId": "test-456", 
    "event_ts_utc": "2025-08-25T10:30:00Z",
    "body": "Test alert body",
    "severity": "warning"
  }'
```

## 💰 **Cost Optimization**

1. **SQS**: Use long polling (`ReceiveMessageWaitTimeSeconds=20`)
2. **S3**: Enable intelligent tiering and lifecycle policies  
3. **Lambda**: Right-size memory allocation based on actual usage
4. **Compression**: Enable gzip for large alert bodies

## 🔄 **Migration from DynamoDB**

1. **Phase 1**: Deploy SQS components alongside existing DynamoDB system
2. **Phase 2**: Route 10% traffic to SQS system, compare outputs
3. **Phase 3**: Full cutover, keep DynamoDB as backup for 30 days
4. **Phase 4**: Decommission DynamoDB resources

This architecture provides better scalability, cost efficiency, and operational simplicity compared to direct DynamoDB writes!
