"""
SQS Ingest Lambda - API Gateway to SQS
Receives alerts from Teams Workflow via API Gateway and sends to SQS for processing.
"""
import json
import os
import time
import uuid
import boto3
import datetime as dt
import logging
import re

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
SQS_QUEUE_URL = os.environ["SQS_QUEUE_URL"]
DEBUG_JSON = os.getenv("DEBUG_JSON", "true").lower() == "true"

# AWS client
sqs = boto3.client("sqs")

# Alert detection/enrichment functions (from your existing collector)
def detect_source(text):
    """Detect the alert source system from text content"""
    t = text.lower()
    if "pagerduty" in t or re.search(r"\bpd\b", t):
        return "pagerduty"
    if "elastic" in t or "kibana" in t or "workflows" in t:
        return "elastic"
    if "pingdom" in t or "my.pingdom.com" in t:
        return "pingdom"
    if "datadog" in t:
        return "datadog"
    return "unknown"

def detect_severity(text):
    """Extract severity level from alert text"""
    # Check for explicit severity levels
    m = re.search(r"\bsev(?:erity)?\s*[:=]?\s*([0-3])\b", text, re.I)
    if m: 
        return f"sev{m.group(1)}"
    
    # Check for common severity keywords
    if re.search(r"\bcritical|crit\b", text, re.I): 
        return "critical"
    if re.search(r"\bhigh\b", text, re.I): 
        return "high"
    if re.search(r"\bwarning|warn\b", text, re.I): 
        return "warning"
    if re.search(r"\blow|info\b", text, re.I): 
        return "info"
    
    return "unknown"

def detect_status(text):
    """Detect alert status from text"""
    if re.search(r"\bresolved|resolve\b", text, re.I): 
        return "resolved"
    if re.search(r"\back(?:nowledged)?|ack\b", text, re.I): 
        return "acknowledged"
    if re.search(r"\bopen\b", text, re.I): 
        return "open"
    if re.search(r"\brecovered|recovery\b", text, re.I): 
        return "recovered"
    if re.search(r"\btriggered|trigger\b", text, re.I): 
        return "triggered"
    
    return "unknown"

def detect_environment(text):
    """Detect environment from alert text"""
    if re.search(r"\bprod(?:uction)?\b", text, re.I): 
        return "production"
    if re.search(r"\bstage|staging|preprod\b", text, re.I): 
        return "staging"
    if re.search(r"\bdev(?:elopment)?\b", text, re.I): 
        return "development"
    if re.search(r"\btest(?:ing)?\b", text, re.I): 
        return "testing"
    
    return "unknown"

def detect_product(text):
    """Detect product/service from alert text"""
    t = text.lower()
    
    # Your specific products
    if "govmeetings" in t or "open cities" in t:
        return "govmeetings"
    if "onemeeting" in t:
        return "onemeeting"
    if "swagit" in t:
        return "govmeetings-swagit"
    
    # Generic service detection
    service_match = re.search(r"\bservice\s*[:]\s*([^\n|,]+)", text, re.I)
    if service_match:
        return service_match.group(1).strip()[:50]
    
    return "unknown"

def extract_incident_key(text, fallback_id):
    """Extract incident/alert key from text"""
    # PagerDuty incident numbers
    m = re.search(r"\b(?:incident|#)\s*(\d{4,})\b", text, re.I)
    if m: 
        return m.group(1)
    
    # Elastic rule/alert IDs
    m = re.search(r"rule\.id[^\w-]*([a-z0-9-]{6,})", text, re.I)
    if m: 
        return m.group(1)
    
    # Pingdom check IDs
    m = re.search(r"\bcheck(?:\s*id)?\s*[:=]\s*(\d{5,})\b", text, re.I)
    if m: 
        return m.group(1)
    
    return fallback_id

def handler(event, context):
    """
    API Gateway Lambda handler that processes incoming alerts and sends to SQS.
    
    Expected event from Teams Workflow:
    {
        "messageId": "optional-id",
        "text": "Alert body content",
        "html": "HTML version if available", 
        "fromDisplay": "Alert source name",
        "createdDateTime": "ISO timestamp",
        "receivedAt": epoch_timestamp
    }
    """
    logger.info(f"Processing alert ingest request")
    
    try:
        # Parse API Gateway request body
        if isinstance(event.get("body"), str):
            body = json.loads(event["body"])
        else:
            body = event.get("body", {})
            
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in request body: {e}")
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Invalid JSON format"})
        }
    
    # Extract core alert data
    now = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)
    message_id = (
        body.get("messageId") or 
        body.get("id") or 
        str(uuid.uuid4())
    )
    
    # Get alert content (prefer text over HTML)
    alert_text = (
        body.get("text") or 
        body.get("html") or 
        body.get("body") or
        ""
    ).strip()
    
    if not alert_text:
        logger.warning(f"Empty alert body for messageId: {message_id}")
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Empty alert body"})
        }
    
    # Parse timestamp (prefer receivedAt, fallback to createdDateTime, then now)
    event_timestamp = now.isoformat().replace("+00:00", "Z")
    
    if received_at := body.get("receivedAt"):
        try:
            if isinstance(received_at, (int, float)):
                ts = dt.datetime.fromtimestamp(int(received_at), tz=dt.timezone.utc)
                event_timestamp = ts.isoformat().replace("+00:00", "Z")
        except Exception as e:
            logger.warning(f"Failed to parse receivedAt '{received_at}': {e}")
    
    elif created_dt := body.get("createdDateTime"):
        try:
            # Parse ISO timestamp
            ts = dt.datetime.fromisoformat(created_dt.replace('Z', '+00:00'))
            event_timestamp = ts.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception as e:
            logger.warning(f"Failed to parse createdDateTime '{created_dt}': {e}")
    
    # Enrich alert with metadata
    enriched_alert = {
        # Core identification
        "messageId": message_id,
        "incidentKey": extract_incident_key(alert_text, message_id),
        
        # Timestamps
        "event_ts_utc": event_timestamp,
        "ingestion_ts_utc": now.isoformat().replace("+00:00", "Z"),
        
        # Alert content
        "body": alert_text,
        "fromDisplay": body.get("fromDisplay", ""),
        "createdDateTime": body.get("createdDateTime", ""),
        
        # Enriched metadata
        "source": detect_source(alert_text),
        "severity": detect_severity(alert_text),
        "status": detect_status(alert_text),
        "environment": detect_environment(alert_text),
        "product": detect_product(alert_text),
        
        # Processing metadata
        "ingestion_source": "teams-workflow",
        "lambda_request_id": context.aws_request_id if context else "local-test",
        
        # Raw data for audit
        "raw_event": body
    }
    
    # Debug logging
    if DEBUG_JSON:
        debug_info = {
            "action": "alert_enriched",
            "messageId": message_id,
            "severity": enriched_alert["severity"],
            "product": enriched_alert["product"],
            "source": enriched_alert["source"],
            "environment": enriched_alert["environment"],
            "status": enriched_alert["status"],
            "body_length": len(alert_text),
            "body_preview": alert_text[:200]
        }
        logger.info(f"ENRICHED: {json.dumps(debug_info)}")
    
    # Send to SQS
    try:
        sqs_message_body = json.dumps(enriched_alert, ensure_ascii=False)
        
        # Add message attributes for filtering/routing
        message_attributes = {
            'severity': {
                'StringValue': enriched_alert['severity'],
                'DataType': 'String'
            },
            'product': {
                'StringValue': enriched_alert['product'],
                'DataType': 'String'
            },
            'source': {
                'StringValue': enriched_alert['source'],
                'DataType': 'String'
            },
            'environment': {
                'StringValue': enriched_alert['environment'],
                'DataType': 'String'
            }
        }
        
        # Send message to SQS
        response = sqs.send_message(
            QueueUrl=SQS_QUEUE_URL,
            MessageBody=sqs_message_body,
            MessageAttributes=message_attributes,
            MessageGroupId=f"{enriched_alert['product']}-{enriched_alert['environment']}" if SQS_QUEUE_URL.endswith('.fifo') else None,
            MessageDeduplicationId=f"{message_id}-{int(time.time())}" if SQS_QUEUE_URL.endswith('.fifo') else None
        )
        
        logger.info(f"Successfully sent alert {message_id} to SQS. MessageId: {response['MessageId']}")
        
        return {
            "statusCode": 202,
            "headers": {
                "Content-Type": "application/json",
                "X-Message-Id": message_id
            },
            "body": json.dumps({
                "status": "accepted",
                "messageId": message_id,
                "sqsMessageId": response['MessageId'],
                "severity": enriched_alert['severity'],
                "product": enriched_alert['product']
            })
        }
        
    except Exception as e:
        logger.error(f"Failed to send message to SQS: {e}")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "error": "Failed to process alert",
                "messageId": message_id,
                "details": str(e)
            })
        }

# Test handler for local development
if __name__ == "__main__":
    # Test event mimicking Teams Workflow
    test_event = {
        "body": json.dumps({
            "messageId": "test-123",
            "text": "CRITICAL: Production database connection failed. Service: govmeetings-api Environment: prod",
            "fromDisplay": "PagerDuty Alert",
            "createdDateTime": "2025-08-25T10:30:00Z",
            "receivedAt": int(time.time())
        })
    }
    
    class MockContext:
        aws_request_id = "test-request-123"
    
    result = handler(test_event, MockContext())
    print(json.dumps(result, indent=2))
