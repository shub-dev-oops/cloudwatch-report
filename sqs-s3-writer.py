"""
SQS to S3 Writer Lambda
Processes SQS messages containing enriched alerts and writes them to S3 in partitioned JSONL format.
"""
import json
import os
import time
import uuid
import boto3
import datetime as dt
import logging
import gzip
from typing import List, Dict

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ALERTS_BUCKET = os.environ["ALERTS_BUCKET"]
COMPRESSION_ENABLED = os.getenv("COMPRESSION_ENABLED", "false").lower() == "true"
MAX_BATCH_SIZE = int(os.getenv("MAX_BATCH_SIZE", "100"))  # Records per S3 file
BATCH_TIMEOUT_SECONDS = int(os.getenv("BATCH_TIMEOUT_SECONDS", "30"))  # Max time to wait for batch

# AWS clients
s3 = boto3.client("s3")

def handler(event, context):
    """
    SQS-triggered Lambda handler that processes alert messages and writes to S3.
    
    Event structure from SQS:
    {
        "Records": [
            {
                "messageId": "sqs-message-id",
                "body": "{...enriched alert data...}",
                "attributes": {...},
                "messageAttributes": {...}
            }
        ]
    }
    """
    logger.info(f"Processing {len(event['Records'])} SQS messages")
    
    # Parse and group messages by date for partitioned storage
    alerts_by_date = {}
    failed_messages = []
    processed_count = 0
    
    for sqs_record in event['Records']:
        try:
            # Parse the enriched alert data from SQS message body
            alert_data = json.loads(sqs_record['body'])
            
            # Add SQS processing metadata
            alert_data['sqs_metadata'] = {
                'sqs_message_id': sqs_record['messageId'],
                'receipt_handle': sqs_record['receiptHandle'],
                'receive_count': sqs_record['attributes'].get('ApproximateReceiveCount', '1'),
                'first_receive_timestamp': sqs_record['attributes'].get('ApproximateFirstReceiveTimestamp'),
                'processed_at': dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat().replace("+00:00", "Z")
            }
            
            # Extract date for partitioning (use event_ts_utc)
            event_ts_str = alert_data.get('event_ts_utc')
            if event_ts_str:
                event_dt = dt.datetime.fromisoformat(event_ts_str.replace('Z', '+00:00'))
                date_key = event_dt.strftime('%Y-%m-%d')
            else:
                # Fallback to processing date if no event timestamp
                date_key = dt.datetime.utcnow().strftime('%Y-%m-%d')
                logger.warning(f"No event_ts_utc found for message {alert_data.get('messageId', 'unknown')}, using today's date")
            
            # Group by date
            if date_key not in alerts_by_date:
                alerts_by_date[date_key] = []
            alerts_by_date[date_key].append(alert_data)
            processed_count += 1
            
            logger.debug(f"Processed alert {alert_data.get('messageId', 'unknown')} for date {date_key}")
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse SQS message body as JSON: {e}")
            logger.error(f"Message body: {sqs_record['body']}")
            failed_messages.append(sqs_record['messageId'])
            
        except Exception as e:
            logger.error(f"Failed to process SQS message {sqs_record['messageId']}: {e}")
            failed_messages.append(sqs_record['messageId'])
    
    # Write grouped alerts to S3
    total_written = 0
    s3_files_created = []
    
    for date_key, alerts in alerts_by_date.items():
        try:
            files_created = write_alerts_to_s3(alerts, date_key)
            s3_files_created.extend(files_created)
            total_written += len(alerts)
            logger.info(f"Successfully wrote {len(alerts)} alerts for date {date_key} to {len(files_created)} S3 files")
            
        except Exception as e:
            logger.error(f"Failed to write alerts for date {date_key}: {e}")
            # Add these alert messageIds to failed list
            for alert in alerts:
                failed_messages.append(alert.get('messageId', 'unknown'))
    
    # Prepare response for SQS (partial batch failure handling)
    response = {
        "batchItemFailures": [
            {"itemIdentifier": msg_id} for msg_id in failed_messages
        ] if failed_messages else []
    }
    
    # Log summary
    logger.info(f"Processing summary: {processed_count} processed, {total_written} written to S3, "
               f"{len(failed_messages)} failed, {len(s3_files_created)} S3 files created")
    
    if failed_messages:
        logger.error(f"Failed message IDs: {failed_messages}")
    
    return response

def write_alerts_to_s3(alerts: List[Dict], date_key: str) -> List[str]:
    """
    Write alerts to S3 in partitioned JSONL format.
    
    Args:
        alerts: List of enriched alert dictionaries
        date_key: Date string in YYYY-MM-DD format
        
    Returns:
        List of S3 keys created
    """
    if not alerts:
        return []
    
    # Parse date for partition structure
    date_obj = dt.datetime.strptime(date_key, '%Y-%m-%d')
    year, month, day = date_obj.year, date_obj.month, date_obj.day
    
    # Split alerts into batches for optimal S3 file sizes
    s3_keys_created = []
    batch_num = 1
    
    for i in range(0, len(alerts), MAX_BATCH_SIZE):
        batch = alerts[i:i + MAX_BATCH_SIZE]
        
        # Generate unique S3 key
        timestamp = int(time.time())
        random_suffix = uuid.uuid4().hex[:8]
        base_key = f"alerts/year={year:04d}/month={month:02d}/day={day:02d}/alerts-{timestamp}-{random_suffix}-{batch_num:03d}"
        
        # Create JSONL content
        jsonl_lines = []
        for alert in batch:
            jsonl_lines.append(json.dumps(alert, ensure_ascii=False, separators=(',', ':')))
        
        jsonl_content = '\n'.join(jsonl_lines) + '\n'
        body_data = jsonl_content.encode('utf-8')
        content_type = "application/x-ndjson"
        
        # Optional compression
        if COMPRESSION_ENABLED:
            body_data = gzip.compress(body_data)
            s3_key = base_key + ".jsonl.gz"
            content_type = "application/gzip"
            content_encoding = "gzip"
        else:
            s3_key = base_key + ".jsonl"
            content_encoding = None
        
        # Prepare S3 metadata
        metadata = {
            "record_count": str(len(batch)),
            "batch_number": str(batch_num),
            "date_partition": date_key,
            "source": "sqs-lambda",
            "compressed": str(COMPRESSION_ENABLED).lower(),
            "file_size_bytes": str(len(body_data))
        }
        
        # Add sample alert info to metadata for debugging
        if batch:
            first_alert = batch[0]
            metadata.update({
                "sample_severity": first_alert.get('severity', 'unknown')[:50],
                "sample_product": first_alert.get('product', 'unknown')[:50],
                "sample_source": first_alert.get('source', 'unknown')[:50]
            })
        
        # Write to S3
        put_args = {
            "Bucket": ALERTS_BUCKET,
            "Key": s3_key,
            "Body": body_data,
            "ContentType": content_type,
            "Metadata": metadata
        }
        
        if content_encoding:
            put_args["ContentEncoding"] = content_encoding
        
        s3.put_object(**put_args)
        
        s3_keys_created.append(s3_key)
        logger.info(f"Created S3 file: s3://{ALERTS_BUCKET}/{s3_key} ({len(batch)} alerts, {len(body_data)} bytes)")
        
        batch_num += 1
    
    return s3_keys_created

def get_s3_stats(bucket: str, prefix: str = "alerts/") -> Dict:
    """
    Helper function to get S3 storage statistics (useful for monitoring).
    """
    try:
        paginator = s3.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=bucket, Prefix=prefix)
        
        total_objects = 0
        total_size = 0
        
        for page in page_iterator:
            if 'Contents' in page:
                for obj in page['Contents']:
                    total_objects += 1
                    total_size += obj['Size']
        
        return {
            "total_objects": total_objects,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2)
        }
    except Exception as e:
        logger.error(f"Failed to get S3 stats: {e}")
        return {"error": str(e)}

# Alternative: Direct API Gateway to S3 handler (if you want to skip SQS)
def direct_handler(event, context):
    """
    Alternative handler for direct API Gateway → Lambda → S3 (bypassing SQS).
    Use this if you prefer simpler architecture without SQS buffering.
    """
    logger.info("Processing direct alert ingestion to S3")
    
    try:
        # Parse API Gateway request
        if isinstance(event.get("body"), str):
            body = json.loads(event["body"])
        else:
            body = event.get("body", {})
    except json.JSONDecodeError:
        return {"statusCode": 400, "body": json.dumps({"error": "Invalid JSON"})}
    
    # Process single alert (reuse the SQS processing logic)
    now = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)
    alert_data = {
        "messageId": body.get("messageId", str(uuid.uuid4())),
        "event_ts_utc": now.isoformat().replace("+00:00", "Z"),
        "body": body.get("text", ""),
        "source": "direct-api",
        # ... add other fields as needed
    }
    
    # Write single alert to S3
    date_key = now.strftime('%Y-%m-%d')
    try:
        files_created = write_alerts_to_s3([alert_data], date_key)
        return {
            "statusCode": 202,
            "body": json.dumps({
                "status": "accepted",
                "messageId": alert_data["messageId"],
                "s3_files": files_created
            })
        }
    except Exception as e:
        logger.error(f"Failed to write to S3: {e}")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}

# Test harness
if __name__ == "__main__":
    # Mock SQS event
    test_event = {
        "Records": [
            {
                "messageId": "sqs-123",
                "body": json.dumps({
                    "messageId": "alert-123",
                    "event_ts_utc": "2025-08-25T10:30:00Z",
                    "body": "Test critical alert",
                    "severity": "critical",
                    "product": "govmeetings",
                    "source": "pagerduty",
                    "environment": "production"
                }),
                "attributes": {
                    "ApproximateReceiveCount": "1",
                    "ApproximateFirstReceiveTimestamp": str(int(time.time()))
                },
                "receiptHandle": "test-handle"
            }
        ]
    }
    
    result = handler(test_event, None)
    print(json.dumps(result, indent=2))
