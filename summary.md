Right Now,  I am working on an MVP (CloudWatch‐only):
That works like this. 
1. CloudWatch alarms → SNS → sre_reporting_cwa_collector Lambda → DynamoDB (15 min TTL)
2. Every 10 min: cw_digest Lambda reads DynamoDB → Bedrock Agent → Teams webhook
3. Validate end-to-end: fire an alarm, wait 10 min, check #sre-digest

```
CloudWatch Alarms ──▶ SNS topic
                         │
                         ▼
              collector_lambda
          (put each alarm into DynamoDB)
                         │
   EventBridge rule  (rate:10 min)
                         ▼
              digest_lambda
         (query DynamoDB → Bedrock → Teams)
```

Essentially,
Alert Ingestion (CloudWatch → SNS → Lambda → DynamoDB)
Digest Function (DynamoDB → Bedrock → Teams)

We have only tested this with only 2 alerts so far, still needs further development.


In future, Pipe in Pingdom & Elastic alerts via the same SNS → collector → digest flow 
If not we will read the entire microsoft teams channel with various sources to compile up a digest and fire it up every few minutes as per the requirements of the ticket.  pull Teams channel messages via Graph API
And Of course, Add SQS for durability and IaC for automation
We may consider Swap S3 or DynamoDB Streams for alternate buffering or faster reads



```

```



I've deployed the following resources:
```

SNS Topic: SRE-Reporting-CWA
DyanmoDB: sre_reporting_cwa_cache
IAM: SRE-Reporting-CWA-IAM
Lambda: sre-reporting-cwa-lambda :sre-reporting-cwa-digest-lambda
Bedrock: SRE-Reporting-Bedrock
teams channel : mon_prod_crit_govmeetings  webhook sre-reporting-webhook

```