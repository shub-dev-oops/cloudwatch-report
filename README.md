# SRE Digest — Executive Overview (with AWS Roles) ✨

## One‑liner

**Teams is the intake; AWS is the engine.** The SRE Digest turns Teams channel alerts into a clear, IST‑timed daily/weekly brief for faster decisions. 🚀

---

## What it does (business view)

* 🧹 **Reduces noise:** Groups and de‑duplicates so leaders see what matters.
* 🚨 **Surfaces risk:** Clear severity buckets (Critical/High/Warning) with occurrences.
* 🗃️ **Creates traceability:** Raw messages are retained for audit/backfill.
* ⏱️ **Speeds mornings:** Predictable, IST‑aligned summary posted to Teams.

---

## How the flow works (Teams as the source)

1. 📢 **Vendors → Teams:** Elastic, Pingdom, CloudWatch, Datadog post into named Teams channels (e.g., `mon_prod_crit_govmeetings`).
2. 🔁 **Teams → AWS API:** A small workflow forwards each new Teams **message body** to our API.
3. ⚙️ **AWS pipeline runs:** Events are enriched, stored, summarized, and a digest is posted back to Teams on schedule.

---

## AWS services and their roles (executive level)

* 🚪 **Amazon API Gateway (HTTP):** Secure front door for messages from the Teams workflow.
* 🤖 **AWS Lambda — Ingest (sqs‑ingest‑lambda.py):** Parses Teams body; sets **severity from channel name**, detects product/env/source; adds timestamps & a stable incident key.
* 📨 **Amazon SQS:** Buffers spikes; decouples ingest from storage for reliability.
* 🧾 **AWS Lambda — S3 Writer (sqs‑s3‑writer.py):** Batches ~100 msgs; writes **JSONL** to date‑partitioned S3; optional gzip.
* 🗂️ **Amazon S3:** Durable, low‑cost system of record (audit/backfill ready).
* ⏰ **Amazon EventBridge (Schedule):** Triggers digest at **18:45 UTC → 00:15 IST**.
* 🧠 **AWS Lambda — Digest (s3_digest.py) + Amazon Bedrock (Claude):** Groups by product/severity, computes **Counts vs Occurrences**, generates concise narrative, posts Teams‑ready markdown.
* 📈 **Amazon CloudWatch Logs/Metrics:** Central logs, health metrics, alarms for the pipeline.
* 🔐 **AWS IAM & KMS (optional):** Fine‑grained access + encryption at rest.

> **Why this set:** Fully serverless, low‑ops, cost‑efficient, and scales with bursty alert traffic. 💸📈

---

## What the digest shows (at a glance)

* 📊 **KPIs:** Total alerts + Critical/High/Warning with **occurrences**.
* 🧭 **Per‑product highlights:** A few lines per product—what happened and how often.
* 🕰️ **Window & timezone:** Explicit **Asia/Kolkata** date range.

---

## Light technical notes (kept simple)

* 🎯 **Severity & product:** Primarily from the **Teams channel name** (e.g., `_crit_`, `_high_`, `_warn_`; `govmeetings`, `onemeeting`, `swagit`).
* 🔁 **De‑duplication:** Stable **incident key** prevents double‑counting.
* ➕ **Counts vs 🔄 Occurrences:**

  * **Count** = unique alerts after de‑duplication.
  * **Occurrences** = total repeats/firings within the window.
* 📁 **Storage layout:** JSONL files in S3 with date partitions (lifecycle policies supported).
* 📅 **Scheduling:** Daily IST‑aligned run; weekly variant easy via another EventBridge rule.
* 🔗 **Links:** Minimized until Teams payloads include reliable canonical URLs.

---

## Controls & levers (exec‑friendly)

* 🧲 **Noise policy:** Include/exclude lower severities (e.g., hide `info`).
* 🧰 **Product scope:** Curated allowlist (GovMeetings + sub‑products).
* ⏱️ **Cadence:** Daily/weekly; ad‑hoc runs if needed.
* 🧮 **Retention:** S3 lifecycle (compression + retention) to balance compliance vs cost.

---

## Benefits to the organization

* ⚡ **Clarity & speed:** Quick read → quicker action.
* 📐 **Consistency:** Same structure daily—easy trend spotting.
* 🔎 **Auditability:** Raw inputs preserved; drill‑downs outside the digest.
* 🧘 **Low overhead:** Managed, serverless building blocks keep ops lean.

---

## Elevator pitch

**“Alerts already land in Teams. We use AWS to enrich, store, and summarize them—then send back a clean, IST‑timed digest so leaders and SREs can focus on action, not noise.”** 🧭
