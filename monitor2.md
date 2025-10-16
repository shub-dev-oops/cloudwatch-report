Perfect—let’s light up CloudWatch monitoring using the **Fluent Bit you already have in `amazon-cloudwatch`**, and avoid any new IAM where possible. I’ll give you a copy-paste “starter pack” that:

1. Creates **log-based metric filters+alarms** for:

   * ALB Controller **reconcile failures/timeouts** (root of your ingress “reconciling” stress),
   * CoreDNS **upstream DNS timeouts/panics** (the usual culprit),
   * CoreDNS **(re)starts** (as a proxy for pod churn if CI metrics aren’t there yet).

2. Uses **Container Insights (CI)** metrics *if they already exist*; otherwise falls back to logs.

3. Shows how to **check Prometheus scrape** quickly.

---

# A) One-shot setup (bash): filters + alarms (no new IAM objects)

> Assumes your cluster logs land in `/aws/eks/aasmp-eks1/cluster` (the common default for `aws-for-fluent-bit`). Replace values if your log group differs. You only need basic CloudWatch Logs/Alarms perms.

```bash
# ========= Config =========
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=us-east-1
LOG_GROUP="/aws/eks/aasmp-eks1/cluster"
SNS_ARN="arn:aws:sns:${REGION}:${ACCOUNT_ID}:devops-pages"   # <- change to your SNS topic

# Sanity: show a sample of recent log streams
aws logs describe-log-streams --log-group-name "$LOG_GROUP" --order-by LastEventTime --descending --max-items 5

# ========= 1) ALB Controller reconcile errors =========
# We’ll create two filters (JSON & plain) to be robust across log formats.

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "ALBController-ReconcileErrors-JSON" \
  --filter-pattern '{ $.kubernetes.container_name = "aws-load-balancer-controller" && ( $.level = "error" || $.msg = "failed to reconcile" || $.error = "timeout" ) }' \
  --metric-transformations metricName="ALBReconcileErrors",metricNamespace="EKS/Ingress",metricValue=1,defaultValue=0

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "ALBController-ReconcileErrors-Plain" \
  --filter-pattern "\"aws-load-balancer-controller\" (\"failed to reconcile\" || timeout || \"reconcile error\")" \
  --metric-transformations metricName="ALBReconcileErrors",metricNamespace="EKS/Ingress",metricValue=1,defaultValue=0

aws cloudwatch put-metric-alarm \
  --alarm-name "ALB-Controller-ReconcileErrors" \
  --namespace "EKS/Ingress" \
  --metric-name "ALBReconcileErrors" \
  --statistic Sum --period 300 --evaluation-periods 1 \
  --threshold 3 --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching \
  --alarm-actions "$SNS_ARN"

# ========= 2) CoreDNS upstream timeouts/panics =========
# Catch classic forwarder timeouts and panics in CoreDNS logs.
aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "CoreDNS-UpstreamTimeouts" \
  --filter-pattern '"kube-dns" ("plugin/forward" && ("timeout" || "no such host" || "i/o timeout"))' \
  --metric-transformations metricName="CoreDNSForwardTimeouts",metricNamespace="EKS/CoreDNS",metricValue=1,defaultValue=0

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "CoreDNS-Panic" \
  --filter-pattern '"kube-dns" "panic:"' \
  --metric-transformations metricName="CoreDNSPanics",metricNamespace="EKS/CoreDNS",metricValue=1,defaultValue=0

aws cloudwatch put-metric-alarm \
  --alarm-name "CoreDNS-Forward-Timeouts" \
  --namespace "EKS/CoreDNS" \
  --metric-name "CoreDNSForwardTimeouts" \
  --statistic Sum --period 300 --evaluation-periods 1 \
  --threshold 5 --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching \
  --alarm-actions "$SNS_ARN"

aws cloudwatch put-metric-alarm \
  --alarm-name "CoreDNS-Panics" \
  --namespace "EKS/CoreDNS" \
  --metric-name "CoreDNSPanics" \
  --statistic Sum --period 300 --evaluation-periods 1 \
  --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching \
  --alarm-actions "$SNS_ARN"

# ========= 3) CoreDNS (re)starts =========
# If Container Insights pod restart metric exists, prefer it:
HAS_CI=$(aws cloudwatch list-metrics --namespace ContainerInsights \
  --metric-name pod_number_of_container_restarts \
  --dimensions Name=ClusterName,Value=aasmp-eks1 Name=Namespace,Value=kube-system \
  --max-items 1 --query 'length(Metrics)')

if [[ "$HAS_CI" -gt 0 ]]; then
  echo "[*] Using ContainerInsights pod_number_of_container_restarts"
  aws cloudwatch put-metric-alarm \
    --alarm-name "CoreDNS-Restarts-Spike" \
    --namespace "ContainerInsights" \
    --metric-name "pod_number_of_container_restarts" \
    --dimensions Name=ClusterName,Value=aasmp-eks1 Name=Namespace,Value=kube-system \
    --statistic Sum --period 300 --evaluation-periods 1 \
    --threshold 3 --comparison-operator GreaterThanOrEqualToThreshold \
    --treat-missing-data notBreaching \
    --alarm-actions "$SNS_ARN"
else
  echo "[*] CI not detected; using log-startup heuristic"
  # Count CoreDNS server startup lines as a proxy for restarts.
  aws logs put-metric-filter \
    --log-group-name "$LOG_GROUP" \
    --filter-name "CoreDNS-Restarts-FromLogs" \
    --filter-pattern '"kube-dns" ("CoreDNS-1." || "Start serving" || "Start listening on :53")' \
    --metric-transformations metricName="CoreDNSRestartsFromLogs",metricNamespace="EKS/CoreDNS",metricValue=1,defaultValue=0

  aws cloudwatch put-metric-alarm \
    --alarm-name "CoreDNS-Restarts-FromLogs" \
    --namespace "EKS/CoreDNS" \
    --metric-name "CoreDNSRestartsFromLogs" \
    --statistic Sum --period 600 --evaluation-periods 1 \
    --threshold 3 --comparison-operator GreaterThanOrEqualToThreshold \
    --treat-missing-data notBreaching \
    --alarm-actions "$SNS_ARN"
fi

echo "[✓] Alarms created. Check CloudWatch → Alarms."
```

**What this gets you (fast):**

* A page when ALB reconciling starts erroring/looping,
* A page when CoreDNS logs show upstream DNS timeouts or panics,
* A page when CoreDNS pods restart a lot (CI metric if available; otherwise log heuristic).

> These hit exactly the patterns that were stressing Naveen: ingress “reconciling” tied to DNS flaps.

---

# B) Auto-collect diagnostics when CoreDNS restarts (no IAM)

If you want an *in-cluster* safety net (no IAM), deploy a tiny watcher that reacts to CoreDNS pod restartCount changes and **dumps ingress diagnostics** (and optionally posts to Teams). I can paste a ready Deployment+RBAC when you say “drop the watcher”.

---

# C) “Dynamic monitor for all Ingresses” (no canary needed)

Use a CronJob that curls **every Ingress host** and fails if any return non-2xx. Then alert on **job failures** via Prometheus (kube-state-metrics) or CloudWatch CI (if you have it).

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ingress-http-check
  namespace: kube-system
spec:
  schedule: "*/2 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
          - name: check
            image: curlimages/curl:8.9.1
            command: ["/bin/sh","-c"]
            args:
              - |
                set -e
                kubectl get ingress -A -o jsonpath='{range .items[*]}{.metadata.namespace}{";"}{.metadata.name}{";"}{range .spec.rules[*]}{.host}{"\n"}{end}{end}' \
                | while IFS=';' read -r ns name host; do
                    [ -z "$host" ] && continue
                    code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "https://${host}" || echo "000")
                    echo "$(date -Is) ${ns}/${name} ${host} -> ${code}"
                    case "$code" in 2*|3*) : ;; *) exit 1 ;; esac
                  done
```

Wire an alert on **failed jobs** (Prometheus: `increase(kube_job_status_failed[5m]) > 0`) or via CI’s job metrics.

---

# D) Do we have **Container Insights** already? How to verify quickly

```bash
# Pods present?
kubectl -n amazon-cloudwatch get pods
kubectl -n kube-system get ds,deploy | egrep -i 'cloudwatch|fluent|cwagent'

# Metrics present?
aws cloudwatch list-metrics --namespace ContainerInsights --max-items 5
aws cloudwatch list-metrics --namespace ContainerInsights \
  --metric-name pod_number_of_container_restarts \
  --dimensions Name=ClusterName,Value=aasmp-eks1 Name=Namespace,Value=kube-system
```

* If metrics exist, we used them above.
* If **not**, you still have value from the **log-based** alarms we just created (no extra IAM).

*(If you later want CI fully: you’ll need either node roles permitting `logs:PutLogEvents`/`cloudwatch:PutMetricData` or IRSA once someone with IAM can create it. Until then, we’re fine with logs+Prometheus.)*

---

# E) “Are we scraping CoreDNS in Prometheus?”

```bash
# Is CoreDNS exposing metrics?
kubectl -n kube-system get svc kube-dns -o yaml | grep -n metrics || true
kubectl -n kube-system port-forward deploy/coredns 9153:9153 >/dev/null 2>&1 &  echo $! > /tmp/pf.pid
sleep 1; curl -s http://127.0.0.1:9153/metrics | head; kill $(cat /tmp/pf.pid)

# Is Prometheus scraping it?
kubectl -A get svc | grep -i prometheus || true
# Port-forward Prometheus UI (adjust ns/name if different)
kubectl -n monitoring port-forward svc/prometheus-server 9090:9090 >/dev/null 2>&1 &  PFP=$!
sleep 1; \
  curl -s 'http://127.0.0.1:9090/api/v1/targets' \
  | jq '.data.activeTargets[] | select(.labels.job|test("coredns|kube-dns")) | {job: .labels.job,health: .health,lastError: .lastError}' \
; kill $PFP
```

If it’s **not** scraping, add a **ServiceMonitor** for `k8s-app=kube-dns`. I can paste a ready YAML for that and the Prometheus alert rules you need.

---

## That’s it

Run the bash block in **(A)** now. It will create the exact alarms that correlate with your incidents and give Naveen near-term confidence. If you want the **CoreDNS restart watcher** or the **ServiceMonitor + Prom alerts** as manifests, say the word and I’ll drop them ready-to-apply.
