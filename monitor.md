
# 0) Log
Got it — this is a common gotcha. Seeing logs under /aws/eks/fluentbit doesn’t mean your setting was ignored; that log group is typically the Fluent Bit pod’s own stdout/stderr (its container logs). Your workload logs are controlled by the aws-for-fluent-bit output.conf generated from the Helm values. Let’s (1) verify current config, (2) confirm where workload logs are landing, and (3) force the desired log group.

1) Verify what the chart actually rendered
```
# What values are in use?
helm get values -n amazon-cloudwatch aws-for-fluent-bit

# Inspect the rendered Fluent Bit output to CloudWatch
kubectl -n amazon-cloudwatch get cm aws-for-fluent-bit -o jsonpath='{.data.output\.conf}{"\n"}'
```

```
helm upgrade --install aws-for-fluent-bit eks/aws-for-fluent-bit \
  -n amazon-cloudwatch \
  --set cloudWatch.enabled=true \
  --set cloudWatch.region=$(aws configure get region) \
  --set cloudWatch.autoCreateGroup=true \
  --set cloudWatch.logGroupTemplate="/aws/containerinsights/{{.ClusterName}}/application" \
  --set cloudWatch.logStreamTemplate="{{.Namespace}}/{{.PodName}}/{{.ContainerName}}" \
  --set cloudWatch.logRetentionDays=30 \
  --set kinesis.enabled=false \
  --set firehose.enabled=false

```

# 1) One-paste CloudShell script — collect CoreDNS health + logs (current & crashed) and save to a file

```bash
# ===== CoreDNS evidence collector (run in CloudShell with kubectl + aws CLI configured) =====
set -euo pipefail

CLUSTER="aasmp-eks1"
NS="kube-system"
LABEL="k8s-app=kube-dns"
TS="$(date +'%Y%m%d_%H%M%S')"
OUT="coredns_diagnostics_${CLUSTER}_${TS}.log"

{
  echo "==== CoreDNS Diagnostics for ${CLUSTER} @ ${TS} ===="

  echo -e "\n## Pods:"
  kubectl get pods -n "${NS}" -l "${LABEL}" -o wide

  echo -e "\n## Restart counts:"
  kubectl get pods -n "${NS}" -l "${LABEL}" -o jsonpath='{range .items[*]}{.metadata.name}{" => restarts: "}{.status.containerStatuses[0].restartCount}{"\n"}{end}'

  echo -e "\n## Resource usage (if metrics-server present):"
  (kubectl top pod -n "${NS}" | grep -i coredns) || echo "metrics-server not available"

  echo -e "\n## Events (recent):"
  kubectl get events -n "${NS}" --sort-by='.lastTimestamp' | grep -iE 'coredns|kube-dns' || true

  echo -e "\n## Current logs (last 500 lines per pod):"
  kubectl logs -n "${NS}" -l "${LABEL}" --tail=500 --timestamps || true

  echo -e "\n## Previous (crashed/restarted) logs (last 500 lines per pod):"
  kubectl logs -n "${NS}" -l "${LABEL}" --previous --tail=500 --timestamps || echo "No previous logs (no recent restarts)"

  echo -e "\n## Error pattern scan (current + previous):"
  {
    kubectl logs -n "${NS}" -l "${LABEL}" --tail=2000 --timestamps || true
    kubectl logs -n "${NS}" -l "${LABEL}" --previous --tail=2000 --timestamps || true
  } | grep -Ei "timeout|SERVFAIL|plugin/cache|read udp|connection refused|dial tcp" || echo "No error patterns found"

} | tee "${OUT}"

echo "✅ Saved CoreDNS diagnostics to: ${OUT}"
```

You can attach that single file (`coredns_diagnostics_<cluster>_<timestamp>.log`) to your CR/RCA.

---

# 2) Check if CoreDNS (pod) logs are already flowing to CloudWatch

```bash
# Replace with your cluster name
CLUSTER="aasmp-eks1"

# Common Container Insights log groups:
aws logs describe-log-groups --log-group-name-prefix "/aws/containerinsights/${CLUSTER}/" --query 'logGroups[].logGroupName' --output table

# Control plane logs (separate from pod logs):
aws logs describe-log-groups --log-group-name-prefix "/aws/eks/${CLUSTER}/cluster" --query 'logGroups[].logGroupName' --output table
```

* If you see `/aws/containerinsights/<cluster>/application`, your **pod stdout/stderr** (including CoreDNS) can be shipped there (via Fluent Bit).
* If you only see `/aws/eks/<cluster>/cluster`, that’s **control plane logs** (API/audit/etc.), not pod logs.

---

# 3) Enable shipping CoreDNS/pod logs to CloudWatch (no Grafana needed)

If pod logs aren’t in CloudWatch yet, deploy **CloudWatch Agent + AWS for Fluent Bit** via Helm (AWS-supported):

```bash
# Add repos
helm repo add aws-cloudwatch https://aws.github.io/amazon-cloudwatch-agent
helm repo add eks https://aws.github.io/eks-charts
helm repo update

# Create namespace
kubectl create namespace amazon-cloudwatch 2>/dev/null || true

# (A) Install CloudWatch Agent (for Container Insights metrics)
helm upgrade --install cloudwatch-agent aws-cloudwatch/amazon-cloudwatch-agent \
  --namespace amazon-cloudwatch \
  --set clusterName=aasmp-eks1

# (B) Install Fluent Bit (ships application/container logs to CloudWatch Logs)
helm upgrade --install aws-for-fluent-bit eks/aws-for-fluent-bit \
  --namespace amazon-cloudwatch \
  --set cloudWatch.region=$(aws configure get region) \
  --set cloudWatch.logGroupName=/aws/containerinsights/aasmp-eks1/application \
  --set cloudWatch.logStreamPrefix=fluent-bit- \
  --set kinesis.enabled=false \
  --set firehose.enabled=false
```

That will start sending **all pod logs** (including CoreDNS in `kube-system`) to:

```
/aws/containerinsights/aasmp-eks1/application
```

### (Optional) Enable control plane logging too (API, audit, etc.)

```bash
aws eks update-cluster-config \
  --name aasmp-eks1 \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
```

---

# 4) Quick CloudWatch Logs Insights query for CoreDNS errors (once logs are flowing)

In **CloudWatch Logs → Log groups →** `/aws/containerinsights/aasmp-eks1/application` → *Logs Insights*, run:

```sql
fields @timestamp, @message, kubernetes.pod_name
| filter kubernetes.namespace_name = "kube-system"
| filter kubernetes.pod_name like /coredns/
| filter @message like /timeout|SERVFAIL|plugin\/cache|read udp|connection refused|dial tcp/
| sort @timestamp desc
| limit 100
```

---

If you want, I can also give you a tiny **Terraform/CloudFormation** snippet to deploy the Helm releases or a **metric filter + alarm** on those error patterns.
