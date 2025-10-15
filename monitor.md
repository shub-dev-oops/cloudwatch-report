```
# 0) Namespace var
NS=kube-system

# 1) Save current (broken) Corefile just in case
kubectl -n $NS get cm coredns -o jsonpath='{.data.Corefile}' > Corefile.broken.$(date +%s)

# 2) Apply a known-good Corefile (minimal, stable)
cat > /tmp/Corefile.good <<'EOF'
.:53 {
    errors
    health
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
    }
    prometheus :9153
    forward . /etc/resolv.conf
    cache 30
    reload
    loadbalance
}
EOF

kubectl -n $NS create configmap coredns --from-file=Corefile=/tmp/Corefile.good --dry-run=client -o yaml | kubectl apply -f -

# 3) Restart and watch
kubectl -n $NS rollout restart deploy/coredns
kubectl -n $NS rollout status deploy/coredns --timeout=5m

# 4) Quick health check
kubectl get pods -n $NS -l k8s-app=kube-dns -o wide
kubectl run dns-test --image=busybox:1.28 -it --rm --restart=Never -- nslookup kubernetes.default

```


You're hitting a classic **resourceVersion conflict** + a couple typos. Let’s fix it cleanly and safely.

## What went wrong

* Namespace typo: `kube-systen` → should be `kube-system`.
* You edited an *old* copy of the ConfigMap; the live object changed → `the object has been modified; please apply your changes to the latest version`.

## Safe, repeatable way to enable CoreDNS query logging (temporary)

### 1) Export the **latest** CoreDNS Corefile to a local file

```bash
kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}' > Corefile
```

### 2) Edit the `Corefile` locally

Add `errors` and `log` inside the main server block (`.:53 { ... }`), keeping the rest as-is. A typical good block looks like this (don’t copy blindly; merge into yours):

```
.:53 {
    errors
    log
    health
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
    }
    prometheus :9153
    forward . /etc/resolv.conf
    cache 30
    reload
    loadbalance
}
```

> Keep the order roughly like above; whitespace is fine. Do **not** remove other lines/plugins you already have.

### 3) Recreate the ConfigMap from your edited Corefile (avoids resourceVersion issues)

```bash
kubectl -n kube-system create configmap coredns \
  --from-file=Corefile=./Corefile \
  --dry-run=client -o yaml | kubectl apply -f -
```

### 4) Restart CoreDNS to pick changes

```bash
kubectl -n kube-system rollout restart deploy/coredns
kubectl -n kube-system rollout status deploy/coredns
```

### 5) Confirm logs (and that Fluent Bit picks them up)

```bash
kubectl -n kube-system logs -l k8s-app=kube-dns --tail=100
```

---

## Alternatives if you prefer “edit in place”

* **Server-side apply** (lets the apiserver merge and resolve fields):

```bash
kubectl -n kube-system apply --server-side --force-conflicts -f /tmp/coredns.yaml
```

* **Direct inline edit** (no tmp files):

```bash
kubectl -n kube-system edit configmap coredns
```

> Paste `errors` and `log` into the `data.Corefile` block, save & exit. If you still hit a conflict, re-run the command—it loads the latest version.

---

## Quick rollback (remove verbose logging)

1. Open editor:

```bash
kubectl -n kube-system edit configmap coredns
```

2. Remove the `log` line (keep `errors`), save.
3. Restart:

```bash
kubectl -n kube-system rollout restart deploy/coredns
```

---

## Pro tips

* Your previous command had typos:

  * `opply` → `apply`
  * `kube-systen` → `kube-system`
  * `/tmp/coredns.yanl` → `/tmp/coredns.yaml`
* If you see `kubectl.kubernetes.io/last-applied-configuration` noise, you can ignore it; or remove that annotation once using:

```bash
kubectl -n kube-system annotate configmap coredns kubectl.kubernetes.io/last-applied-configuration-
```

If you paste your current **exact** Corefile (sanitized), I’ll return the corrected version with `log` added in the right place and minimal diff.

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
  --set input.tail.path="/var/log/containers/*.log" \
  --set input.tail.parser="docker" \
  --set input.tail.memBufLimit="50MB" \
  --set input.tail.skipLongLines=true \
  --set input.tail.db="/var/fluent-bit/state/flb_kube.db" \
  --set input.tail.readFromHead=true \
  --set extraVolumeMounts[0].name=varlog \
  --set extraVolumeMounts[0].mountPath=/var/log \
  --set extraVolumes[0].name=varlog \
  --set extraVolumes[0].hostPath.path=/var/log


```
# Backup and edit CoreDNS config
### 
```
# Backup and edit CoreDNS config
kubectl -n kube-system get cm coredns -o yaml > /tmp/coredns.yaml

# In the Corefile 'block', ensure you have (order matters is ok here):
#   errors
#   log
# Example fragment:
# .:53 {
#     errors
#     log
#     health
#     ready
#     kubernetes cluster.local in-addr.arpa ip6.arpa {
#       pods insecure
#       fallthrough in-addr.arpa ip6.arpa
#     }
#     prometheus :9153
#     forward . /etc/resolv.conf
#     cache 30
# }
# Then apply:
kubectl -n kube-system apply -f /tmp/coredns.yaml
kubectl -n kube-system rollout restart deploy/coredns
kubectl -n kube-system rollout status deploy/coredns
```


### Quick chec
```
# On the node via Fluent Bit pod:
kubectl -n amazon-cloudwatch exec "$FB_POD" -- sh -lc 'grep coredns /var/log/containers/*.log | head -n 3 || true'

# In CloudWatch:
aws logs describe-log-groups --log-group-name-prefix "/aws/containerinsights/aasmp-eks1/application"
# Then check recent streams for namespace 'kube-system' and pod name containing 'coredns'

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
