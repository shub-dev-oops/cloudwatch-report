You got it—here’s a clean, **CLI-only** setup for **Container Insights on EKS** (metrics + logs) using **IRSA** + **Helm**. Copy, paste, and run section-by-section.

> Assumes: `aws`, `kubectl`, `helm`, and `jq` are installed and you have cluster admin. Replace variables as needed.

---

# 0) Set variables

```bash
# >>> change these <<<
export CLUSTER=aasmp-eks1
export REGION=us-east-1

# usually fine to keep
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export OIDC_URL=$(aws eks describe-cluster --region $REGION --name $CLUSTER --query "cluster.identity.oidc.issuer" --output text | sed 's#^https://##')
```

---

# 1) Ensure OIDC provider exists for IRSA

```bash
aws iam list-open-id-connect-providers --query "OpenIDConnectProviderList[].Arn" --output text | grep -q "$OIDC_URL" || \
aws iam create-open-id-connect-provider \
  --url "https://$OIDC_URL" \
  --client-id-list "sts.amazonaws.com" \
  --thumbprint-list "9e99a48a9960b14926bb7f3b02e22da0afd10df6"
```

---

# 2) Create IAM roles (IRSA) for:

* **CloudWatch Agent** (metrics → CloudWatch “ContainerInsights”)
* **Fluent Bit** (logs → CloudWatch Logs)

## 2a) Trust policies (bind SA → role)

```bash
cat > /tmp/trust-cwagent.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::$ACCOUNT_ID:oidc-provider/$OIDC_URL" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": { "StringEquals": { "$OIDC_URL:sub": "system:serviceaccount:amazon-cloudwatch:cloudwatch-agent" } }
  }]
}
EOF

cat > /tmp/trust-fluentbit.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::$ACCOUNT_ID:oidc-provider/$OIDC_URL" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": { "StringEquals": { "$OIDC_URL:sub": "system:serviceaccount:kube-system:aws-for-fluent-bit" } }
  }]
}
EOF
```

## 2b) Create roles

```bash
aws iam create-role --role-name EKS-CWAgent-$CLUSTER --assume-role-policy-document file:///tmp/trust-cwagent.json
aws iam create-role --role-name EKS-FluentBit-$CLUSTER --assume-role-policy-document file:///tmp/trust-fluentbit.json
```

## 2c) Attach policies (use AWS managed for speed)

```bash
# Metrics & basic system discovery
aws iam attach-role-policy --role-name EKS-CWAgent-$CLUSTER --policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy

# Logs to CloudWatch Logs (use tighter custom policy later if you want)
aws iam attach-role-policy --role-name EKS-FluentBit-$CLUSTER --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsFullAccess
```

> (Optional hardening later: replace `CloudWatchLogsFullAccess` with a least-priv policy granting `logs:CreateLogGroup`, `CreateLogStream`, `PutLogEvents`, `DescribeLogStreams` on your log groups.)

---

# 3) Create namespaces & service accounts (with IRSA annotations)

```bash
kubectl create namespace amazon-cloudwatch --dry-run=client -o yaml | kubectl apply -f -
kubectl create sa cloudwatch-agent -n amazon-cloudwatch --dry-run=client -o yaml | kubectl apply -f -
kubectl create sa aws-for-fluent-bit -n kube-system --dry-run=client -o yaml | kubectl apply -f -

kubectl annotate sa cloudwatch-agent -n amazon-cloudwatch eks.amazonaws.com/role-arn=arn:aws:iam::$ACCOUNT_ID:role/EKS-CWAgent-$CLUSTER --overwrite
kubectl annotate sa aws-for-fluent-bit -n kube-system eks.amazonaws.com/role-arn=arn:aws:iam::$ACCOUNT_ID:role/EKS-FluentBit-$CLUSTER --overwrite
```

---

# 4) Add EKS charts & install **CloudWatch Agent** (metrics)

```bash
helm repo add eks https://aws.github.io/eks-charts
helm repo update

cat > cwagent-values.yaml <<'EOF'
clusterName: aasmp-eks1
region: us-east-1
serviceAccount:
  create: false
  name: cloudwatch-agent
  annotations: {}
# Request/limit modest so it’s light
agent:
  resources:
    requests: { cpu: "100m", memory: "200Mi" }
    limits:   { cpu: "200m", memory: "400Mi" }
# Enable Kubernetes metrics collection (Container Insights)
logs:
  metrics_collected:
    kubernetes: {}
# Emit Container Insights enhanced metrics
# (The chart ships a default ConfigMap; leaving as default is fine for CI)
EOF

helm upgrade --install cloudwatch-agent eks/cloudwatch-agent \
  -n amazon-cloudwatch -f cwagent-values.yaml
```

---

# 5) Install **Fluent Bit** (logs → CloudWatch Logs)

Pick a single cluster log group to keep things tidy.

```bash
export CW_LOG_GROUP=/aws/eks/$CLUSTER/cluster

# Make sure the group exists (no-op if it does)
aws logs create-log-group --log-group-name "$CW_LOG_GROUP" --region $REGION 2>/dev/null || true

helm upgrade --install aws-for-fluent-bit eks/aws-for-fluent-bit -n kube-system \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-for-fluent-bit \
  --set cloudWatch.region=$REGION \
  --set cloudWatch.logGroupName="$CW_LOG_GROUP" \
  --set cloudWatch.autoCreateGroup=true
```

> This ships kubelet/kube-apiserver/container stdout/stderr into the log group. You can later fine-tune parsers/filters to cut noise.

---

# 6) Validate

```bash
# Pods up and running?
kubectl -n amazon-cloudwatch get pods
kubectl -n kube-system get pods | grep fluent-bit

# Metrics appearing? (give it 2–3 minutes)
aws cloudwatch list-metrics --namespace "ContainerInsights" --region $REGION \
  --query 'Metrics[?contains(Dimensions[?Name==`ClusterName`].Value, `'$CLUSTER'`)]' --output table

# Logs flowing?
aws logs describe-log-streams --log-group-name "$CW_LOG_GROUP" --region $REGION --max-items 5
```

Open **CloudWatch → Metrics → ContainerInsights** and you should see cluster, node, namespace, pod, and deployment level metrics.
Open **CloudWatch → Logs → Log groups** and check `$CW_LOG_GROUP` for streams.

---

# 7) (Optional) CoreDNS-focused alarms (now that CI is on)

**Pod restart spike (namespace-wide, no pod names needed)**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "CoreDNS-Restarts-Spike" \
  --namespace "ContainerInsights" \
  --metric-name "pod_number_of_container_restarts" \
  --dimensions Name=ClusterName,Value=$CLUSTER Name=Namespace,Value=kube-system \
  --statistic Sum --period 300 --evaluation-periods 1 \
  --threshold 3 --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching
```

**Deployment availability dip**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "CoreDNS-Availability-Dip" \
  --metrics '[
    {"Id":"desired","MetricStat":{"Metric":{"Namespace":"ContainerInsights","MetricName":"deployment_desired","Dimensions":[
      {"Name":"ClusterName","Value":"'$CLUSTER'"} ,{"Name":"Namespace","Value":"kube-system"},{"Name":"Deployment","Value":"coredns"}]},"Period":60,"Stat":"Average"}},
    {"Id":"available","MetricStat":{"Metric":{"Namespace":"ContainerInsights","MetricName":"deployment_available","Dimensions":[
      {"Name":"ClusterName","Value":"'$CLUSTER'"} ,{"Name":"Namespace","Value":"kube-system"},{"Name":"Deployment","Value":"coredns"}]},"Period":60,"Stat":"Average"}},
    {"Id":"breach","Expression":"available < desired","Label":"unavailable","ReturnData":true}
  ]' \
  --comparison-operator GreaterThanThreshold --threshold 0 \
  --evaluation-periods 5 --treat-missing-data breaching
```

(Add `--alarm-actions arn:aws:sns:$REGION:$ACCOUNT_ID:your-topic` to wire paging.)

---

# 8) (Optional) ALB Controller “reconcile errors” alarm (cluster-wide)

```bash
# Create a metric from controller logs (already shipped by Fluent Bit)
aws logs put-metric-filter \
  --log-group-name "$CW_LOG_GROUP" \
  --filter-name "ALBControllerReconcileErrors" \
  --filter-pattern '"failed to reconcile" || timeout || "reconcile error"' \
  --metric-transformations metricName="ALBReconcileErrors",metricNamespace="EKS/Ingress",metricValue=1,defaultValue=0

aws cloudwatch put-metric-alarm \
  --alarm-name "ALB-Controller-ReconcileErrors" \
  --namespace "EKS/Ingress" \
  --metric-name "ALBReconcileErrors" \
  --statistic Sum --period 300 --evaluation-periods 1 \
  --threshold 3 --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching
```

---

## Notes / gotchas

* If you use **cluster-autoscaler** or many pods, keep Fluent Bit filters lean to control log costs.
* Container Insights doesn’t scrape CoreDNS Prometheus metrics; it surfaces pod/deployment/node stats. For DNS latency/rcode panels, keep Prometheus scraping `:9153`.
* You can scope logs initially to `kube-system` by altering the Fluent Bit chart filters (reduce cost/noise), then expand.

If you want, I can also give you **least-priv IAM JSON** for Fluent Bit, and a **CloudWatch Dashboard** JSON (CoreDNS restarts/availability + node & pod CPU/Mem) that you can import in one click.
