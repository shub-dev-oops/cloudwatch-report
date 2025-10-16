Looking at this SOP and the recurring CoreDNS issues, let me think through a comprehensive analysis and action plan:

## Immediate Diagnostic Questions

**Critical gaps in the current SOP:**
1. **What specific error logs are appearing in CoreDNS?** (DNS timeouts, memory issues, crashes?)
2. **How frequently is this restart needed?** (Daily? Weekly? This indicates severity)
3. **Are there any patterns?** (Time of day, traffic spikes, specific queries?)
4. **What's the actual failure mode?** (Pods crashing, unresponsive, slow responses?)

## Checking CoreDNS Version

```bash
# Method 1: Check the deployment image
kubectl get deployment coredns -n kube-system -o jsonpath='{.spec.template.spec.containers[0].image}'

# Method 2: Check running pods
kubectl describe deployment coredns -n kube-system | grep Image

# Method 3: CoreDNS version via logs
kubectl logs -n kube-system -l k8s-app=kube-dns --tail=50 | grep version
```

```
# Pod image tag (what’s actually running)
kubectl -n kube-system get deploy coredns -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'

# EKS add-on version (source of truth if using managed add-on)
aws eks describe-addon --cluster-name aasmp-eks1 --addon-name coredns \
  --query 'addon.{AddonVersion:addonVersion,Status:status,Health:health.issues}' --output table

# If using Helm instead of EKS add-on:
helm -n kube-system list | grep -i coredns
helm -n kube-system history coredns

```



## Root Cause Analysis - What Could Be Wrong?

### 1. **Resource Exhaustion** (Most Likely)
```bash
# Check if CoreDNS is hitting memory/CPU limits
kubectl describe deployment coredns -n kube-system | grep -A 5 "Limits\|Requests"

# Check if pods are being OOMKilled
kubectl get pods -n kube-system -l k8s-app=kube-dns -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.containerStatuses[0].lastState.terminated.reason}{"\n"}{end}'
```

**Action:** Increase CoreDNS resource limits
```bash
kubectl set resources deployment coredns -n kube-system \
  --limits=memory=512Mi,cpu=500m \
  --requests=memory=256Mi,cpu=100m
```

### 2. **DNS Query Load**
```bash
# Enable CoreDNS metrics (if not already enabled)
kubectl get configmap coredns -n kube-system -o yaml

# Check if Prometheus metrics are enabled
# Look for "prometheus :9153" in the Corefile
```

### 3. **Pod Anti-Affinity Issues**
CoreDNS pods might be scheduling on the same nodes, creating single points of failure.

```bash
# Check current pod distribution
kubectl get pods -n kube-system -l k8s-app=kube-dns -o wide

# Add pod anti-affinity to spread across nodes
kubectl edit deployment coredns -n kube-system
```

## What to Tell Naveen - Action Plan

### **Short-term (This Week)**

1. **Increase CoreDNS Replicas**
```bash
kubectl scale deployment coredns -n kube-system --replicas=3
# Or even 4-5 for high-traffic prod
```

2. **Increase Resource Limits**
```bash
# Current limits might be too low
kubectl set resources deployment coredns -n kube-system \
  --limits=memory=512Mi,cpu=500m \
  --requests=memory=256Mi,cpu=250m
```

3. **Enable NodeLocal DNSCache**
This caches DNS queries on each node, dramatically reducing load on CoreDNS:
```bash
# Deploy NodeLocal DNSCache
kubectl apply -f https://k8s.io/examples/admin/dns/nodelocaldns.yaml
```

4. **Update CoreDNS Version**
```bash
# Check EKS recommended version
aws eks describe-addon-versions --addon-name coredns --kubernetes-version 1.XX

# Update via EKS addon
aws eks update-addon --cluster-name aasmp-eks1 \
  --addon-name coredns \
  --addon-version v1.XX.X-eksbuild.X
```

### **Mid-term (Next 2 Weeks)**

5. **Implement Proper Monitoring & Alerting**

```yaml
# Add ServiceMonitor for Prometheus
apiVersion: v1
kind: Service
metadata:
  name: coredns-metrics
  namespace: kube-system
  labels:
    k8s-app: kube-dns
spec:
  selector:
    k8s-app: kube-dns
  ports:
  - name: metrics
    port: 9153
    protocol: TCP
    targetPort: 9153
```

**Key Metrics to Monitor:**
```bash
# CoreDNS request rate
rate(coredns_dns_requests_total[5m])

# CoreDNS errors
rate(coredns_dns_responses_total{rcode="SERVFAIL"}[5m])

# CoreDNS latency
histogram_quantile(0.99, rate(coredns_dns_request_duration_seconds_bucket[5m]))

# Cache hit rate
rate(coredns_cache_hits_total[5m]) / rate(coredns_dns_requests_total[5m])
```

6. **Configure PodDisruptionBudget**
```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: coredns-pdb
  namespace: kube-system
spec:
  minAvailable: 2
  selector:
    matchLabels:
      k8s-app: kube-dns
```

7. **Optimize CoreDNS Configuration**
```bash
kubectl edit configmap coredns -n kube-system
```

Add these optimizations to the Corefile:
```
.:53 {
    errors
    health {
        lameduck 5s
    }
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
    prometheus :9153
    forward . /etc/resolv.conf {
        max_concurrent 1000
        policy random  # Better load distribution
    }
    cache 30 {  # Increase cache duration
        success 9984 30
        denial 9984 5
    }
    loop
    reload
    loadbalance round_robin  # Better distribution
}
```

### **Long-term (Next Month)**

8. **Investigate AWS Load Balancer Controller**
The ingress reconciliation issue suggests the AWS LB Controller might be making excessive DNS queries:
```bash
# Check AWS LB Controller logs
kubectl logs -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller --tail=100

# Check its resource usage
kubectl top pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

9. **Consider External DNS Solution**
For external domains, consider using Route53 directly or External-DNS operator.

10. **Implement Automated Remediation**
Create a Kubernetes CronJob or use a tool like Kubernetes Reloader to automatically restart CoreDNS if it becomes unhealthy (though this is a band-aid, not a fix).

## Enhanced Observability Setup

### **Grafana Dashboard Queries**
```promql
# DNS Request Rate
sum(rate(coredns_dns_requests_total[5m])) by (type)

# DNS Response Codes
sum(rate(coredns_dns_responses_total[5m])) by (rcode)

# Cache Efficiency
sum(rate(coredns_cache_hits_total[5m])) / sum(rate(coredns_dns_requests_total[5m])) * 100

# Pod Restarts
kube_pod_container_status_restarts_total{namespace="kube-system",pod=~"coredns.*"}
```

### **CloudWatch Logs Insights Queries**
```sql
# If using CloudWatch Container Insights
fields @timestamp, @message
| filter kubernetes.namespace_name = "kube-system"
| filter kubernetes.pod_name like /coredns/
| filter @message like /error|Error|ERROR|timeout|refused/
| sort @timestamp desc
| limit 100
```

## Critical Questions for Naveen

1. **What's the actual error in iLegislate when it's down?** (DNS resolution failure, timeout, 502/503?)
2. **How often does this happen?** (Multiple times daily = emergency)
3. **What's the traffic pattern?** (Constant or spiky?)
4. **When was CoreDNS last updated?** (Could be running ancient version)
5. **Is there a WAF/CDN in front?** (CloudFlare, etc. could help)
6. **What's the current replica count?** (Likely only 2, should be 3-5)

## Recommended Immediate Actions (Priority Order)

1. ✅ **Scale CoreDNS to 4-5 replicas** (5 minutes)
2. ✅ **Increase memory limits to 512Mi** (5 minutes)
3. ✅ **Check and update CoreDNS version** (30 minutes)
4. ✅ **Enable comprehensive logging** (15 minutes)
5. ✅ **Deploy NodeLocal DNSCache** (1 hour)
6. ✅ **Set up monitoring dashboard** (2 hours)
7. ✅ **Optimize Corefile configuration** (30 minutes)

This is a **systemic issue**, not a "restart and pray" situation. The restarts are treating symptoms, not the disease.
