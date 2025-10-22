# Example: AWS NLB + keep client IPs + restrict access


```
helm upgrade sre-stack prometheus-community/kube-prometheus-stack \
  -n sre-monitoring \
  --reuse-values \
  --set prometheus.service.type=LoadBalancer \
  --set alertmanager.service.type=LoadBalancer \
  --set prometheus.service.externalTrafficPolicy=Local \
  --set alertmanager.service.externalTrafficPolicy=Local \
  --set prometheus.service.loadBalancerSourceRanges[0]=1.2.3.4/32 \
  --set alertmanager.service.loadBalancerSourceRanges[0]=1.2.3.4/32 \
  --set prometheus.service.annotations."service\.beta\.kubernetes\.io/aws-load-balancer-type"=nlb \
  --set alertmanager.service.annotations."service\.beta\.kubernetes\.io/aws-load-balancer-type"=nlb
```