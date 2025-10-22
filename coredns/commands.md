
-----

### Step 1: Install the Prometheus Operator Stack

This is the **one-time setup** that installs the "brain" (the Operator) and your new Prometheus, Alertmanager, and Grafana.

1.  **Create Your Isolated Namespace:**
    This keeps your new monitoring stack separate from Kubecost and everything else.

    ```bash
    kubectl create namespace sre-monitoring
    ```

2.  **Add the Prometheus Helm Repository:**
    This tells Helm where to find the chart.

    ```bash
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo update
    ```

3.  **Install the Stack:**
    This is the main command. It installs the `kube-prometheus-stack` chart into the namespace you just created.

    ```bash
    helm install sre-stack prometheus-community/kube-prometheus-stack \
      --namespace sre-monitoring
    ```

      * `sre-stack`: This is the "release name" we are giving our installation.
      * `--namespace sre-monitoring`: This tells Helm to install everything inside your new namespace.

4.  **Verify the Installation:**
    Wait 2-3 minutes for everything to start. Then, check that the pods are running:

    ```bash
    kubectl get pods -n sre-monitoring
    ```

    You should see a list of new pods, including:

      * `sre-stack-kube-prome-operator-...` (This is the "brain" itself)
      * `sre-stack-kube-prome-prometheus-...` (This is your new Prometheus server)
      * `alertmanager-sre-stack-kube-prome-alertmanager-...` (Your new Alertmanager)
      * And others for Grafana, `kube-state-metrics`, etc.

**Congratulations, your new monitoring stack is now running.**

-----

### Step 2: Apply Your Monitoring Configuration

**Now** you can apply the 4 YAML files from our previous conversation.

Because the operator (`sre-stack-kube-prome-operator-...`) is running, it will instantly see these new files and automatically re-configure your new Prometheus server.

1.  **Apply Your 4 Config Files:**
    (Run these commands from your local machine, in the directory where you saved the files.)
    ```bash
    kubectl apply -f monitor-coredns.yaml
    kubectl apply -f monitor-ingress.yaml
    kubectl apply -f dns-probe-cronjob.yaml
    kubectl apply -f sre-alerts.yaml
    ```

-----

### Step 3: Verify and Configure Notifications

This is the same as the final part of the last message.

1.  **Verify Prometheus:**
    Wait 1-2 minutes for the operator to act. Then, port-forward to your new Prometheus server to check the **Targets** and **Alerts** pages.

    ```bash
    kubectl port-forward -n sre-monitoring svc/sre-stack-kube-prome-prometheus 9090
    ```

      * Go to `http://localhost:9090`
      * Check **Status -\> Targets** to see your new `coredns-monitor` and `ingress-nginx-monitor` targets (they should turn green).
      * Check **Alerts** to see your three new alerts (`CoreDNSForwardErrors`, `IngressHigh5xxRate`, `DnsProbeJobFailed`).

2.  **Configure Notifications:**
    Follow the steps from the previous message to edit the `alertmanager-sre-stack-kube-prome-alertmanager` **secret** to add your Slack/SNS configuration and restart the Alertmanager pod.