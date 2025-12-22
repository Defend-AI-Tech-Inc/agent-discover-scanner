# Tetragon Setup Guide

## Overview

This guide explains how to install Cilium Tetragon in your Kubernetes cluster to enable runtime monitoring for AgentDiscover Scanner.

**Prerequisites:**
- Kubernetes cluster (v1.23+)
- `kubectl` configured with cluster admin access
- Helm 3.x installed
- 5-10 minutes

**What You'll Get:**
- eBPF-based runtime monitoring
- Detection of LLM/Vector DB API calls from any pod
- Near-zero performance overhead
- Production-grade security observability

---

## Quick Start

```bash
# 1. Install Tetragon via Helm
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system

# 2. Verify installation
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon

# 3. Apply LLM detection policy
kubectl apply -f https://raw.githubusercontent.com/Defend-AI-Tech-Inc/agent-discover-scanner/main/deployment/kubernetes/tracing-policy.yaml

# 4. Test it works
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout --tail=10
```

---

## Detailed Installation

### Step 1: Install Tetragon

Tetragon runs as a DaemonSet (one pod per node) and uses eBPF to monitor kernel-level events.

```bash
# Add Cilium Helm repository
helm repo add cilium https://helm.cilium.io
helm repo update

# Install Tetragon in kube-system namespace
helm install tetragon cilium/tetragon \
  --namespace kube-system \
  --wait

# Wait for pods to be ready (1-2 minutes)
kubectl rollout status daemonset/tetragon -n kube-system
```

**Expected output:**
```
NAME                    READY   STATUS    RESTARTS   AGE
tetragon-xxxxx          2/2     Running   0          30s
tetragon-yyyyy          2/2     Running   0          30s
tetragon-zzzzz          2/2     Running   0          30s
```

### Step 2: Verify Event Stream

Tetragon streams events to stdout. Let's verify it's working:

```bash
# View raw Tetragon events
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout --tail=20 -f
```

You should see JSON events like:
```json
{
  "process_exec": {...},
  "process_connect": {...},
  "time": "2025-12-22T10:30:00Z"
}
```

Press `Ctrl+C` to stop.

### Step 3: Apply TracingPolicy

TracingPolicies tell Tetragon **what** to monitor. We've created one specifically for LLM/Vector DB detection.

```bash
# Apply the LLM detection policy
kubectl apply -f deployment/kubernetes/tracing-policy.yaml
```

This policy monitors connections to:
- **LLM APIs**: OpenAI, Anthropic, Google AI, Cohere, AWS Bedrock
- **Vector Databases**: Pinecone, Weaviate, Qdrant, Chroma

### Step 4: Test the Setup

Deploy a test pod that makes an LLM API call:

```bash
# Deploy test workload
kubectl apply -f examples/k8s/test-workload.yaml

# Watch for events (should see connection to api.openai.com)
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout --tail=50 | grep openai
```

If you see events mentioning `api.openai.com`, **it's working!** 🎉

---

## Platform-Specific Notes

### Amazon EKS

```bash
# EKS works out of the box
helm install tetragon cilium/tetragon -n kube-system
```

### Google GKE

```bash
# GKE requires COS (Container-Optimized OS) nodes
# Verify your nodes are COS:
kubectl get nodes -o jsonpath='{.items[*].status.nodeInfo.osImage}'

# If using Ubuntu nodes, install BTF headers:
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/gke-ubuntu-btf.yaml

# Then install Tetragon
helm install tetragon cilium/tetragon -n kube-system
```

### Azure AKS

```bash
# AKS works out of the box
helm install tetragon cilium/tetragon -n kube-system
```

### k3s (Lightweight Kubernetes)

```bash
# k3s uses Flannel by default, but Tetragon doesn't require Cilium CNI
helm install tetragon cilium/tetragon -n kube-system

# No additional configuration needed
```

### OpenShift

```bash
# OpenShift requires SecurityContextConstraints
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/install/openshift/tetragon-scc.yaml

helm install tetragon cilium/tetragon \
  --namespace kube-system \
  --set securityContext.privileged=true
```

---

## Configuration Options

### Custom Helm Values

Create `tetragon-values.yaml`:

```yaml
# Export events to file instead of stdout (useful for large clusters)
export:
  filenames:
    - /var/log/tetragon/events.json

# Resource limits (adjust based on cluster size)
resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

# Enable metrics for Prometheus
enableProcessCred: true
enableProcessNs: true
```

Install with custom values:
```bash
helm install tetragon cilium/tetragon \
  -n kube-system \
  -f tetragon-values.yaml
```

---

## Validation Checklist

Before using AgentDiscover Scanner's `monitor-k8s` command, verify:

- [ ] Tetragon pods are running on **all nodes**
  ```bash
  kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon -o wide
  ```

- [ ] TracingPolicy is applied
  ```bash
  kubectl get tracingpolicy -A
  ```

- [ ] Events are streaming
  ```bash
  kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout --tail=5
  ```

- [ ] Test workload generates events
  ```bash
  kubectl apply -f examples/k8s/test-workload.yaml
  kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout | grep -i "openai\|anthropic"
  ```

---

## Troubleshooting

### Pods Not Starting

**Error**: `CrashLoopBackOff` or `ImagePullBackOff`

**Solution**:
```bash
# Check pod status
kubectl describe pod -n kube-system -l app.kubernetes.io/name=tetragon

# Common issue: Insufficient permissions
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/install/kubernetes/tetragon.yaml
```

### No Events Appearing

**Error**: `kubectl logs` shows no output

**Solution**:
```bash
# 1. Verify Tetragon is running
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon

# 2. Check if TracingPolicy is applied
kubectl get tracingpolicy -A

# 3. Test with verbose logging
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c tetragon -f
```

### eBPF Not Supported

**Error**: `kernel does not support eBPF`

**Solution**: Upgrade your kernel to 4.19+ or use a supported platform (EKS, GKE, AKS all support eBPF).

### Performance Impact

**Concern**: "Will this slow down my cluster?"

**Answer**: No. eBPF monitoring has <1% overhead. Tetragon is designed for production use.

**Verification**:
```bash
# Check Tetragon resource usage
kubectl top pods -n kube-system -l app.kubernetes.io/name=tetragon
```

Typical usage: ~50-100MB RAM, ~0.05 CPU per node.

---

## Security Considerations

### What Tetragon Can See

✅ **Tetragon monitors**:
- Process executions
- Network connections
- File operations
- System calls

❌ **Tetragon CANNOT see**:
- Encrypted traffic contents (HTTPS payload)
- Environment variables
- Secrets/ConfigMaps
- Application memory

**Privacy**: Tetragon sees *metadata* (destination IPs, DNS names) but not *data* (API keys, prompts, responses).

### RBAC Permissions

Tetragon requires cluster-level permissions. Review the ServiceAccount:

```bash
# View Tetragon's permissions
kubectl get clusterrole tetragon -o yaml
```

**Required permissions**:
- Read pods, namespaces (for attribution)
- eBPF system access (privileged pods)

---

## Uninstallation

To remove Tetragon:

```bash
# Delete TracingPolicy
kubectl delete tracingpolicy llm-api-detection

# Uninstall Helm release
helm uninstall tetragon -n kube-system

# Verify removal
kubectl get pods -n kube-system | grep tetragon
```

---

## Next Steps

Now that Tetragon is installed:

1. **Install AgentDiscover Scanner**:
   ```bash
   pip install agent-discover-scanner
   ```

2. **Run production monitoring**:
   ```bash
   agent-discover-scanner monitor-k8s --namespace production --duration 300
   ```

3. **Correlate with code scans**:
   ```bash
   agent-discover-scanner scan ./my-app --output code-scan.sarif
   agent-discover-scanner monitor-k8s --namespace prod --output runtime.json
   agent-discover-scanner correlate --code-scan code-scan.sarif --network-scan runtime.json
   ```

---

## Support

- **Documentation**: https://tetragon.io/docs/
- **GitHub Issues**: https://github.com/cilium/tetragon/issues
- **Slack**: https://cilium.slack.com (join #tetragon channel)
- **DefendAI Support**: support@defendai.ai

---

## FAQs

**Q: Do I need Cilium CNI to use Tetragon?**  
A: No. Tetragon works with any CNI (Flannel, Calico, etc.).

**Q: Can I use Tetragon with Istio/service mesh?**  
A: Yes, they're complementary. Istio handles L7, Tetragon handles kernel-level visibility.

**Q: Does this work on ARM nodes?**  
A: Yes, Tetragon supports both amd64 and arm64.

**Q: Can I run this in air-gapped environments?**  
A: Yes, pull images beforehand:
```bash
docker pull quay.io/cilium/tetragon:latest
docker pull quay.io/cilium/tetragon-operator:latest
```

**Q: How much disk space does Tetragon use?**  
A: ~500MB for images, plus event logs (configurable rotation).

---

**You're ready!** Tetragon is now monitoring your cluster for AI agent activity. 🚀
