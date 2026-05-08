# Deploying AgentDiscover Scanner in Kubernetes

Run the scanner as a DaemonSet to continuously monitor every node in your cluster for AI agent activity.

---

## Overview

The recommended production deployment for Kubernetes environments:

- **DaemonSet** — one scanner pod per node, watching local network and endpoint activity
- **Tetragon** — eBPF-based kernel visibility into pod-level AI API calls (Layer 3)
- **Platform integration** — continuous upload to DefendAI platform for cross-cluster inventory

---

## Prerequisites

- Kubernetes 1.24+
- Helm 3+
- `kubectl` with cluster-admin access (for Tetragon DaemonSet)
- Linux nodes (Layer 3 eBPF requires Linux kernel 5.4+)

---

## Quick install (automated)

```bash
git clone https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner
cd agent-discover-scanner
sudo bash install.sh
```

`install.sh` handles:
- Helm repository setup
- Tetragon installation with the AgentDiscover tracing policy
- RBAC (ClusterRole for K8s API read access)
- Service account creation

---

## Manual Helm install

### 1. Install Tetragon

```bash
helm repo add cilium https://helm.cilium.io
helm repo update

helm install tetragon cilium/tetragon \
  --namespace kube-system \
  --set tetragon.export.stdout.enabled=true
```

### 2. Apply the tracing policy

The tracing policy tells Tetragon which syscalls to watch. The AgentDiscover policy watches `connect()` calls to AI provider IP ranges:

```bash
kubectl apply -f deployment/kubernetes/tracing-policy.yaml
```

### 3. Verify Tetragon is running

```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon
```

### 4. Run the scanner targeting the Tetragon export file

```bash
# On the node directly, or via a DaemonSet pod:
agent-discover-scanner monitor-k8s \
  --tetragon-export-file /var/run/cilium/tetragon/tetragon.log \
  --format jsonl \
  --output /var/log/agent-discover/layer3_k8s.jsonl
```

---

## DaemonSet deployment

Deploy the scanner as a DaemonSet to monitor every node:

```yaml
# daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: agent-discover-scanner
  namespace: kube-system
  labels:
    app: agent-discover-scanner
spec:
  selector:
    matchLabels:
      app: agent-discover-scanner
  template:
    metadata:
      labels:
        app: agent-discover-scanner
    spec:
      serviceAccountName: agent-discover-scanner
      hostNetwork: true        # Layer 2: see host network connections
      hostPID: true            # Layer 2: attribute connections to processes
      containers:
        - name: scanner
          image: python:3.12-slim
          command:
            - /bin/sh
            - -c
            - |
              pip install agent-discover-scanner && \
              agent-discover-scanner scan-all /host-repo \
                --daemon \
                --duration 30 \
                --output /var/log/agent-discover \
                --tetragon-export-file /var/run/cilium/tetragon/tetragon.log \
                --platform \
                --api-key $(cat /etc/defendai/api-key)
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          volumeMounts:
            - name: host-repo
              mountPath: /host-repo
              readOnly: true
            - name: tetragon-export
              mountPath: /var/run/cilium/tetragon
              readOnly: true
            - name: scan-output
              mountPath: /var/log/agent-discover
            - name: api-key
              mountPath: /etc/defendai
              readOnly: true
          securityContext:
            privileged: false
            capabilities:
              add: ["NET_ADMIN"]   # required for Layer 2 network monitoring
      volumes:
        - name: host-repo
          hostPath:
            path: /opt/apps       # path to your deployed code on each node
        - name: tetragon-export
          hostPath:
            path: /var/run/cilium/tetragon
        - name: scan-output
          hostPath:
            path: /var/log/agent-discover
        - name: api-key
          secret:
            secretName: defendai-api-key
      tolerations:
        - operator: Exists          # run on all nodes including masters
```

Apply:

```bash
kubectl apply -f daemonset.yaml
```

---

## RBAC

The scanner needs read access to K8s API objects for Layer 3 (K8s API path, when Tetragon is not available):

```yaml
# rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: agent-discover-scanner
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: agent-discover-scanner
rules:
  - apiGroups: [""]
    resources: ["pods", "nodes", "namespaces"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "daemonsets", "replicasets", "statefulsets"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: agent-discover-scanner
subjects:
  - kind: ServiceAccount
    name: agent-discover-scanner
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: agent-discover-scanner
  apiGroup: rbac.authorization.k8s.io
```

```bash
kubectl apply -f rbac.yaml
```

---

## Verifying detection

After deploying, check that Layer 3 is producing findings:

```bash
kubectl logs -n kube-system -l app=agent-discover-scanner -f
```

You should see lines like:

```
[DETECT] AI connection: pod=trading-bot ns=default → api.openai.com:443
Layer 3+: eBPF/Tetragon active (deep network visibility)
```

If you see `Layer 3: Kubernetes API discovery` instead of `eBPF/Tetragon`, Tetragon is not exporting events. Check:

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon
```

---

## Managed clusters (EKS, GKE, AKE)

On managed clusters where eBPF DaemonSets are restricted, use the K8s API fallback. The scanner detects cluster type and falls back automatically. No configuration needed.

For EKS with Bottlerocket nodes, eBPF is supported — follow the standard Tetragon Helm install.

---

## See also

- [Tetragon setup guide](../TETRAGON_SETUP.md)
- [systemd service deployment](../../deployment/systemd/README.md)
- [GitHub Actions integration](github-actions.md)
