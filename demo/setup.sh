#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "🚀 DefendAI Demo Environment Setup"
echo "===================================="

# Check OrbStack/multipass VM is running
echo "✓ Checking environment..."
kubectl cluster-info &>/dev/null || { echo "❌ kubectl not connected. Run inside VM."; exit 1; }

# Ensure kubernetes client available for scanner (pipx installs)
echo "✓ Ensuring kubernetes client for agent-discover-scanner..."
pipx inject agent-discover-scanner kubernetes 2>/dev/null || true

# Install Tetragon
echo "📦 Installing Tetragon..."
helm repo add cilium https://helm.cilium.io 2>/dev/null || true
helm repo update
helm upgrade --install tetragon cilium/tetragon \
  --namespace kube-system \
  --wait --timeout 120s

# Apply TracingPolicy
echo "🔍 Applying network TracingPolicy..."
cat <<EOF | kubectl apply -f -
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: tcp-connect-syscall
spec:
  tracepoints:
  - subsystem: "sock"
    event: "inet_sock_set_state"
    args:
    - index: 0
      type: "sock"
    - index: 1
      type: "int"
    - index: 2
      type: "int"
    selectors:
    - matchArgs:
      - index: 2
        operator: "Equal"
        values:
        - "1"
EOF

# Fix permissions
chmod 644 /var/run/cilium/tetragon/tetragon.log 2>/dev/null || true

# Deploy demo agents
echo "🤖 Deploying demo AI agents..."
kubectl apply -f k8s/
kubectl rollout status deployment/langchain-agent --timeout=120s
kubectl rollout status deployment/crewai-agent --timeout=120s
kubectl rollout status deployment/shadow-agent --timeout=120s

echo ""
echo "✅ Demo environment ready!"
echo ""
echo "Now run on your Mac:"
echo "  agent-discover-scanner scan-all ./sample-repo --duration 60"
echo ""
echo "Expected results:"
echo "  CONFIRMED: langchain-agent (code + network + eBPF)"
echo "  CONFIRMED: crewai-agent (code + network + eBPF)"
echo "  GHOST:     shadow-agent (network + eBPF, NO code) ← CRITICAL"
