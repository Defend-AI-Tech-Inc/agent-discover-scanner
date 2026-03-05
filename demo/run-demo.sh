#!/bin/bash
set -e
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
rm -rf ~/demo-results-live

echo "🚀 Running DefendAI live demo scan..."
agent-discover-scanner scan-all ~/projects/agent-discover-scanner/demo/sample-repo \
  --duration 10 \
  --output ~/demo-results-live

cat ~/demo-results-live/agent_inventory.json | python3 -m json.tool
