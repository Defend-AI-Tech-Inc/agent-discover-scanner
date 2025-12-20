# Usage Examples

## Basic Scanning

### Scan a Single Project
```bash
# Simple scan
agent-discover-scanner scan ~/projects/my-ai-app

# With verbose output
agent-discover-scanner scan ~/projects/my-ai-app --verbose
```

### Scan Multiple Projects
```bash
# Scan all repos in a directory
for dir in ~/projects/*/; do
  echo "Scanning $dir..."
  agent-discover-scanner scan "$dir" --format sarif --output "$(basename $dir).sarif"
done
```

## CI/CD Integration

### GitHub Actions
```yaml
name: AI Agent Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Scanner
        run: |
          pip install uv
          uv tool install agent-discover-scanner
      
      - name: Scan for Agents
        run: |
          agent-discover-scanner scan . --format sarif --output results.sarif
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      
      - name: Fail on Critical Findings
        run: |
          # Check if we have critical (error) findings
          if grep -q '"level": "error"' results.sarif; then
            echo "❌ Critical security findings detected"
            exit 1
          fi
```

### GitLab CI
```yaml
agent_scan:
  stage: security
  image: python:3.12
  script:
    - pip install uv
    - uv tool install agent-discover-scanner
    - agent-discover-scanner scan . --format sarif --output results.sarif
  artifacts:
    reports:
      sast: results.sarif
```

## Advanced Usage

### Full Security Audit
```bash
#!/bin/bash
# complete-audit.sh

PROJECT_DIR="/path/to/project"
OUTPUT_DIR="./scan-results"

mkdir -p "$OUTPUT_DIR"

echo "1/4: Scanning code..."
agent-discover-scanner scan "$PROJECT_DIR" \
  --format both \
  --output "$OUTPUT_DIR/code-scan.sarif"

echo "2/4: Scanning dependencies..."
agent-discover-scanner deps "$PROJECT_DIR" \
  --verbose > "$OUTPUT_DIR/deps-report.txt"

echo "3/4: Monitoring network (5 minutes)..."
agent-discover-scanner monitor \
  --duration 300 \
  --output "$OUTPUT_DIR/network-activity.json"

echo "4/4: Correlating findings..."
agent-discover-scanner correlate \
  --code-scan "$OUTPUT_DIR/code-scan.sarif" \
  --network-scan "$OUTPUT_DIR/network-activity.json" \
  --output "$OUTPUT_DIR/final-inventory.json"

echo "✅ Audit complete! Results in $OUTPUT_DIR/"
```

## Filtering Results

### Show Only Critical Findings
```bash
agent-discover-scanner scan . --format sarif --output results.sarif
cat results.sarif | jq '.runs[0].results[] | select(.level == "error")'
```

### Show Only Shadow AI
```bash
agent-discover-scanner scan . --verbose | grep "DAI004"
```

### Count Agents by Framework
```bash
agent-discover-scanner scan . --verbose 2>&1 | \
  grep -E "(DAI001|DAI002|DAI003)" | \
  cut -d: -f3 | \
  sort | uniq -c
```

## Real-World Scenarios

### Scenario 1: Developer Onboarding Check
```bash
# Ensure new developer's laptop has no Shadow AI
agent-discover-scanner scan ~/code --format table
```

### Scenario 2: Pre-Deployment Scan
```bash
# In your deploy script
if agent-discover-scanner scan . | grep -q "DAI004"; then
  echo "❌ Deployment blocked: Shadow AI detected"
  echo "Route all LLM traffic through DefendAI Gateway"
  exit 1
fi
```

### Scenario 3: Weekly Security Report
```bash
#!/bin/bash
# weekly-report.sh

DATE=$(date +%Y-%m-%d)
REPOS=(
  "/repos/backend"
  "/repos/frontend"
  "/repos/ml-service"
)

for repo in "${REPOS[@]}"; do
  agent-discover-scanner scan "$repo" \
    --output "report-$(basename $repo)-$DATE.sarif"
done

# Email results to security team
# ... email logic here
```
