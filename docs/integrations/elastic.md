# Using AgentDiscover Scanner with Elastic / Kibana

Forward scan results to Elasticsearch for AI agent dashboards, alerting, and long-term audit storage.

---

## Overview

AgentDiscover Scanner writes structured JSON to `defendai-results/`. Two integration paths:

1. **Filebeat** — watch the output directory and ship to Elasticsearch (recommended for daemon mode)
2. **Direct API** — POST scan results to Elasticsearch after each scan (simpler for one-shot scans)

---

## Option 1 — Filebeat

### 1. Run the scanner in daemon mode

```bash
agent-discover-scanner scan-all ~/projects \
  --daemon \
  --output /var/log/agent-discover \
  --duration 30
```

### 2. Configure Filebeat

```yaml
# /etc/filebeat/filebeat.yml

filebeat.inputs:
  - type: filestream
    id: agent-discover-inventory
    paths:
      - /var/log/agent-discover/agent_inventory.json
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
    tags: ["agent_discover", "inventory"]

  - type: filestream
    id: agent-discover-history
    paths:
      - /var/log/agent-discover/agent_inventory_history.jsonl
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
    tags: ["agent_discover", "history"]

  - type: filestream
    id: agent-discover-network
    paths:
      - /var/log/agent-discover/layer2_network.json
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
    tags: ["agent_discover", "network"]

output.elasticsearch:
  hosts: ["https://your-elasticsearch:9200"]
  username: "${ES_USERNAME}"
  password: "${ES_PASSWORD}"
  index: "agent-discover-%{+yyyy.MM.dd}"

setup.kibana:
  host: "https://your-kibana:5601"
```

### 3. Create the index template

```bash
curl -X PUT "https://elasticsearch:9200/_index_template/agent-discover" \
  -H "Content-Type: application/json" \
  -u elastic:password \
  -d '{
    "index_patterns": ["agent-discover-*"],
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 1
      },
      "mappings": {
        "properties": {
          "generated_at":    { "type": "date" },
          "timestamp":       { "type": "date" },
          "summary.ghost":   { "type": "integer" },
          "summary.confirmed": { "type": "integer" },
          "summary.unknown": { "type": "integer" }
        }
      }
    }
  }'
```

---

## Option 2 — Direct Elasticsearch API

For simpler setups or one-shot scans:

```bash
agent-discover-scanner scan-all ~/projects \
  --duration 30 \
  --output /tmp/agent-scan

# Index the inventory document
curl -X POST "https://elasticsearch:9200/agent-discover/_doc" \
  -H "Content-Type: application/json" \
  -u elastic:password \
  -d @/tmp/agent-scan/agent_inventory.json
```

---

## Kibana queries

**GHOST agents in the last 7 days:**

```
tags: "agent_discover" AND tags: "history" AND summary.ghost > 0
```

**High-risk agent inventory:**

```
tags: "agent_discover" AND tags: "inventory" AND inventory.confirmed.risk_level: (critical OR high)
```

**Network connections to AI providers:**

```
tags: "agent_discover" AND tags: "network" AND connections.service: *
```

---

## Alerting

Create a Kibana alerting rule on:

```
tags: "agent_discover" AND summary.ghost > 0
```

Action: notify Slack, email, or PagerDuty when the first GHOST agent is detected.

---

## Kibana dashboard

Build a dashboard with:

1. **GHOST count over time** — line chart on `summary.ghost`
2. **Classification breakdown** — pie chart on confirmed / unknown / shadow_ai / zombie
3. **Top SaaS providers** — aggregation on `network.connections.service`
4. **Risk score distribution** — histogram on agent risk scores

---

## See also

- [Splunk integration](splunk.md)
- [GitHub Actions integration](github-actions.md)
