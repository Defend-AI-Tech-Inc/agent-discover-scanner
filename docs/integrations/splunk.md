# Using AgentDiscover Scanner with Splunk

Forward scan results to Splunk for continuous AI agent monitoring, dashboards, and alerting.

---

## Overview

AgentDiscover Scanner outputs structured JSON at every scan. The recommended pattern for Splunk integration is:

1. Run the scanner in daemon mode, writing output to `defendai-results/`
2. Configure Splunk Universal Forwarder (or HEC) to ingest the JSON files
3. Use the agent inventory and history JSONL for dashboards and alerts

---

## Option 1 — Splunk HTTP Event Collector (HEC)

The simplest integration: post scan results directly to Splunk HEC after each scan.

```bash
# Run a scan and POST results to Splunk HEC
agent-discover-scanner scan-all ~/projects \
  --duration 30 \
  --output /tmp/agent-scan

INVENTORY=$(cat /tmp/agent-scan/agent_inventory.json)
curl -k "https://splunk.example.com:8088/services/collector/event" \
  -H "Authorization: Splunk YOUR_HEC_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"sourcetype\": \"agent_discover:inventory\", \"event\": $INVENTORY}"
```

Wrap this in a cron job for periodic scans:

```bash
# /etc/cron.d/agent-discover-splunk
*/30 * * * * agent-discover-scanner scan-all /opt/apps --duration 30 --output /tmp/agent-scan && \
  curl -sk "https://splunk.example.com:8088/services/collector/event" \
  -H "Authorization: Splunk YOUR_HEC_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"sourcetype\":\"agent_discover:inventory\",\"event\":$(cat /tmp/agent-scan/agent_inventory.json)}"
```

---

## Option 2 — Splunk Universal Forwarder

For continuous daemon mode, configure the Universal Forwarder to watch the output directory.

**1. Run daemon mode:**

```bash
agent-discover-scanner scan-all ~/projects \
  --daemon \
  --output /var/log/agent-discover \
  --duration 30
```

**2. Configure inputs.conf:**

```ini
# /opt/splunkforwarder/etc/system/local/inputs.conf

[monitor:///var/log/agent-discover/agent_inventory.json]
disabled = false
sourcetype = agent_discover:inventory
index = ai_security

[monitor:///var/log/agent-discover/agent_inventory_history.jsonl]
disabled = false
sourcetype = agent_discover:history
index = ai_security

[monitor:///var/log/agent-discover/layer2_network.json]
disabled = false
sourcetype = agent_discover:network
index = ai_security
```

**3. Configure props.conf for JSON parsing:**

```ini
# /opt/splunkforwarder/etc/system/local/props.conf

[agent_discover:inventory]
KV_MODE = json
TIMESTAMP_FIELDS = generated_at
TIME_FORMAT = %Y-%m-%dT%H:%M:%S

[agent_discover:history]
KV_MODE = json
TIMESTAMP_FIELDS = timestamp
TIME_FORMAT = %Y-%m-%dT%H:%M:%S

[agent_discover:network]
KV_MODE = json
```

---

## Useful Splunk searches

**GHOST agents detected in the last 24 hours:**

```spl
index=ai_security sourcetype=agent_discover:history ghost>0
| table timestamp ghost confirmed unknown
| sort -timestamp
```

**Agents by classification over time:**

```spl
index=ai_security sourcetype=agent_discover:history
| timechart span=1h max(confirmed) as Confirmed max(ghost) as Ghost max(unknown) as Unknown
```

**High-risk agents:**

```spl
index=ai_security sourcetype=agent_discover:inventory
| spath input=event path=inventory.confirmed{}
| mvexpand inventory.confirmed{}
| spath input=inventory.confirmed{} path=risk_level
| where risk_level="critical" OR risk_level="high"
| table _time agent_id risk_level framework saas_connections{}
```

**Network connections to AI providers:**

```spl
index=ai_security sourcetype=agent_discover:network
| spath input=event path=connections{}
| mvexpand connections{}
| spath input=connections{} path=service
| stats count by service, process
| sort -count
```

---

## Alerting

**Alert on first GHOST detection:**

```spl
index=ai_security sourcetype=agent_discover:history ghost>0
| stats earliest(_time) as first_seen by host
| where first_seen > relative_time(now(), "-1h@h")
```

Set this as a real-time alert with action: send email or trigger a webhook to your incident management system.

**Alert on new AI frameworks:**

```spl
index=ai_security sourcetype=agent_discover:inventory
| spath input=event path=inventory.unknown{}
| mvexpand inventory.unknown{}
| spath input=inventory.unknown{} path=agent_id
| stats dc(agent_id) as new_agents by host
| where new_agents > 0
```

---

## Dashboard

Import `docs/splunk-dashboard.xml` (when available) for a pre-built AI agent governance dashboard showing:
- GHOST agent timeline
- Agent classification breakdown
- SaaS blast radius by agent
- Network connection activity
