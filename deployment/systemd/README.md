# systemd unit for AgentDiscover Scanner daemon

## Prerequisites

- `agent-discover-scanner` installed (e.g. via `pip` or `install.sh`) and available as `/usr/local/bin/agent-discover-scanner`
- Scan target directory: `/opt/defendai/scan-path` (create and populate with repos to scan)
- Cilium Tetragon exporting to `/var/run/cilium/tetragon/tetragon.log` (e.g. k3s with Tetragon)
- Output directory: `/var/log/defendai` (created by the unit’s runtime; ensure the service user can create it or create it beforehand)

## Install

```bash
sudo cp deployment/systemd/agent-discover-scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable agent-discover-scanner
sudo systemctl start agent-discover-scanner
```

## Paths

| Path | Purpose |
|------|--------|
| `/opt/defendai/scan-path` | Directory to scan (Layer 1 code discovery) |
| `/var/log/defendai` | Output dir: layer outputs, `agent_inventory.json`, `daemon.log` |
| `/var/run/cilium/tetragon/tetragon.log` | Tetragon export file for Layer 3 (read each cycle when `--layer3-file` is set) |

For position-tracked tailing of the Tetragon log (no reprocessing across restarts), use the `monitor-k8s --tetragon-export-file` flow; `scan-all --layer3-file` reads the file each correlation cycle.

## Logs

```bash
journalctl -u agent-discover-scanner -f
```

## Customize

Edit the unit or use a drop-in to change:

- `ExecStart`: scan path, `--output`, `--layer3-file`, `--max-log-size`, `--max-log-backups`, `--skip-layers`, etc.
- `User`: run as a non-root user if the scan path and Tetragon log are readable and write paths are writable.
