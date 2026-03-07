# MeshPatrol

MeshPatrol is a Meshtastic packet-monitoring bot that:

- subscribes to incoming packets from a Meshtastic node (serial or TCP)
- stores packet payloads using `meshdb`
- tracks per-node and per-packet-type hourly counts in SQLite
- sends a direct message (DM) to nodes that exceed configured thresholds
- serves a dashboard over HTTP (window follows configured threshold unit)

## Requirements

- Python `>=3.9,<3.15`
- A Meshtastic-compatible radio reachable by USB serial or Meshtastic TCP
- Runtime dependencies:
  - `meshtastic`
  - `meshdb`
  - `PyPubSub`
  - `Flask`

## Installation

### Install from PyPI (recommended)

```bash
pip install meshpatrol
```

### Install from source

```bash
git clone https://github.com/pdxlocations/meshpatrol.git
cd meshpatrol
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

## Running MeshPatrol

After installation, run:

```bash
meshpatrol
```

You can also run directly as a module:

```bash
python -m meshpatrol
```

### Connection selection (CLI)

Use one of these optional flags to pick the interface at runtime:

```bash
# Serial device path
python -m meshpatrol --serial /dev/ttyUSB0

# TCP host:port
python -m meshpatrol --tcp 192.168.1.50:4403

# IPv6 TCP target
python -m meshpatrol --tcp [fe80::1]:4403
```

On startup, MeshPatrol:

- connects to your Meshtastic interface (`SerialInterface` or `TCPInterface`)
- subscribes to `meshtastic.receive`
- starts a web dashboard on `0.0.0.0:5050` (by default), accessible from your LAN via `http://<host-ip>:5050`

Stop with `Ctrl+C`.

## Configuration

Runtime settings live in `APP_SETTINGS` in [`meshpatrol/__main__.py`](meshpatrol/__main__.py).
Threshold values are loaded from [`config/thresholds.json`](config/thresholds.json).

```python
APP_SETTINGS = {
    "interface": "serial",
    "port": None,
    "tcp_hostname": "127.0.0.1",
    "tcp_port": 4403,
    "meshdb_path": "./meshpatrol/databases/mesh_packets.db",
    "counter_db_path": "./meshpatrol/databases/packet_counters.db",
    "thresholds_path": "./meshpatrol/thresholds.json",
    "threshold_unit": "hour",
    "default_threshold": 120,
    "threshold_overrides": [],
    "alert_template": "...",
    "log_level": "INFO",
    "web_ui": True,
    "web_host": "0.0.0.0",
    "web_port": 5050,
}
```

### Key settings

- `interface`: `"serial"` or `"tcp"` (used when no CLI override is provided).
- `port`: serial device path. Use `None` for Meshtastic auto-detect.
- `tcp_hostname` / `tcp_port`: TCP destination when `interface="tcp"`.
- `thresholds_path`: JSON file for threshold configuration.
- `threshold_unit`: legacy fallback default unit if missing from thresholds JSON (`"hour"` or `"24h"`).
- `default_threshold` / `threshold_overrides`: legacy fallback only, used if `thresholds_path` file is missing.
- `alert_template`: DM text. Supports `{node_id}`, `{packet_type}`, `{count}`, `{threshold}`, `{hour_bucket}`, `{window_label}`, `{threshold_unit}`.
- `web_ui`: enable/disable dashboard.
- `meshdb_path`: SQLite file used by `meshdb` packet storage.
- `counter_db_path`: SQLite file used for rate counters and alert history.

### Threshold file format

`config/thresholds.json`:

```json
{
  "threshold_unit": "hour",
  "default_threshold": 120,
  "overrides": {
    "POSITION_APP": 300,
    "TELEMETRY_APP": {
      "threshold": 180,
      "unit": "24h"
    }
  }
}
```

- `threshold_unit`: default unit (`"hour"` or `"24h"`) for entries that do not specify a unit.
- `default_threshold`: fallback threshold value in the default unit for packet types without an override.
- `overrides`: per-port thresholds keyed by Meshtastic port name. Each value can be:
  - integer: threshold using default `threshold_unit`
  - object: `{ "threshold": <int>, "unit": "hour" | "24h" }` for per-port unit override

## Dashboard and API

When `web_ui` is enabled, MeshPatrol serves:

- `GET /` - HTML dashboard
- `GET /api/snapshot` - JSON snapshot for the active threshold windows (hour, 24h, or mixed)

Dashboard includes:

- top nodes by packet count (active window)
- totals by packet type (active window)
- configured thresholds
- node+type breakdown with ETA to threshold (per-port threshold unit)
- recent alerts (active window)

## Data files

By default, MeshPatrol creates/updates files in the working-directory `./meshpatrol/` folder:

- `./meshpatrol/databases/mesh_packets.<owner_node_num>.db` (created by `meshdb`)
- `./meshpatrol/databases/packet_counters.db`
- `./meshpatrol/thresholds.json`

If WAL mode is active, you may also see `-wal` and `-shm` sidecar files.

## Logging

Logging is controlled by `APP_SETTINGS["log_level"]` and defaults to `INFO`.

## Development

Install editable with dependencies:

```bash
pip install -e .
```

Run directly:

```bash
python -m meshpatrol
```

## Release process

This repository includes a GitHub Actions workflow at `.github/workflows/release.yaml` that:

1. triggers on semantic version tags (for example: `1.2.3`, `1.2.3rc1`)
2. checks the new tag version is greater than the latest on PyPI
3. builds with Poetry
4. publishes artifacts to PyPI
5. creates a GitHub Release with generated notes

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).
