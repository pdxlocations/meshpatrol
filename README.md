# MeshPatrol
<img width="1197" height="779" alt="Screenshot 2026-03-08 at 9 51 19 PM" src="https://github.com/user-attachments/assets/d3dc0013-9447-4bc5-84e3-e5f70a24833c" />

MeshPatrol is a Meshtastic packet-monitoring bot that:

- runs an embedded `vnode` virtual Meshtastic node and monitors incoming packets
- stores packet payloads using `meshdb`
- tracks per-node and per-packet-type hourly counts in SQLite
- sends a direct message (DM) to nodes that exceed configured thresholds
- serves a dashboard over HTTP (window follows configured threshold unit)

## Requirements

- Python `>=3.11,<3.15`
- Access to a Meshtastic multicast UDP mesh (vnode defaults to `239.0.0.69:4403`), or an optional radio reachable by USB serial or TCP
- Runtime dependencies:
  - `vnode>=0.2.3,<0.3`
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
pip install -e .
```

## Run with Docker

The included Compose setup runs vnode as `MeshPatrol` / `🚨`, stores its identity,
thresholds, and databases in a persistent Docker volume, and serves the dashboard
on port `5050`.

Use a Linux Docker host connected to the multicast mesh for deployment. Compose
uses host networking so vnode can join the LAN multicast group; publishing UDP
port `4403` alone does not provide multicast connectivity. Docker Desktop 4.34+
provides optional [host networking](https://docs.docker.com/engine/network/drivers/host/)
under **Settings → Resources → Network → Enable host networking**, but its network
implementation differs from Linux. Verify LAN multicast reception before relying
on Docker Desktop for monitoring.

```bash
# Build and start in the background
docker compose up -d --build

# View startup messages and packet activity
docker compose logs -f meshpatrol

# Check container status and dashboard health
docker compose ps
```

Open `http://<docker-host-ip>:5050` (or `http://localhost:5050` on the Docker host).
The image runs as UID/GID `10001`, checks `/api/snapshot` for health, and shuts down
with `SIGINT` so vnode closes its sockets and databases cleanly.

The named volume is mounted at `/app/meshpatrol-data`; container rebuilds and
restarts retain the same private key and node ID. Existing host files in
`./meshpatrol-data` are separate from this volume and are not imported automatically.

To change the channel, PSK, multicast settings, or broadcast intervals after the
first startup:

```bash
mkdir -p meshpatrol-data
docker compose cp meshpatrol:/app/meshpatrol-data/node.json ./meshpatrol-data/node.json
# Edit meshpatrol-data/node.json, keeping security.private_key to retain identity.
docker compose exec -T meshpatrol python -c 'from pathlib import Path; import sys; Path("/app/meshpatrol-data/node.json").write_text(sys.stdin.read(), encoding="utf-8")' < ./meshpatrol-data/node.json
docker compose restart meshpatrol
```

The same process works for `thresholds.json`. MeshPatrol reapplies `MeshPatrol` and
`🚨` to the vnode names on every startup.

```bash
# Stop and remove containers; keep the data volume
docker compose down
```

`docker compose down --volumes` also deletes the stored identity and databases.
The build context excludes runtime data and private keys.

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

By default, MeshPatrol starts an embedded [vnode](https://github.com/pdxlocations/vnode)
with long name `MeshPatrol` and short name `🚨`. No serial or TCP connection to a
radio is needed. A gateway must forward mesh traffic to the multicast group for
MeshPatrol to monitor and alert nodes on the radio mesh.

The identity and settings are created in `meshpatrol-data/node.json` on first run.
Edit that file to select the channel name/PSK, multicast group/port, or broadcast
settings. Keep the generated private key to retain the same node identity across
restarts. MeshPatrol applies the requested names each time it starts.

Use one of these optional flags to select a different config or a hardware interface:

```bash
# Use a different vnode identity/config file
python -m meshpatrol --vnode-file ./meshpatrol-data/node.json

# Serial device path
python -m meshpatrol --serial /dev/ttyUSB0

# TCP host:port
python -m meshpatrol --tcp 192.168.1.50:4403

# IPv6 TCP target
python -m meshpatrol --tcp [fe80::1]:4403
```

On startup, MeshPatrol:

- starts vnode, or connects to the optional serial/TCP interface
- subscribes to `meshtastic.receive`
- starts a web dashboard on `0.0.0.0:5050` (by default), accessible from your LAN via `http://<host-ip>:5050`

Stop with `Ctrl+C`.

## Configuration

Runtime settings live in `APP_SETTINGS` in [`meshpatrol/__main__.py`](meshpatrol/__main__.py).
Threshold values are loaded from [`config/thresholds.json`](config/thresholds.json).

```python
APP_SETTINGS = {
    "interface": "vnode",
    "vnode_file": "./meshpatrol-data/node.json",
    "port": None,
    "tcp_hostname": "127.0.0.1",
    "tcp_port": 4403,
    "meshdb_path": "./meshpatrol-data/databases/mesh_packets.db",
    "counter_db_path": "./meshpatrol-data/databases/packet_counters.db",
    "thresholds_path": "./meshpatrol-data/thresholds.json",
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

- `interface`: `"vnode"` (default), `"serial"`, or `"tcp"` (used when no CLI override is provided).
- `vnode_file`: persistent vnode configuration and identity file. Its `meshdb.path` is relative to that file; the default stores vnode data in `meshpatrol-data/data/`.
- `port`: serial device path. Use `None` for Meshtastic auto-detect.
- `tcp_hostname` / `tcp_port`: TCP destination when `interface="tcp"`.
- `thresholds_path`: JSON file for threshold configuration.
- `threshold_unit`: legacy fallback default unit if missing from thresholds JSON (`"hour"` or `"24h"`).
- `default_threshold` / `threshold_overrides`: legacy fallback only, used if `thresholds_path` file is missing.
- `alert_template`: fallback DM text used when the thresholds JSON does not define `default_alert_template`. Supports `{node_id}`, `{packet_type}`, `{count}`, `{threshold}`, `{hour_bucket}`, `{window_label}`, `{threshold_unit}`.
- `web_ui`: enable/disable dashboard.
- `meshdb_path`: SQLite file used by `meshdb` packet storage for serial/TCP. vnode manages its own packet storage using `meshdb.path` in its config.
- `counter_db_path`: SQLite file used for rate counters and alert history.

### Threshold file format

`config/thresholds.json`:

```json
{
  "threshold_unit": "hour",
  "default_threshold": 120,
  "default_alert_template": "MeshPatrol alert: node {node_id} sent {count} packets of type {packet_type} in {window_label}. Please check your settings.",
  "overrides": {
    "POSITION_APP": 300,
    "TELEMETRY_APP": {
      "threshold": 180,
      "unit": "24h"
    },
    "POSITION_REPEATED": {
      "threshold": 1,
      "unit": "24h",
      "alert_template": "MeshPatrol alert: node {node_id} reported the same position {position_repeat_count} times in {window_label}. Please check tracking settings."
    }
  }
}
```

- `threshold_unit`: default unit (`"hour"` or `"24h"`) for entries that do not specify a unit.
- `default_threshold`: fallback threshold value in the default unit for packet types without an override.
- `default_alert_template`: default DM template used for packet types without their own override template.
- `overrides`: per-port thresholds keyed by Meshtastic port name. Each value can be:
  - integer: threshold using default `threshold_unit`
  - object: `{ "threshold": <int>, "unit": "hour" | "24h", "alert_template": "<text>" }` for per-port unit and alert-template override

`POSITION_REPEATED` is a synthetic packet type emitted when the same normalized position is seen 3 times from the same node within a rolling 24-hour window. A threshold of `1` on `POSITION_REPEATED` therefore alerts on the first such repeat event.

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

## Alert Cadence

- `hour` thresholds alert at most once per `node_id + packet_type + UTC hour bucket`
- `24h` thresholds alert at most once per rolling 24-hour window for `node_id + packet_type`
- alerts are only evaluated when a new packet is received, so MeshPatrol does not resend on a timer by itself

## Data files

By default, MeshPatrol creates/updates files in the working-directory `./meshpatrol-data/` folder:

- `./meshpatrol-data/node.json` (vnode settings and persistent private key)
- `./meshpatrol-data/node.public.key` (generated public key)
- `./meshpatrol-data/data/` (vnode packet and node databases)
- `./meshpatrol-data/databases/mesh_packets.<owner_node_num>.db` (serial/TCP packet storage)
- `./meshpatrol-data/databases/packet_counters.db`
- `./meshpatrol-data/thresholds.json`

If WAL mode is active, you may also see `-wal` and `-shm` sidecar files.

## Logging

Logging is controlled by `APP_SETTINGS["log_level"]` and defaults to `INFO`.

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).

Meshtastic® is a registered trademark of Meshtastic LLC. Meshtastic software components are released under various licenses, see GitHub for details. No warranty is provided - use at your own risk.
