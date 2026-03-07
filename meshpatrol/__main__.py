#!/usr/bin/env python3
"""Meshtastic packet monitor bot.

Features:
- Subscribes to incoming Meshtastic packets.
- Persists packet payloads using the meshdb library when available.
- Tracks per-node, per-packet-type hourly counts in a local SQLite database.
- Sends a DM when a packet type threshold per hour is reached.
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

APP_WORK_DIR = Path.cwd() / "meshpatrol-data"
APP_DB_DIR = APP_WORK_DIR / "databases"

APP_SETTINGS: dict[str, Any] = {
    # Interface type: "serial" or "tcp".
    "interface": "serial",
    # Meshtastic serial device path. Use None for default auto-detected device.
    "port": None,
    # Meshtastic TCP target (used when interface == "tcp").
    "tcp_hostname": "127.0.0.1",
    "tcp_port": 4403,
    "meshdb_path": str(APP_DB_DIR / "mesh_packets.db"),
    "counter_db_path": str(APP_DB_DIR / "packet_counters.db"),
    # Ignore packets originating from the connected/local node for counters/alerts.
    "ignore_connected_node": True,
    # Threshold config JSON path. Example schema:
    # {
    #   "default_threshold": 120,
    #   "overrides": {
    #     "POSITION_APP": 300,
    #     "TELEMETRY_APP": 180
    #   }
    # }
    "thresholds_path": str(APP_WORK_DIR / "thresholds.json"),
    # Legacy fallback settings used only if thresholds_path is missing/unreadable.
    "threshold_unit": "hour",  # "hour" or "24h"
    "default_threshold": 120,
    # Optional per-packet-type legacy overrides: ["POSITION_APP=300", "TELEMETRY_APP=180"]
    "threshold_overrides": [],
    "alert_template": (
        "MeshPatrol alert: node {node_id} sent {count} packets of type "
        "{packet_type} in {window_label} ending {hour_bucket} "
        "(threshold {threshold} per {threshold_unit}). "
        "Please check your {packet_type} settings."
    ),
    "log_level": "INFO",
    "web_ui": True,
    "web_host": "0.0.0.0",
    "web_port": 5050,
}

VALID_THRESHOLD_UNITS = {"hour", "24h"}
FALLBACK_PORTNUMS: tuple[str, ...] = (
    "UNKNOWN_APP",
    "TEXT_MESSAGE_APP",
    "REMOTE_HARDWARE_APP",
    "POSITION_APP",
    "NODEINFO_APP",
    "ROUTING_APP",
    "ADMIN_APP",
    "TEXT_MESSAGE_COMPRESSED_APP",
    "WAYPOINT_APP",
    "AUDIO_APP",
    "DETECTION_SENSOR_APP",
    "ALERT_APP",
    "KEY_VERIFICATION_APP",
    "REPLY_APP",
    "IP_TUNNEL_APP",
    "PAXCOUNTER_APP",
    "STORE_FORWARD_PLUSPLUS_APP",
    "NODE_STATUS_APP",
    "SERIAL_APP",
    "STORE_FORWARD_APP",
    "RANGE_TEST_APP",
    "TELEMETRY_APP",
    "ZPS_APP",
    "SIMULATOR_APP",
    "TRACEROUTE_APP",
    "NEIGHBORINFO_APP",
    "ATAK_PLUGIN",
    "MAP_REPORT_APP",
    "POWERSTRESS_APP",
    "RETICULUM_TUNNEL_APP",
    "CAYENNE_APP",
    "PRIVATE_APP",
    "ATAK_FORWARDER",
)


def parse_tcp_target(value: str) -> tuple[str, int]:
    target = value.strip()
    if not target:
        raise ValueError("TCP target cannot be empty")

    host = ""
    port_str = ""
    if target.startswith("["):
        end = target.find("]")
        if end == -1 or end + 1 >= len(target) or target[end + 1] != ":":
            raise ValueError("TCP target must be in format [host]:port")
        host = target[1:end].strip()
        port_str = target[end + 2 :].strip()
    else:
        if ":" not in target:
            raise ValueError("TCP target must be in format host:port")
        host, port_str = target.rsplit(":", 1)
        host = host.strip()
        port_str = port_str.strip()

    if not host:
        raise ValueError("TCP host is empty")
    try:
        port = int(port_str)
    except ValueError as exc:
        raise ValueError("TCP port must be an integer") from exc
    if port <= 0:
        raise ValueError("TCP port must be > 0")

    return host, port


def parse_cli_overrides(argv: list[str] | None = None) -> dict[str, Any]:
    parser = argparse.ArgumentParser(description="MeshPatrol packet monitor")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--serial",
        metavar="DEVPATH",
        help="Use serial interface with selected device path",
    )
    group.add_argument(
        "--tcp",
        metavar="HOST:PORT",
        help="Use TCP interface with host and port (example: 192.168.1.50:4403)",
    )

    args = parser.parse_args(argv)
    overrides: dict[str, Any] = {}

    if args.serial:
        overrides["interface"] = "serial"
        overrides["port"] = str(args.serial).strip()
    if args.tcp:
        host, port = parse_tcp_target(str(args.tcp))
        overrides["interface"] = "tcp"
        overrides["tcp_hostname"] = host
        overrides["tcp_port"] = port

    return overrides


def utc_hour_bucket(ts: datetime | None = None) -> str:
    now = ts or datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:00:00Z")


def local_hour_bucket(ts: datetime | None = None) -> str:
    now = ts or datetime.now(UTC)
    local_now = now.astimezone()
    local_hour = local_now.replace(minute=0, second=0, microsecond=0)
    return local_hour.strftime("%Y-%m-%d %H:00:00 %Z")


def iso_to_local_text(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return ""

    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return str(value or "")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def normalize_threshold_unit(value: Any) -> str:
    text = str(value or "").strip().lower()
    aliases = {
        "hour": "hour",
        "per_hour": "hour",
        "1h": "hour",
        "24h": "24h",
        "24hr": "24h",
        "24hours": "24h",
        "per_24h": "24h",
    }
    normalized = aliases.get(text, text)
    if normalized not in VALID_THRESHOLD_UNITS:
        raise ValueError("threshold_unit must be 'hour' or '24h'")
    return normalized


def packet_type_of(packet: dict[str, Any]) -> str:
    decoded = packet.get("decoded") or {}
    portnum = decoded.get("portnum") or packet.get("portnum")
    if isinstance(portnum, str) and portnum:
        return portnum
    if portnum is not None:
        return str(portnum)
    if packet.get("encrypted"):
        return "ENCRYPTED"
    if packet.get("channel") is not None and decoded:
        return "DECODED_UNKNOWN"
    return "UNKNOWN"


def node_id_of(packet: dict[str, Any]) -> str:
    from_id = packet.get("fromId") or packet.get("from")
    if from_id is None:
        return "UNKNOWN_NODE"
    return str(from_id)


def int_from_node_id(node_id: Any) -> int | None:
    if node_id is None:
        return None
    if isinstance(node_id, int):
        return node_id
    text = str(node_id).strip()
    if not text:
        return None
    had_bang_prefix = text.startswith("!")
    if had_bang_prefix:
        text = text[1:]
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if had_bang_prefix:
            return int(text, 16)
        return int(text)
    except ValueError:
        try:
            # Fallback for hex strings without 0x prefix.
            return int(text, 16)
        except ValueError:
            return None


def parse_thresholds(items: list[str], default: int) -> dict[str, int]:
    thresholds: dict[str, int] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"Bad threshold '{item}'. Expected format TYPE=COUNT")
        pkt_type, count_str = item.split("=", 1)
        pkt_type = pkt_type.strip()
        if not pkt_type:
            raise ValueError(f"Bad threshold '{item}'. Packet type is empty")
        try:
            count = int(count_str.strip())
        except ValueError as exc:
            raise ValueError(f"Bad threshold '{item}'. COUNT must be an integer") from exc
        if count <= 0:
            raise ValueError(f"Bad threshold '{item}'. COUNT must be > 0")
        thresholds[pkt_type] = count

    thresholds["*"] = thresholds.get("*", default)
    return thresholds


def parse_threshold_overrides(
    overrides: dict[str, Any],
    *,
    default: int,
    default_unit: str,
) -> tuple[dict[str, int], dict[str, str]]:
    thresholds: dict[str, int] = {}
    threshold_units: dict[str, str] = {}
    normalized_default_unit = normalize_threshold_unit(default_unit)
    for packet_type, override_value in overrides.items():
        pkt_type = str(packet_type).strip()
        if not pkt_type:
            raise ValueError("Threshold overrides cannot contain an empty packet type")
        count_raw: Any = override_value
        unit_raw: Any = normalized_default_unit
        if isinstance(override_value, dict):
            count_raw = override_value.get("threshold", override_value.get("count"))
            unit_raw = override_value.get("unit", normalized_default_unit)
        try:
            count = int(count_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Threshold override for '{pkt_type}' must be an integer") from exc
        if count <= 0:
            raise ValueError(f"Threshold override for '{pkt_type}' must be > 0")
        thresholds[pkt_type] = count
        threshold_units[pkt_type] = normalize_threshold_unit(unit_raw)

    thresholds["*"] = thresholds.get("*", default)
    threshold_units["*"] = threshold_units.get("*", normalized_default_unit)
    return thresholds, threshold_units


def load_threshold_settings(
    *,
    path: Path,
    fallback_default: int,
    fallback_overrides: list[str],
    fallback_threshold_unit: str,
) -> tuple[int, dict[str, int], str, dict[str, str]]:
    if not path.exists():
        logging.warning(
            "Thresholds file not found at %s; using legacy APP_SETTINGS thresholds",
            path,
        )
        default_threshold = int(fallback_default)
        thresholds = parse_thresholds(fallback_overrides, default_threshold)
        threshold_unit = normalize_threshold_unit(fallback_threshold_unit)
        threshold_units = {key: threshold_unit for key in thresholds}
        return default_threshold, thresholds, threshold_unit, threshold_units

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Failed to read thresholds file {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"Thresholds file {path} must contain a JSON object")

    default_raw = payload.get("default_threshold", fallback_default)
    try:
        default_threshold = int(default_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("default_threshold must be an integer") from exc
    if default_threshold <= 0:
        raise ValueError("default_threshold must be > 0")

    overrides_raw = payload.get("overrides", {})
    if not isinstance(overrides_raw, dict):
        raise ValueError("overrides must be an object map of TYPE to COUNT")

    threshold_unit = normalize_threshold_unit(
        payload.get("threshold_unit", fallback_threshold_unit)
    )
    thresholds, threshold_units = parse_threshold_overrides(
        overrides_raw,
        default=default_threshold,
        default_unit=threshold_unit,
    )
    return default_threshold, thresholds, threshold_unit, threshold_units


def _all_portnums() -> list[str]:
    try:
        from meshtastic.protobuf import portnums_pb2  # type: ignore
    except Exception:
        return list(FALLBACK_PORTNUMS)

    return [v.name for v in portnums_pb2._PORTNUM.values if v.name != "MAX"]


def _load_thresholds_example_template() -> dict[str, Any] | None:
    candidate_paths = (
        Path.cwd() / "meshpatrol" / "thresholds-example.json",
        Path(__file__).resolve().with_name("thresholds-example.json"),
        Path.cwd() / "config" / "thresholds-example.json",
        Path.cwd() / "thresholds-example.json",
    )
    for candidate in candidate_paths:
        if not candidate.exists():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            return payload
    return None


def ensure_thresholds_file(path: Path, *, default_threshold: int, default_unit: str) -> None:
    if path.exists():
        return
    template = _load_thresholds_example_template()
    if template is None:
        unit = normalize_threshold_unit(default_unit)
        threshold_value = int(default_threshold)
        if threshold_value <= 0:
            threshold_value = 120
        template = {
            "threshold_unit": unit,
            "default_threshold": threshold_value,
            "overrides": {name: threshold_value for name in _all_portnums()},
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(template, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    logging.info("Created default thresholds file at %s", path)


class PacketCounterDB:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_schema()
        self._normalize_existing_node_ids()

    def _create_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS packet_hourly_counts (
                node_id TEXT NOT NULL,
                packet_type TEXT NOT NULL,
                hour_bucket TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                last_seen_utc TEXT NOT NULL,
                alerted_utc TEXT,
                PRIMARY KEY (node_id, packet_type, hour_bucket)
            );

            CREATE INDEX IF NOT EXISTS idx_packet_hourly_counts_hour
                ON packet_hourly_counts (hour_bucket);

            CREATE TABLE IF NOT EXISTS bot_alert_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT NOT NULL,
                packet_type TEXT NOT NULL,
                hour_bucket TEXT NOT NULL,
                count_at_alert INTEGER NOT NULL,
                alert_utc TEXT NOT NULL,
                message TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    @staticmethod
    def _canonical_node_id(node_id: Any) -> str:
        as_int = int_from_node_id(node_id)
        if as_int is not None:
            return str(as_int)
        return str(node_id or "").strip()

    def _normalize_existing_node_ids(self) -> None:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT node_id, packet_type, hour_bucket, count, last_seen_utc, alerted_utc
                FROM packet_hourly_counts
                """
            ).fetchall()
            if not rows:
                return

            remap: dict[str, str] = {}
            touched = 0
            for row in rows:
                old_node_id = str(row["node_id"] or "").strip()
                new_node_id = self._canonical_node_id(old_node_id)
                if not old_node_id or not new_node_id or old_node_id == new_node_id:
                    continue
                remap[old_node_id] = new_node_id
                self._conn.execute(
                    """
                    INSERT INTO packet_hourly_counts
                        (node_id, packet_type, hour_bucket, count, last_seen_utc, alerted_utc)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(node_id, packet_type, hour_bucket)
                    DO UPDATE SET
                        count = packet_hourly_counts.count + excluded.count,
                        last_seen_utc = CASE
                            WHEN excluded.last_seen_utc > packet_hourly_counts.last_seen_utc
                            THEN excluded.last_seen_utc
                            ELSE packet_hourly_counts.last_seen_utc
                        END,
                        alerted_utc = CASE
                            WHEN packet_hourly_counts.alerted_utc IS NULL THEN excluded.alerted_utc
                            WHEN excluded.alerted_utc IS NULL THEN packet_hourly_counts.alerted_utc
                            WHEN excluded.alerted_utc > packet_hourly_counts.alerted_utc
                            THEN excluded.alerted_utc
                            ELSE packet_hourly_counts.alerted_utc
                        END
                    """,
                    (
                        new_node_id,
                        str(row["packet_type"]),
                        str(row["hour_bucket"]),
                        int(row["count"]),
                        str(row["last_seen_utc"]),
                        row["alerted_utc"],
                    ),
                )
                self._conn.execute(
                    """
                    DELETE FROM packet_hourly_counts
                    WHERE node_id = ? AND packet_type = ? AND hour_bucket = ?
                    """,
                    (
                        old_node_id,
                        str(row["packet_type"]),
                        str(row["hour_bucket"]),
                    ),
                )
                touched += 1

            for old_node_id, new_node_id in remap.items():
                self._conn.execute(
                    """
                    UPDATE bot_alert_history
                    SET node_id = ?
                    WHERE node_id = ?
                    """,
                    (new_node_id, old_node_id),
                )

            if touched > 0:
                self._conn.commit()
                logging.info("Normalized %d counter rows to canonical node IDs", touched)

    def increment_and_fetch(
        self,
        *,
        node_id: str,
        packet_type: str,
        hour_bucket: str,
        seen_utc: str,
    ) -> int:
        canonical_node_id = self._canonical_node_id(node_id)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO packet_hourly_counts
                    (node_id, packet_type, hour_bucket, count, last_seen_utc)
                VALUES (?, ?, ?, 1, ?)
                ON CONFLICT(node_id, packet_type, hour_bucket)
                DO UPDATE SET
                    count = count + 1,
                    last_seen_utc = excluded.last_seen_utc
                """,
                (canonical_node_id, packet_type, hour_bucket, seen_utc),
            )
            row = self._conn.execute(
                """
                SELECT count
                FROM packet_hourly_counts
                WHERE node_id = ? AND packet_type = ? AND hour_bucket = ?
                """,
                (canonical_node_id, packet_type, hour_bucket),
            ).fetchone()
            self._conn.commit()
            return int(row[0]) if row else 0

    def mark_alerted(
        self,
        *,
        node_id: str,
        packet_type: str,
        hour_bucket: str,
        message: str,
        count_at_alert: int,
        alerted_utc: str,
    ) -> None:
        canonical_node_id = self._canonical_node_id(node_id)
        with self._lock:
            self._conn.execute(
                """
                UPDATE packet_hourly_counts
                SET alerted_utc = ?
                WHERE node_id = ? AND packet_type = ? AND hour_bucket = ?
                """,
                (alerted_utc, canonical_node_id, packet_type, hour_bucket),
            )
            self._conn.execute(
                """
                INSERT INTO bot_alert_history
                    (node_id, packet_type, hour_bucket, count_at_alert, alert_utc, message)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    canonical_node_id,
                    packet_type,
                    hour_bucket,
                    count_at_alert,
                    alerted_utc,
                    message,
                ),
            )
            self._conn.commit()

    def was_alerted(
        self,
        *,
        node_id: str,
        packet_type: str,
        hour_bucket: str,
    ) -> bool:
        canonical_node_id = self._canonical_node_id(node_id)
        row = self._conn.execute(
            """
            SELECT alerted_utc
            FROM packet_hourly_counts
            WHERE node_id = ? AND packet_type = ? AND hour_bucket = ?
            """,
            (canonical_node_id, packet_type, hour_bucket),
        ).fetchone()
        return bool(row and row[0])

    def count_since(
        self,
        *,
        node_id: str,
        packet_type: str,
        since_utc: str,
    ) -> int:
        canonical_node_id = self._canonical_node_id(node_id)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COALESCE(SUM(count), 0)
                FROM packet_hourly_counts
                WHERE node_id = ? AND packet_type = ? AND last_seen_utc >= ?
                """,
                (canonical_node_id, packet_type, since_utc),
            ).fetchone()
            return int(row[0]) if row else 0

    def was_alerted_since(
        self,
        *,
        node_id: str,
        packet_type: str,
        since_utc: str,
    ) -> bool:
        canonical_node_id = self._canonical_node_id(node_id)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT 1
                FROM bot_alert_history
                WHERE node_id = ? AND packet_type = ? AND alert_utc >= ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (canonical_node_id, packet_type, since_utc),
            ).fetchone()
            return bool(row)

    def close(self) -> None:
        self._conn.close()

    def dashboard_snapshot(
        self,
        since_utc: str,
        one_hour_since_utc: str,
        max_rows: int = 50,
        exclude_node_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        limit = max(1, min(max_rows, 500))
        node_filter = ""
        args_prefix: tuple[Any, ...] = (since_utc,)
        exclude_ids = [
            self._canonical_node_id(v)
            for v in (exclude_node_ids or [])
            if str(v).strip()
        ]
        if exclude_ids:
            placeholders = ",".join(["?"] * len(exclude_ids))
            node_filter = f" AND node_id NOT IN ({placeholders})"
            args_prefix = (since_utc, *exclude_ids)
        with self._lock:
            top_nodes = [
                dict(row)
                for row in self._conn.execute(
                    """
                    SELECT
                        node_id,
                        SUM(count) AS total_count,
                        MAX(last_seen_utc) AS last_seen_utc
                    FROM packet_hourly_counts
                    WHERE last_seen_utc >= ?""" + node_filter + """
                    GROUP BY node_id
                    ORDER BY total_count DESC, node_id ASC
                    LIMIT ?
                    """,
                    args_prefix + (limit,),
                ).fetchall()
            ]

            by_type = [
                dict(row)
                for row in self._conn.execute(
                    """
                    SELECT
                        packet_type,
                        SUM(count) AS total_count,
                        COUNT(DISTINCT node_id) AS distinct_nodes
                    FROM packet_hourly_counts
                    WHERE last_seen_utc >= ?""" + node_filter + """
                    GROUP BY packet_type
                    ORDER BY total_count DESC, packet_type ASC
                    LIMIT ?
                    """,
                    args_prefix + (limit,),
                ).fetchall()
            ]

            node_type_rows = [
                dict(row)
                for row in self._conn.execute(
                    """
                    SELECT
                        node_id,
                        packet_type,
                        SUM(count) AS count,
                        SUM(CASE WHEN last_seen_utc >= ? THEN count ELSE 0 END) AS count_1h,
                        MAX(last_seen_utc) AS last_seen_utc,
                        MAX(alerted_utc) AS alerted_utc
                    FROM packet_hourly_counts
                    WHERE last_seen_utc >= ?""" + node_filter + """
                    GROUP BY node_id, packet_type
                    ORDER BY count DESC, count_1h DESC, last_seen_utc DESC
                    LIMIT ?
                    """,
                    (one_hour_since_utc, *args_prefix, limit),
                ).fetchall()
            ]

            alerts = [
                dict(row)
                for row in self._conn.execute(
                    """
                    SELECT
                        node_id,
                        packet_type,
                        hour_bucket,
                        count_at_alert,
                        alert_utc,
                        message
                    FROM bot_alert_history
                    WHERE alert_utc >= ?""" + node_filter + """
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    args_prefix + (limit,),
                ).fetchall()
            ]

        return {
            "window_start_utc": since_utc,
            "generated_utc": datetime.now(UTC).isoformat(),
            "top_nodes": top_nodes,
            "by_type": by_type,
            "node_type_rows": node_type_rows,
            "alerts": alerts,
        }


class MeshDBAdapter:
    """Adapter for pdxlocations/meshdb public API."""

    def __init__(self, db_path: Path) -> None:
        try:
            import meshdb  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "meshdb is required but not installed. Install it before running this bot."
            ) from exc

        self._meshdb = meshdb
        self._meshdb_path = db_path
        self._configure_default_path()

        if not callable(getattr(self._meshdb, "handle_packet", None)):
            raise RuntimeError("Installed meshdb does not expose handle_packet()")

    def _configure_default_path(self) -> None:
        set_default = getattr(self._meshdb, "set_default_db_path", None)
        if callable(set_default):
            set_default(str(self._meshdb_path))

    def save_packet(self, packet: dict[str, Any], owner_node_num: int) -> None:
        handle_packet = getattr(self._meshdb, "handle_packet")

        # meshdb quickstart uses node_database_number; support likely aliases as fallback.
        for kwargs in (
            {"node_database_number": owner_node_num},
            {"owner_node_num": owner_node_num},
        ):
            try:
                handle_packet(packet, **kwargs)
                return
            except TypeError:
                continue

        handle_packet(packet)


@dataclass(slots=True)
class Config:
    interface: str
    port: str | None
    tcp_hostname: str
    tcp_port: int
    meshdb_path: Path
    counter_db_path: Path
    ignore_connected_node: bool
    threshold_unit: str
    default_threshold: int
    thresholds: dict[str, int]
    threshold_units: dict[str, str]
    alert_template: str
    web_ui: bool
    web_host: str
    web_port: int


class PacketMonitorBot:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.counter_db = PacketCounterDB(cfg.counter_db_path)
        self.mesh_store = MeshDBAdapter(cfg.meshdb_path)

    def threshold_for(self, packet_type: str) -> int:
        return self.cfg.thresholds.get(packet_type, self.cfg.thresholds["*"])

    def threshold_unit_for(self, packet_type: str) -> str:
        return self.cfg.threshold_units.get(packet_type, self.cfg.threshold_units["*"])

    def on_receive(self, packet: dict[str, Any], interface: Any) -> None:
        now = datetime.now(UTC)
        now_iso = now.isoformat()
        hour_bucket_utc = utc_hour_bucket(now)
        hour_bucket_local = local_hour_bucket(now)

        node_id = node_id_of(packet)
        packet_type = packet_type_of(packet)
        if packet_type == "SIMULATOR_APP":
            logging.debug("Ignoring simulator packet: node=%s", node_id)
            return
        threshold = self.threshold_for(packet_type)
        threshold_unit = self.threshold_unit_for(packet_type)

        owner_node_num = self._owner_node_num(interface, packet)

        try:
            self.mesh_store.save_packet(packet, owner_node_num=owner_node_num)
        except Exception:
            logging.exception("Failed to persist packet to meshdb")

        if self.cfg.ignore_connected_node and self._is_connected_node_packet(
            packet, interface
        ):
            logging.debug("Ignoring connected-node packet: node=%s type=%s", node_id, packet_type)
            return

        count = self.counter_db.increment_and_fetch(
            node_id=node_id,
            packet_type=packet_type,
            hour_bucket=hour_bucket_utc,
            seen_utc=now_iso,
        )
        window_hours = 24 if threshold_unit == "24h" else 1
        window_start_utc = (now - timedelta(hours=window_hours)).isoformat()
        window_label = "last 24 hours" if window_hours == 24 else "this hour"
        count_for_window = count
        if window_hours == 24:
            count_for_window = self.counter_db.count_since(
                node_id=node_id,
                packet_type=packet_type,
                since_utc=window_start_utc,
            )

        logging.info(
            "packet node=%s type=%s count_%s=%d threshold=%d",
            node_id,
            packet_type,
            threshold_unit,
            count_for_window,
            threshold,
        )

        if count_for_window < threshold:
            return
        if window_hours == 24:
            if self.counter_db.was_alerted_since(
                node_id=node_id,
                packet_type=packet_type,
                since_utc=window_start_utc,
            ):
                return
        else:
            if self.counter_db.was_alerted(
                node_id=node_id,
                packet_type=packet_type,
                hour_bucket=hour_bucket_utc,
            ):
                return

        alert_message = self.cfg.alert_template.format(
            node_id=node_id,
            packet_type=packet_type,
            threshold=threshold,
            hour_bucket=hour_bucket_local,
            hour_bucket_local=hour_bucket_local,
            hour_bucket_utc=hour_bucket_utc,
            count=count_for_window,
            threshold_unit=threshold_unit,
            window_label=window_label,
        )

        sent = self._send_dm(interface, node_id=node_id, message=alert_message)
        if not sent:
            logging.warning(
                "Threshold hit but failed to DM node=%s type=%s", node_id, packet_type
            )
            return

        self.counter_db.mark_alerted(
            node_id=node_id,
            packet_type=packet_type,
            hour_bucket=hour_bucket_utc,
            message=alert_message,
            count_at_alert=count_for_window,
            alerted_utc=now_iso,
        )

    @staticmethod
    def _local_node_num(interface: Any) -> int | None:
        # Use Meshtastic's explicit local node lookup only.
        get_node = getattr(interface, "getNode", None)
        if callable(get_node):
            try:
                local_node = get_node("^local")
                as_int = int_from_node_id(getattr(local_node, "nodeNum", None))
                if as_int is not None:
                    return as_int
            except Exception:
                pass
        return None

    @classmethod
    def _is_connected_node_packet(cls, packet: dict[str, Any], interface: Any) -> bool:
        local_node_num = cls._local_node_num(interface)
        if local_node_num is None:
            return False
        sender_node_num = int_from_node_id(packet.get("fromId") or packet.get("from"))
        return sender_node_num == local_node_num

    @staticmethod
    def _owner_node_num(interface: Any, packet: dict[str, Any]) -> int:
        # Prefer local node identity; fallback to sender if local value unavailable.
        local_node_num = PacketMonitorBot._local_node_num(interface)
        if local_node_num is not None:
            return local_node_num

        candidates = (
            packet.get("to"),
            packet.get("toId"),
            packet.get("from"),
            packet.get("fromId"),
        )
        for value in candidates:
            as_int = int_from_node_id(value)
            if as_int is not None:
                return as_int

        return 0

    @staticmethod
    def _send_dm(interface: Any, *, node_id: str, message: str) -> bool:
        try:
            interface.sendText(
                text=message,
                destinationId=node_id,
                wantAck=True,
            )
            return True
        except TypeError:
            try:
                interface.sendText(message, destinationId=node_id)
                return True
            except Exception:
                return False
        except Exception:
            return False

    def close(self) -> None:
        self.counter_db.close()


class WebDashboard:
    def __init__(
        self,
        *,
        counter_db: PacketCounterDB,
        meshdb_path: Path,
        thresholds: dict[str, int],
        threshold_units: dict[str, str],
        host: str,
        port: int,
    ) -> None:
        self._counter_db = counter_db
        self._meshdb_path = meshdb_path
        self._thresholds = thresholds
        self._threshold_units = threshold_units
        self._host = host
        self._port = port
        self._window_hours = 24
        self._connected_node_id = ""
        self._connected_node_exclude_ids: list[str] = []
        self._thread: threading.Thread | None = None
        self._app = self._build_app()

    def set_connected_node_id(self, node_id: Any) -> None:
        canonical = self._canonical_node_id(node_id)
        self._connected_node_id = canonical
        exclude_ids = {canonical}
        node_num = int_from_node_id(canonical)
        if node_num is not None:
            hex_lower = format(node_num, "x")
            hex_upper = format(node_num, "X")
            exclude_ids.update(
                {
                    str(node_num),
                    f"!{hex_lower}",
                    f"!{hex_upper}",
                    f"!{hex_lower.zfill(8)}",
                    f"!{hex_upper.zfill(8)}",
                    f"0x{hex_lower}",
                    f"0x{hex_upper}",
                    hex_lower,
                    hex_upper,
                }
            )
        self._connected_node_exclude_ids = sorted(exclude_ids)

    def _threshold_for(self, packet_type: str) -> int:
        return int(self._thresholds.get(packet_type, self._thresholds["*"]))

    def _threshold_unit_for(self, packet_type: str) -> str:
        return str(self._threshold_units.get(packet_type, self._threshold_units["*"]))

    @staticmethod
    def _canonical_node_id(node_id: Any) -> str:
        as_int = int_from_node_id(node_id)
        if as_int is not None:
            return str(as_int)
        return str(node_id or "").strip()

    def _meshdb_candidate_paths(self) -> list[Path]:
        base = self._meshdb_path
        if base.suffix:
            pattern = f"{base.stem}.*{base.suffix}"
        else:
            pattern = f"{base.name}.*"

        candidates = [path for path in base.parent.glob(pattern) if path.is_file()]
        if base.is_file():
            candidates.append(base)

        uniq: dict[str, Path] = {}
        for path in candidates:
            uniq[str(path.resolve())] = path
        return sorted(uniq.values(), key=lambda p: p.stat().st_mtime, reverse=True)

    def _lookup_node_names(self, node_ids: set[str]) -> dict[str, dict[str, str]]:
        canonical_ids = sorted(
            {self._canonical_node_id(node_id) for node_id in node_ids if str(node_id).strip()}
        )
        if not canonical_ids:
            return {}

        placeholders = ",".join(["?"] * len(canonical_ids))
        names_by_node: dict[str, dict[str, str]] = {}

        for db_path in self._meshdb_candidate_paths():
            try:
                with sqlite3.connect(db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    tables = [
                        str(row["name"])
                        for row in conn.execute(
                            "SELECT name FROM sqlite_master "
                            "WHERE type = 'table' AND name LIKE '%_nodedb'"
                        ).fetchall()
                    ]
                    for table_name in tables:
                        sql = (
                            f'SELECT node_num, long_name, short_name FROM "{table_name}" '
                            f"WHERE node_num IN ({placeholders})"
                        )
                        for row in conn.execute(sql, canonical_ids).fetchall():
                            node_key = self._canonical_node_id(row["node_num"])
                            current = names_by_node.get(node_key, {"long_name": "", "short_name": ""})
                            long_name = str(row["long_name"] or "").strip()
                            short_name = str(row["short_name"] or "").strip()
                            if long_name and not current["long_name"]:
                                current["long_name"] = long_name
                            if short_name and not current["short_name"]:
                                current["short_name"] = short_name
                            names_by_node[node_key] = current
            except sqlite3.Error:
                continue

            if len(names_by_node) >= len(canonical_ids):
                break

        return names_by_node

    @staticmethod
    def _eta_to_threshold_text(
        *,
        count: int,
        threshold: int,
        elapsed_seconds: float,
    ) -> str:
        if count >= threshold:
            return "Reached"
        if count <= 0 or elapsed_seconds <= 0:
            return "Insufficient data"

        rate_per_second = count / elapsed_seconds
        if rate_per_second <= 0:
            return "Insufficient data"

        remaining = threshold - count
        eta_seconds = int(round(remaining / rate_per_second))
        if eta_seconds < 60:
            return f"{eta_seconds}s"
        if eta_seconds < 3600:
            mins = eta_seconds // 60
            secs = eta_seconds % 60
            return f"{mins}m {secs}s"
        hours = eta_seconds // 3600
        mins = (eta_seconds % 3600) // 60
        return f"{hours}h {mins}m"

    def _enriched_snapshot(self) -> dict[str, Any]:
        now = datetime.now(UTC)
        window_start = now - timedelta(hours=self._window_hours)
        one_hour_start = now - timedelta(hours=1)
        data = self._counter_db.dashboard_snapshot(
            window_start.isoformat(),
            one_hour_start.isoformat(),
            exclude_node_ids=self._connected_node_exclude_ids,
        )
        elapsed_seconds_24h = max((now - window_start).total_seconds(), 1.0)
        elapsed_seconds_1h = max((now - one_hour_start).total_seconds(), 1.0)

        all_node_ids: set[str] = set()
        for section in ("top_nodes", "node_type_rows", "alerts"):
            for row in data.get(section, []):
                node_id = str(row.get("node_id") or "").strip()
                if node_id:
                    all_node_ids.add(node_id)

        if self._connected_node_id:
            all_node_ids.add(self._connected_node_id)
        names_by_node = self._lookup_node_names(all_node_ids)

        for section in ("top_nodes", "node_type_rows", "alerts"):
            for row in data.get(section, []):
                node_id = str(row.get("node_id") or "").strip()
                names = names_by_node.get(self._canonical_node_id(node_id), {})
                row["short_name"] = str(names.get("short_name") or "")
                row["long_name"] = str(names.get("long_name") or "")

        for row in data["node_type_rows"]:
            packet_type = str(row.get("packet_type") or "UNKNOWN")
            threshold_unit = self._threshold_unit_for(packet_type)
            count_24h = int(row.get("count") or 0)
            count_1h = int(row.get("count_1h") or 0)
            count = count_24h if threshold_unit == "24h" else count_1h
            threshold = self._threshold_for(packet_type)
            elapsed_seconds = elapsed_seconds_24h if threshold_unit == "24h" else elapsed_seconds_1h
            row["threshold"] = threshold
            row["threshold_unit"] = threshold_unit
            row["count"] = count
            row["eta_to_threshold"] = self._eta_to_threshold_text(
                count=count,
                threshold=threshold,
                elapsed_seconds=elapsed_seconds,
            )

        threshold_rows = [
            {
                "packet_type": key,
                "threshold": int(value),
                "unit": self._threshold_unit_for(key),
            }
            for key, value in sorted(self._thresholds.items(), key=lambda item: item[0])
        ]
        data["thresholds"] = threshold_rows
        data["window_elapsed_seconds"] = int(elapsed_seconds_24h)
        data["window_hours"] = self._window_hours
        data["window_end_utc"] = now.isoformat()
        data["window_start_local"] = iso_to_local_text(data.get("window_start_utc"))
        data["window_end_local"] = iso_to_local_text(data.get("window_end_utc"))
        data["generated_local"] = iso_to_local_text(data.get("generated_utc"))
        connected_names = names_by_node.get(self._connected_node_id, {})
        data["connected_node_id"] = self._connected_node_id
        data["connected_short_name"] = str(connected_names.get("short_name") or "")
        data["connected_long_name"] = str(connected_names.get("long_name") or "")

        for row in data.get("top_nodes", []):
            row["last_seen_local"] = iso_to_local_text(row.get("last_seen_utc"))
        for row in data.get("node_type_rows", []):
            row["last_seen_local"] = iso_to_local_text(row.get("last_seen_utc"))
            row["alerted_local"] = iso_to_local_text(row.get("alerted_utc"))
        for row in data.get("alerts", []):
            row["alert_local"] = iso_to_local_text(row.get("alert_utc"))
        return data

    def _build_app(self) -> Any:
        try:
            from flask import Flask, jsonify
        except ImportError as exc:
            raise RuntimeError("Flask is required when APP_SETTINGS['web_ui'] is True.") from exc

        app = Flask(__name__)
        window_label = "Past 24 Hours"

        @app.get("/")
        def dashboard() -> str:
            html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MeshPatrol Packet Dashboard</title>
  <link rel="stylesheet" href="/static/dashboard.css">
</head>
<body class="scanline">
  <div class="wrap">
    <div class="head">
      <h1>MeshPatrol Realtime Packet Usage</h1>
      <div class="stamp">
        Connected Node: <span id="connectedId" class="mono">-</span>
        (<span id="connectedShort">-</span> / <span id="connectedLong">-</span>)<br>
        Window: <span id="window" class="mono">-</span><br>
        Last Update: <span id="updated" class="mono">-</span>
      </div>
    </div>
	    <div class="grid">
	      <section class="panel" style="grid-column: 1 / -1;">
	        <h2>Recent Alerts</h2>
	        <table id="alerts">
	          <thead><tr><th>Alert Time</th><th>Node</th><th>Short Name</th><th>Long Name</th><th>Type</th><th>Count</th><th>Message</th></tr></thead>
	          <tbody></tbody>
	        </table>
	      </section>
	      <section class="panel panel-top-nodes">
	        <h2>Top Nodes (__WINDOW_LABEL__)</h2>
	        <table id="topNodes">
	          <thead><tr><th>Node</th><th>Short Name</th><th>Long Name</th><th>Total Packets</th><th>Last Seen</th></tr></thead>
	          <tbody></tbody>
        </table>
      </section>
      <section class="panel">
        <h2>Packet Types (__WINDOW_LABEL__)</h2>
        <table id="byType">
          <thead><tr><th>Type</th><th>Total</th><th>Nodes</th></tr></thead>
          <tbody></tbody>
        </table>
      </section>
      <section class="panel" style="grid-column: 1 / -1;">
        <h2>Node + Type Breakdown</h2>
        <table id="nodeType">
          <thead><tr><th>Node</th><th>Short Name</th><th>Long Name</th><th>Type</th><th>Count</th><th>Threshold</th><th>Unit</th><th>ETA To Threshold</th><th>Alerted</th><th>Last Seen</th></tr></thead>
          <tbody></tbody>
        </table>
      </section>
	      <section class="panel" style="grid-column: 1 / -1;">
	        <h2>Configured Thresholds</h2>
	        <table id="thresholds">
          <thead><tr><th>Type</th><th>Threshold</th><th>Unit</th></tr></thead>
          <tbody></tbody>
        </table>
      </section>
    </div>
  </div>
  <script>
    function fillTable(id, rows, cells) {
      const body = document.querySelector('#' + id + ' tbody');
      body.innerHTML = '';
      if (!rows || rows.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.className = 'empty';
        td.colSpan = cells.length;
        td.textContent = 'No data yet';
        tr.appendChild(td);
        body.appendChild(tr);
        return;
      }
      rows.forEach((row) => {
        const tr = document.createElement('tr');
        cells.forEach((key) => {
          const td = document.createElement('td');
          const v = row[key];
          td.textContent = v === null || v === undefined ? '' : String(v);
          tr.appendChild(td);
        });
        body.appendChild(tr);
      });
    }

    function render(data) {
      const formatUnit = (u) => {
        if (u === '24h') return 'per 24h';
        if (u === 'hour') return 'per hour';
        return u || '';
      };
      const start = data.window_start_local || '-';
      const end = data.window_end_local || data.generated_local || '-';
      document.getElementById('connectedId').textContent = data.connected_node_id || '-';
      document.getElementById('connectedShort').textContent = data.connected_short_name || '-';
      document.getElementById('connectedLong').textContent = data.connected_long_name || '-';
      document.getElementById('window').textContent = start + ' -> ' + end;
      document.getElementById('updated').textContent = data.generated_local || '-';

      fillTable('topNodes', data.top_nodes, ['node_id', 'short_name', 'long_name', 'total_count', 'last_seen_local']);
      fillTable('byType', data.by_type, ['packet_type', 'total_count', 'distinct_nodes']);
      const thresholds = (data.thresholds || []).map((row) => ({
        ...row,
        unit: formatUnit(row.unit),
      }));
      const nodeTypeRows = (data.node_type_rows || []).map((row) => ({
        ...row,
        threshold_unit: formatUnit(row.threshold_unit),
      }));
      fillTable('thresholds', thresholds, ['packet_type', 'threshold', 'unit']);
      fillTable('nodeType', nodeTypeRows, ['node_id', 'short_name', 'long_name', 'packet_type', 'count', 'threshold', 'threshold_unit', 'eta_to_threshold', 'alerted_local', 'last_seen_local']);
      fillTable('alerts', data.alerts, ['alert_local', 'node_id', 'short_name', 'long_name', 'packet_type', 'count_at_alert', 'message']);
    }

    async function fetchOnce() {
      const res = await fetch('/api/snapshot', {cache: 'no-store'});
      if (!res.ok) throw new Error('snapshot request failed');
      render(await res.json());
    }

    fetchOnce().catch(() => {});
    setInterval(() => {
      fetchOnce().catch(() => {});
    }, 30000);
  </script>
</body>
</html>"""
            return (
                html.replace("__WINDOW_LABEL__", window_label)
            )

        @app.get("/api/snapshot")
        def api_snapshot() -> Any:
            data = self._enriched_snapshot()
            return jsonify(data)

        return app

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        def _run() -> None:
            self._app.run(
                host=self._host,
                port=self._port,
                debug=False,
                use_reloader=False,
                threaded=True,
            )

        self._thread = threading.Thread(target=_run, daemon=True, name="web-dashboard")
        self._thread.start()


def run(argv: list[str] | None = None) -> int:
    app = dict(APP_SETTINGS)
    try:
        app.update(parse_cli_overrides(argv))
    except ValueError as exc:
        logging.error("Invalid CLI connection argument: %s", exc)
        return 2
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        return code

    logging.basicConfig(
        level=getattr(logging, str(app["log_level"]).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    thresholds_path = Path(str(app.get("thresholds_path", str(APP_WORK_DIR / "thresholds.json"))))
    ensure_thresholds_file(
        thresholds_path,
        default_threshold=int(app["default_threshold"]),
        default_unit=str(app.get("threshold_unit", "hour")),
    )

    try:
        default_threshold, thresholds, threshold_unit, threshold_units = load_threshold_settings(
            path=thresholds_path,
            fallback_default=int(app["default_threshold"]),
            fallback_overrides=list(app.get("threshold_overrides", [])),
            fallback_threshold_unit=str(app.get("threshold_unit", "hour")),
        )
    except ValueError as exc:
        logging.error("Invalid threshold settings: %s", exc)
        return 2

    cfg = Config(
        interface=str(app.get("interface", "serial")).strip().lower(),
        port=app.get("port"),
        tcp_hostname=str(app.get("tcp_hostname", "127.0.0.1")).strip(),
        tcp_port=int(app.get("tcp_port", 4403)),
        meshdb_path=Path(str(app["meshdb_path"])),
        counter_db_path=Path(str(app["counter_db_path"])),
        ignore_connected_node=bool(app.get("ignore_connected_node", True)),
        threshold_unit=threshold_unit,
        default_threshold=default_threshold,
        thresholds=thresholds,
        threshold_units=threshold_units,
        alert_template=str(app["alert_template"]),
        web_ui=bool(app["web_ui"]),
        web_host=str(app["web_host"]),
        web_port=int(app["web_port"]),
    )
    if cfg.interface not in {"serial", "tcp"}:
        logging.error("APP_SETTINGS['interface'] must be 'serial' or 'tcp'")
        return 2
    if cfg.interface == "tcp":
        if not cfg.tcp_hostname:
            logging.error("APP_SETTINGS['tcp_hostname'] must be set when using TCP")
            return 2
        if cfg.tcp_port <= 0:
            logging.error("APP_SETTINGS['tcp_port'] must be > 0 when using TCP")
            return 2

    cfg.meshdb_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.counter_db_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        bot = PacketMonitorBot(cfg)
    except RuntimeError as exc:
        logging.error(str(exc))
        return 2
    web_dashboard: WebDashboard | None = None

    try:
        from meshtastic.serial_interface import SerialInterface  # type: ignore
        from meshtastic.tcp_interface import TCPInterface  # type: ignore
        from pubsub import pub  # type: ignore
    except ImportError as exc:
        logging.error(
            "Missing runtime dependency: %s. Install meshtastic and PyPubSub.", exc
        )
        bot.close()
        return 2

    def _on_receive(packet: Any, interface: Any) -> None:
        if not isinstance(packet, dict):
            logging.debug("Skipping non-dict packet payload: %r", packet)
            return
        bot.on_receive(packet, interface)

    try:
        if cfg.web_ui:
            try:
                web_dashboard = WebDashboard(
                    counter_db=bot.counter_db,
                    meshdb_path=cfg.meshdb_path,
                    thresholds=cfg.thresholds,
                    threshold_units=cfg.threshold_units,
                    host=cfg.web_host,
                    port=cfg.web_port,
                )
                web_dashboard.start()
                logging.info(
                    "Web dashboard running at http://%s:%d",
                    cfg.web_host,
                    cfg.web_port,
                )
            except RuntimeError as exc:
                logging.error(str(exc))
                return 2

        if cfg.interface == "tcp":
            iface = TCPInterface(hostname=cfg.tcp_hostname, portNumber=cfg.tcp_port)
            logging.info(
                "Connected via Meshtastic TCP interface %s:%d",
                cfg.tcp_hostname,
                cfg.tcp_port,
            )
        else:
            iface = SerialInterface(devPath=cfg.port) if cfg.port else SerialInterface()
            if cfg.port:
                logging.info("Connected via Meshtastic serial interface %s", cfg.port)
            else:
                logging.info("Connected via Meshtastic auto-detected serial interface")

        if web_dashboard:
            local_node_num = PacketMonitorBot._local_node_num(iface)
            if local_node_num is not None:
                web_dashboard.set_connected_node_id(local_node_num)
        pub.subscribe(_on_receive, "meshtastic.receive")
        logging.info("Packet monitor started. Listening for meshtastic.receive")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logging.info("Shutting down")
    finally:
        bot.close()
        try:
            iface.close()  # type: ignore[name-defined]
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
