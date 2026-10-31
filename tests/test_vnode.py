import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from meshpatrol import __main__ as app

try:
    import vnode
except ImportError:
    vnode = None


def config(root):
    return app.Config(
        interface="vnode", port=None, tcp_hostname="127.0.0.1", tcp_port=4403,
        vnode_file=root / "node.json", meshdb_path=root / "packets.db",
        counter_db_path=root / "counters.db", ignore_connected_node=True,
        threshold_unit="hour", default_threshold=1, thresholds={"*": 1},
        threshold_units={"*": "hour"}, alert_templates={"*": "Check settings"},
        web_ui=False, web_host="127.0.0.1", web_port=5050,
    )


class VnodeTests(unittest.TestCase):
    def test_cli_selects_vnode_and_preserves_hardware_options(self):
        self.assertEqual(app.APP_SETTINGS["interface"], "vnode")
        self.assertEqual(app.parse_cli_overrides(["--vnode-file", "custom.json"]),
                         {"interface": "vnode", "vnode_file": "custom.json"})
        self.assertEqual(app.parse_cli_overrides(["--serial", "/dev/ttyUSB0"]),
                         {"interface": "serial", "port": "/dev/ttyUSB0"})
        self.assertEqual(app.parse_cli_overrides(["--tcp", "[::1]:4403"]),
                         {"interface": "tcp", "tcp_hostname": "::1", "tcp_port": 4403})

    def test_vnode_identity_filter_alert_and_single_packet_storage(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(app, "MeshDBAdapter") as store:
            bot = app.PacketMonitorBot(config(Path(tmp)))
            interface = SimpleNamespace(node_num=0x12345678, sendText=Mock())
            try:
                self.assertEqual(bot._local_node_num(interface), 0x12345678)
                bot.on_receive({"fromId": "!12345678", "decoded": {"portnum": "TEXT_MESSAGE_APP"}}, interface)
                interface.sendText.assert_not_called()
                bot.on_receive({"fromId": "!87654321", "decoded": {"portnum": "TEXT_MESSAGE_APP"}}, interface)
                interface.sendText.assert_called_once_with(
                    text="Check settings", destinationId="!87654321", wantAck=True)
                store.return_value.save_packet.assert_not_called()
            finally:
                bot.close()

    @unittest.skipIf(vnode is None, "vnode runtime dependencies not installed")
    def test_run_subscribes_before_start_and_closes_before_database(self):
        from pubsub import pub

        for startup_error in (None, RuntimeError("startup failed")):
            with self.subTest(startup_error=startup_error), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                events = []
                iface = Mock()
                iface.node_num = 0x12345678
                iface.meshdb_path = str(root / "data")
                iface.config = SimpleNamespace(node_id="!12345678", channel=SimpleNamespace(name="LongFast", psk="AQ=="))
                def receive(cb):
                    events.append("receive")
                    pub.subscribe(cb, "meshtastic.receive")
                iface.receive.side_effect = receive
                iface.unreceive.side_effect = lambda cb: pub.unsubscribe(cb, "meshtastic.receive")
                def start():
                    events.append("start")
                    if startup_error:
                        raise startup_error
                iface.start.side_effect = start
                iface.close.side_effect = lambda: events.append("close")
                settings = dict(app.APP_SETTINGS, web_ui=False, vnode_file=str(root / "node.json"),
                                thresholds_path=str(root / "thresholds.json"),
                                meshdb_path=str(root / "packets.db"), counter_db_path=str(root / "counters.db"))
                with patch.object(app, "APP_SETTINGS", settings), \
                     patch.object(app, "PacketMonitorBot") as bot, \
                     patch.object(app, "create_virtual_node", return_value=iface), \
                     patch.object(app.time, "sleep", side_effect=KeyboardInterrupt):
                    bot.return_value.close.side_effect = lambda: events.append("database close")
                    self.assertEqual(app.run([]), 2 if startup_error else 0)
                    self.assertEqual(events, ["receive", "start", "close", "database close"])
                    iface.unreceive.assert_called_once()
                    self.assertFalse(pub.isSubscribed(iface.unreceive.call_args.args[0], "meshtastic.receive"))


@unittest.skipIf(vnode is None, "vnode runtime dependencies not installed")
class RealVnodeTests(unittest.TestCase):
    def setUp(self):
        # vnode.stop() expects these transport topics even without starting sockets.
        from pubsub import pub
        for topic in (vnode.VirtualNode.RAW_PACKET_TOPIC, vnode.VirtualNode.PACKET_TOPIC,
                      vnode.VirtualNode.RECEIVE_TOPIC, vnode.VirtualNode.ACK_TOPIC,
                      vnode.VirtualNode.NAK_TOPIC):
            pub.getDefaultTopicMgr().getOrCreateTopic(topic)

    def test_numeric_vnode_sender_gets_one_alert_in_rolling_window(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(app, "MeshDBAdapter"):
            root = Path(tmp)
            cfg = config(root)
            cfg.thresholds = {"*": 2}
            cfg.threshold_units = {"*": "24h"}
            node = app.create_virtual_node(root / "node.json")
            bot = app.PacketMonitorBot(cfg)
            packet = {"from": 2409766760, "decoded": {"portnum": "TELEMETRY_APP"}}
            try:
                # Exercise vnode's real destination resolver, replacing only the wire send.
                with patch.object(node, "_send_data_packet") as send:
                    bot.on_receive(packet, node)
                    send.assert_not_called()
                    bot.on_receive(packet, node)
                    send.assert_called_once()
                    self.assertEqual(send.call_args.kwargs["destination"], 2409766760)
                    self.assertTrue(send.call_args.kwargs["want_ack"])
                    self.assertTrue(bot.counter_db.was_alerted(
                        node_id="2409766760", packet_type="TELEMETRY_APP",
                        hour_bucket=app.utc_hour_bucket()))
                    bot.on_receive(packet, node)
                    send.assert_called_once()
            finally:
                node.close()
                bot.close()

    def test_names_identity_and_dashboard_node_lookup_survive_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node = app.create_virtual_node(root / "node.json")
            try:
                self.assertEqual(node.getLongName(), "MeshPatrol")
                self.assertEqual(node.getShortName(), "🚨")
                payload = json.loads((root / "node.json").read_text())
                key = payload["security"]["private_key"]
                node_num = node.node_num
                payload["long_name"] = "Old name"
                payload["short_name"] = "OLD"
                payload["channel"]["name"] = "Custom"
                (root / "node.json").write_text(json.dumps(payload))
            finally:
                node.close()
            node = app.create_virtual_node(root / "node.json")
            try:
                self.assertEqual(node.node_num, node_num)
                self.assertEqual(node.config.security.private_key, key)
                self.assertEqual(node.config.channel.name, "Custom")
                self.assertEqual(node.getLongName(), "MeshPatrol")
                self.assertEqual(node.getShortName(), "🚨")
                from mudp.encryption import generate_hash
                with patch.object(app.WebDashboard, "_build_app"):
                    dashboard = app.WebDashboard(
                        counter_db=Mock(), meshdb_path=Path(node.meshdb_path),
                        thresholds={"*": 1}, threshold_units={"*": "hour"},
                        host="127.0.0.1", port=5050,
                        meshdb_scope={"channel": generate_hash(node.config.channel.name, node.config.channel.psk),
                                      "channel_name": node.config.channel.name, "storage_name": str(node.node_num)},
                    )
                    dashboard.set_connected_node_id(node.node_num)
                    self.assertEqual(dashboard._lookup_node_names({str(node.node_num)}),
                                     {str(node.node_num): {"long_name": "MeshPatrol", "short_name": "🚨"}})
            finally:
                node.close()


if __name__ == "__main__":
    unittest.main()
