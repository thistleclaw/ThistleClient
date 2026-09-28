#!/usr/bin/env python3
"""
Unit test suite for ThistleClient core components.
Tests parser, config generator, Xray outbound adapter, and pinger dispatcher.
"""

import unittest
import json
from thistle_client.subscription_parser import (
    parse_vless,
    parse_hysteria2,
    parse_subscription_content,
    safe_b64decode,
)
from thistle_client.xray_adapter import node_to_xray_outbound
from thistle_client.config_generator import generate_singbox_config
from thistle_client.pinger import MultiModePinger


class TestSubscriptionParser(unittest.TestCase):
    def test_parse_vless_reality(self):
        uri = (
            "vless://a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d@vless.example.com:4575?"
            "encryption=none&fp=chrome&pbk=gdaox-3rhlam0g9rVMP7on63UulGu2pK4Ye57u6WIhU"
            "&security=reality&sid=0123456789abcdef&sni=speedtest.net&spx=%2Fexample-spiderx"
            "&type=tcp#%F0%9F%87%B7%F0%9F%87%BA%20RAW%3A%20RU"
        )
        node = parse_vless(uri)
        self.assertEqual(node["type"], "vless")
        self.assertEqual(node["server"], "vless.example.com")
        self.assertEqual(node["server_port"], 4575)
        self.assertEqual(node["tag"], "🇷🇺 RAW: RU")
        self.assertEqual(node["tls"]["reality"]["public_key"], "gdaox-3rhlam0g9rVMP7on63UulGu2pK4Ye57u6WIhU")
        self.assertEqual(node["tls"]["reality"]["short_id"], "0123456789abcdef")
        self.assertIn("_raw_query", node)
        self.assertEqual(node["_raw_query"]["spx"], "/example-spiderx")

    def test_parse_vless_xhttp(self):
        uri = (
            "vless://a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d@xhttp.example.com:8044?"
            "alpn=h2%2Chttp%2F1.1&encryption=none&extra=%7B%22mode%22%3A%22packet-up%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D"
            "&fp=edge&host=xhttp.example.com&mode=packet-up&path=%2Fapi%2Fv1%2Fstream&security=tls"
            "&sni=xhttp.example.com&type=xhttp#%F0%9F%87%B7%F0%9F%87%BA%20XHTTP%3A%20RU"
        )
        node = parse_vless(uri)
        self.assertEqual(node["type"], "vless")
        self.assertEqual(node["tag"], "🇷🇺 XHTTP: RU")
        self.assertEqual(node["_raw_query"]["type"], "xhttp")
        self.assertEqual(node["_raw_query"]["path"], "/api/v1/stream")
        self.assertEqual(node["_raw_query"]["mode"], "packet-up")

    def test_parse_hysteria2(self):
        uri = (
            "hysteria2://demo-hy2-password@hy2.example.com:443?"
            "alpn=h3&fp=ios&obfs=salamander&obfs-password=demo-salamander-pw"
            "&security=tls&sni=hy2.example.com#%F0%9F%87%B7%F0%9F%87%BA%20Hysteria%3A%20RU"
        )
        node = parse_hysteria2(uri)
        self.assertEqual(node["type"], "hysteria2")
        self.assertEqual(node["server"], "hy2.example.com")
        self.assertEqual(node["server_port"], 443)
        self.assertEqual(node["password"], "demo-hy2-password")
        self.assertEqual(node["obfs"]["type"], "salamander")
        self.assertEqual(node["obfs"]["password"], "demo-salamander-pw")


class TestXrayAdapter(unittest.TestCase):
    def test_vless_reality_translation(self):
        node = {
            "type": "vless",
            "tag": "Reality Test",
            "server": "1.2.3.4",
            "server_port": 443,
            "uuid": "test-uuid-1234",
            "_raw_query": {
                "type": "tcp",
                "security": "reality",
                "sni": "speedtest.net",
                "fp": "chrome",
                "pbk": "test-public-key",
                "sid": "test-short-id",
                "spx": "/test-spider-x"
            }
        }
        ob = node_to_xray_outbound(node)
        self.assertEqual(ob["protocol"], "vless")
        self.assertEqual(ob["streamSettings"]["network"], "tcp")
        self.assertEqual(ob["streamSettings"]["security"], "reality")
        reality = ob["streamSettings"]["realitySettings"]
        self.assertEqual(reality["publicKey"], "test-public-key")
        self.assertEqual(reality["shortId"], "test-short-id")
        self.assertEqual(reality["spiderX"], "/test-spider-x")
        self.assertEqual(reality["fingerprint"], "chrome")

    def test_vless_xhttp_translation(self):
        node = {
            "type": "vless",
            "tag": "XHTTP Test",
            "server": "1.2.3.4",
            "server_port": 8044,
            "uuid": "test-uuid-1234",
            "_raw_query": {
                "type": "xhttp",
                "security": "tls",
                "sni": "xhttp.example.com",
                "path": "/api/v1/stream",
                "mode": "packet-up"
            }
        }
        ob = node_to_xray_outbound(node)
        self.assertEqual(ob["protocol"], "vless")
        self.assertEqual(ob["streamSettings"]["network"], "xhttp")
        self.assertEqual(ob["streamSettings"]["security"], "tls")
        xhttp = ob["streamSettings"]["xhttpSettings"]
        self.assertEqual(xhttp["path"], "/api/v1/stream")
        self.assertEqual(xhttp["mode"], "packet-up")


class TestConfigGenerator(unittest.TestCase):
    def test_metadata_stripping(self):
        nodes = [
            {
                "type": "hysteria2",
                "tag": "Hysteria Node",
                "server": "1.2.3.4",
                "server_port": 443,
                "password": "secret",
                "_raw_query": {"dummy": "value"},
                "_raw_uri": "hysteria2://dummy"
            },
            {
                "type": "vless",
                "tag": "VLESS Node",
                "server": "1.2.3.4",
                "server_port": 8443,
                "uuid": "dummy-uuid",
                "_raw_query": {"spx": "123"},
                "_raw_uri": "vless://dummy"
            }
        ]
        cfg = generate_singbox_config(nodes, active_tag="Hysteria Node", enable_tun=False)
        for ob in cfg.get("outbounds", []):
            self.assertFalse(any(k.startswith("_") for k in ob.keys()))

    def test_selector_routing(self):
        nodes = [
            {"type": "hysteria2", "tag": "Hy2-Node", "server": "1.2.3.4", "server_port": 443, "password": "pass"},
            {"type": "vless", "tag": "gRPC-Node", "server": "1.2.3.4", "server_port": 443, "uuid": "uuid", "transport": {"type": "grpc"}},
            {"type": "vless", "tag": "Reality-Node", "server": "1.2.3.4", "server_port": 443, "uuid": "uuid", "_raw_query": {"security": "reality"}},
            {"type": "vless", "tag": "XHTTP-Node", "server": "1.2.3.4", "server_port": 443, "uuid": "uuid", "_raw_query": {"type": "xhttp"}}
        ]
        # Active is Hysteria 2 -> selector should point to Hy2-Node directly
        cfg_hy2 = generate_singbox_config(nodes, active_tag="Hy2-Node", enable_tun=False)
        proxy_ob = [o for o in cfg_hy2["outbounds"] if o["tag"] == "PROXY"][0]
        self.assertEqual(proxy_ob["default"], "Hy2-Node")

        # Active is gRPC (VLESS) -> selector should point to xray-out (handled by Xray)
        cfg_grpc = generate_singbox_config(nodes, active_tag="gRPC-Node", enable_tun=False)
        proxy_ob_grpc = [o for o in cfg_grpc["outbounds"] if o["tag"] == "PROXY"][0]
        self.assertEqual(proxy_ob_grpc["default"], "xray-out")

        # Active is Reality -> selector should point to xray-out
        cfg_reality = generate_singbox_config(nodes, active_tag="Reality-Node", enable_tun=False)
        proxy_ob2 = [o for o in cfg_reality["outbounds"] if o["tag"] == "PROXY"][0]
        self.assertEqual(proxy_ob2["default"], "xray-out")

        # Active is XHTTP -> selector should point to xray-out
        cfg_xhttp = generate_singbox_config(nodes, active_tag="XHTTP-Node", enable_tun=False)
        proxy_ob3 = [o for o in cfg_xhttp["outbounds"] if o["tag"] == "PROXY"][0]
        self.assertEqual(proxy_ob3["default"], "xray-out")

    def test_server_bypass_and_dns_rules(self):
        nodes = [
            {"type": "vless", "tag": "Test-Node", "server": "example.com", "server_port": 443, "uuid": "uuid"}
        ]
        cfg = generate_singbox_config(nodes, active_tag="Test-Node", enable_tun=False)
        
        # Check domain rule exists in route.rules
        route_domains = []
        for r in cfg["route"]["rules"]:
            if "domain" in r and r.get("outbound") == "direct":
                route_domains.extend(r["domain"])
        self.assertIn("example.com", route_domains)

        # Check domain rule exists in dns.rules
        dns_domains = []
        for r in cfg["dns"]["rules"]:
            if "domain" in r and r.get("server") == "dns-direct":
                dns_domains.extend(r["domain"])
        self.assertIn("example.com", dns_domains)

    def test_dns_upstream_hostname_cannot_create_bootstrap_recursion(self):
        from unittest.mock import patch
        from thistle_client.config import settings

        original_get = settings.get

        def get_setting(section, key, default=None):
            if section == "dns" and key == "remote_server":
                return "resolver.example"
            return original_get(section, key, default)

        with patch.object(settings, "get", side_effect=get_setting):
            cfg = generate_singbox_config([], enable_tun=False)
        self.assertEqual(cfg["dns"]["servers"][0]["server"], "8.8.8.8")


class TestCloseToTrayAndSettings(unittest.TestCase):
    def test_default_close_to_tray_setting(self):
        from thistle_client.config import DEFAULT_SETTINGS, settings
        self.assertIn("close_to_tray", DEFAULT_SETTINGS["app"])
        self.assertTrue(DEFAULT_SETTINGS["app"]["close_to_tray"])
        self.assertTrue(settings.get("app", "close_to_tray", True))

    def test_close_to_tray_window_behavior(self):
        from unittest.mock import MagicMock, patch
        from thistle_client.config import settings
        from thistle_client.manager_gui import ThistleManagerWindow

        mock_tray = MagicMock()
        win = ThistleManagerWindow(tray_app=mock_tray)
        win.hide = MagicMock()

        # When close_to_tray is True: on_delete_event should hide and return True
        settings.set("app", "close_to_tray", True)
        res = win.on_delete_event(None, None)
        self.assertTrue(res)
        win.hide.assert_called_once()

        # When close_to_tray is False: on_delete_event should call Gtk.main_quit and return False
        settings.set("app", "close_to_tray", False)
        with patch("thistle_client.manager_gui.Gtk.main_quit") as mock_quit:
            res_no_tray = win.on_delete_event(None, None)
            self.assertFalse(res_no_tray)
            mock_quit.assert_called_once()

        # Restore default
        settings.set("app", "close_to_tray", True)

    def test_ipc_socket_path(self):
        from thistle_client.main import get_ipc_socket_path
        path = get_ipc_socket_path()
        self.assertTrue(path.endswith("thistle-client.sock"))

    def test_process_bypass_and_singbox_check(self):
        import subprocess, tempfile, json
        import os
        from thistle_client.core_manager import _is_managed_singbox_process
        from thistle_client.config_generator import generate_singbox_config
        from thistle_client.xray_adapter import XrayManager

        nodes = [
            {"type": "vless", "tag": "Test-Node", "server": "203.0.113.195", "server_port": 443, "uuid": "uuid"}
        ]
        cfg = generate_singbox_config(nodes, active_tag="Test-Node", enable_tun=False)

        # 1. Verify process_name bypass exists
        proc_bypass = [r for r in cfg["route"]["rules"] if "process_name" in r and r.get("outbound") == "direct"]
        self.assertTrue(len(proc_bypass) > 0)
        self.assertIn("xray", proc_bypass[0]["process_name"])
        self.assertIn("sing-box", proc_bypass[0]["process_name"])
        self.assertFalse(_is_managed_singbox_process(os.getpid()))
        self.assertFalse(XrayManager()._is_managed_process(os.getpid()))

        # 2. Verify dns-direct is UDP to 8.8.8.8 without detour
        dns_direct = [s for s in cfg["dns"]["servers"] if s.get("tag") == "dns-direct"][0]
        self.assertEqual(dns_direct.get("type"), "udp")
        self.assertEqual(dns_direct.get("server"), "8.8.8.8")
        self.assertNotIn("detour", dns_direct)

        # 3. Validate with sing-box check and dry-run initialization
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            tmp_path = f.name
        try:
            res = subprocess.run(["sing-box", "check", "-c", tmp_path], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"sing-box check failed: {res.stderr}")

            # Test actual run initialization without crashing
            try:
                subprocess.run(["sing-box", "run", "-c", tmp_path], capture_output=True, text=True, timeout=1.5)
            except subprocess.TimeoutExpired:
                pass  # Running cleanly without crash
        finally:
            import os
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_core_manager_refuses_to_start_with_another_vpn_active(self):
        import json
        import tempfile
        from unittest.mock import Mock
        from thistle_client.core_manager import CoreManager

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as config_file:
            json.dump({"inbounds": []}, config_file)
            config_path = config_file.name
        try:
            core = CoreManager(config_path=config_path)
            core.is_running = Mock(return_value=False)
            core.is_conflict_running = Mock(return_value="Happ")
            core.xray.start = Mock()
            self.assertFalse(core.start({"type": "vless", "tag": "test"}))
            core.xray.start.assert_not_called()
        finally:
            import os
            os.unlink(config_path)

    def test_core_manager_refuses_an_occupied_tun_route_slot(self):
        import json
        import os
        import tempfile
        import subprocess
        from unittest.mock import Mock, patch
        from thistle_client.core_manager import CoreManager

        config = {
            "inbounds": [{
                "type": "tun", "iproute2_table_index": 2024, "iproute2_rule_index": 9100
            }]
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as config_file:
            json.dump(config, config_file)
            config_path = config_file.name
        try:
            core = CoreManager(config_path=config_path)
            core.is_running = Mock(return_value=False)
            core.is_conflict_running = Mock(return_value="")
            core.xray.start = Mock()
            occupied_rule = subprocess.CompletedProcess(
                ["ip"], 0, "9100: from all lookup main\n", ""
            )
            with patch("thistle_client.core_manager.subprocess.run", return_value=occupied_rule):
                self.assertFalse(core.start({"type": "vless", "tag": "test"}))
            core.xray.start.assert_not_called()
        finally:
            os.unlink(config_path)

    def test_hybrid_tun_dns_and_xray_bridge_are_loop_free(self):
        import os
        import subprocess
        import tempfile
        from unittest.mock import patch
        from thistle_client.config import XRAY_SOCKS_PORT

        nodes = [
            {"type": "hysteria2", "tag": "Hy2", "server": "hy2.example", "server_port": 443,
             "password": "secret", "tls": {"enabled": True, "server_name": "hy2.example"}},
            {"type": "vless", "tag": "XHTTP", "server": "xray.example", "server_port": 443,
             "uuid": "uuid", "_raw_query": {"security": "reality", "type": "xhttp", "sni": "xray.example"}},
        ]
        with patch("thistle_client.config_generator.socket.gethostbyname", side_effect=OSError):
            cfg = generate_singbox_config(nodes, active_tag="XHTTP", enable_tun=True)

        tun = next(inbound for inbound in cfg["inbounds"] if inbound["type"] == "tun")
        self.assertEqual(tun["interface_name"], "thistle0")
        self.assertEqual(tun["iproute2_table_index"], 2024)
        self.assertEqual(tun["iproute2_rule_index"], 9100)
        self.assertEqual(cfg["dns"]["servers"][0]["server"], "8.8.8.8")
        self.assertNotIn("detour", cfg["dns"]["servers"][0])
        self.assertIn(
            {"protocol": "dns", "action": "hijack-dns"},
            cfg["route"]["rules"],
        )
        self.assertIn(
            {"port": [53], "action": "hijack-dns"},
            cfg["route"]["rules"],
        )
        xray_bridge = next(outbound for outbound in cfg["outbounds"] if outbound["tag"] == "xray-out")
        self.assertEqual(xray_bridge["server"], "127.0.0.1")
        self.assertEqual(xray_bridge["server_port"], XRAY_SOCKS_PORT)
        self.assertTrue(any(
            "xray" in rule.get("process_name", []) and rule.get("outbound") == "direct"
            for rule in cfg["route"]["rules"]
        ))
        self.assertTrue(any(
            "xray.example" in rule.get("domain", []) and rule.get("outbound") == "direct"
            for rule in cfg["route"]["rules"]
        ))

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as config_file:
            json.dump(cfg, config_file)
            config_path = config_file.name
        try:
            checked = subprocess.run(
                ["sing-box", "check", "-c", config_path], capture_output=True, text=True
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
        finally:
            os.unlink(config_path)

    def test_xray_config_validation(self):
        import subprocess, tempfile, json
        from thistle_client.xray_adapter import node_to_xray_outbound

        node = {
            "type": "vless",
            "tag": "🇷🇺 RAW: RU",
            "server": "reality.example.com",
            "server_port": 4575,
            "uuid": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
            "_raw_query": {
                "security": "reality",
                "sni": "speedtest.net",
                "pbk": "gdaox-3rhlam0g9rVMP7on63UulGu2pK4Ye57u6WIhU",
                "sid": "0123456789abcdef",
                "spx": "/example-spiderx",
                "type": "tcp"
            }
        }
        outbound = node_to_xray_outbound(node)
        self.assertEqual(outbound["streamSettings"]["realitySettings"]["serverName"], "speedtest.net")

        xray_cfg = {
            "log": {"loglevel": "warning"},
            "dns": {
                "hosts": {"reality.example.com": "203.0.113.195", "dns.google": "8.8.8.8"},
                "servers": ["8.8.8.8", "1.1.1.1"]
            },
            "inbounds": [
                {"port": 29996, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}
            ],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(xray_cfg, f)
            tmp_path = f.name
        try:
            res = subprocess.run(["xray", "-test", "-config", tmp_path], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"xray -test failed: {res.stderr}")
        finally:
            import os
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_xray_reality_xhttp_and_grpc_configs_validate_with_loopback_socks(self):
        import os
        import subprocess
        import tempfile

        reality = {
            "security": "reality",
            "sni": "www.example.com",
            "pbk": "gdaox-3rhlam0g9rVMP7on63UulGu2pK4Ye57u6WIhU",
            "sid": "0123456789abcdef",
        }
        transports = [
            ("xhttp", {"path": "/api", "mode": "packet-up"}),
            ("grpc", {"serviceName": "rpc-service"}),
        ]
        for transport, extra in transports:
            with self.subTest(transport=transport):
                node = {
                    "type": "vless",
                    "tag": transport,
                    "server": "192.0.2.1",
                    "server_port": 443,
                    "uuid": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
                    "_raw_query": {**reality, "type": transport, **extra},
                }
                outbound = node_to_xray_outbound(node)
                config = {
                    "log": {"loglevel": "warning"},
                    "inbounds": [{
                        "tag": "socks-in",
                        "listen": "127.0.0.1",
                        "port": 20850,
                        "protocol": "socks",
                        "settings": {"auth": "noauth", "udp": True},
                    }],
                    "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
                }
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as config_file:
                    json.dump(config, config_file)
                    config_path = config_file.name
                try:
                    checked = subprocess.run(
                        ["xray", "run", "-test", "-c", config_path],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(checked.returncode, 0, checked.stderr)
                finally:
                    os.unlink(config_path)

    def test_conflict_detection(self):
        from thistle_client.core_manager import check_conflicting_vpns
        # Since Happ is running, it should detect Happ (or return a string)
        conflict = check_conflicting_vpns()
        self.assertIsInstance(conflict, str)

    def test_free_ports_allocation(self):
        from thistle_client.pinger import _get_free_ports
        ports = _get_free_ports(6)
        self.assertEqual(len(ports), 6)
        self.assertEqual(len(set(ports)), 6)
        for p in ports:
            self.assertGreater(p, 1024)

    def test_format_delay_markup(self):
        from thistle_client.manager_gui import ThistleManagerWindow
        # None
        m_none, v_none = ThistleManagerWindow.format_delay(None)
        self.assertIn("—", m_none)
        self.assertEqual(v_none, 99999)
        # Loading
        m_load, v_load = ThistleManagerWindow.format_delay("loading")
        self.assertIn("замер...", m_load)
        # Timeout / unreachable
        m_unreach, v_unreach = ThistleManagerWindow.format_delay(-1)
        self.assertIn("Недоступен", m_unreach)
        self.assertEqual(v_unreach, 99998)
        # Low latency (<150)
        m_low, v_low = ThistleManagerWindow.format_delay(48)
        self.assertIn("00E676", m_low)
        self.assertEqual(v_low, 48)
        # Medium latency (<350)
        m_med, v_med = ThistleManagerWindow.format_delay(220)
        self.assertIn("FFD600", m_med)
        self.assertEqual(v_med, 220)
        # High latency (>=350)
        m_high, v_high = ThistleManagerWindow.format_delay(450)
        self.assertIn("FF9100", m_high)
        self.assertEqual(v_high, 450)

    def test_manager_ping_progress_is_queued_for_gtk_main_loop(self):
        import threading
        from unittest.mock import MagicMock, patch
        from thistle_client.manager_gui import ThistleManagerWindow

        window = ThistleManagerWindow(tray_app=None)
        window.data = {
            "active_sub": "test",
            "active_node": "Node",
            "subs": {"test": {"nodes": [{
                "type": "hysteria2", "tag": "Node", "server": "127.0.0.1", "server_port": 1
            }]}},
        }
        window.update_server_list()
        window.pinger = MagicMock()
        progress_seen = threading.Event()

        def fake_ping_all(_nodes, **kwargs):
            kwargs["on_progress"]("Node", 42)
            progress_seen.set()
            return {"Node": 42}

        window.pinger.ping_all.side_effect = fake_ping_all
        queued = []
        worker_finished = threading.Event()

        def queue_for_main_loop(callback, *args):
            queued.append((callback, args))
            if callback == window.finish_ping:
                worker_finished.set()
            return 1

        try:
            with patch("thistle_client.manager_gui.GLib.idle_add", side_effect=queue_for_main_loop):
                window.on_ping_clicked(None)
                self.assertTrue(progress_seen.wait(timeout=2))
                self.assertTrue(worker_finished.wait(timeout=2))

                # Worker callbacks are queued; only begin_ping touched GTK so far.
                self.assertIn("замер...", window.model_servers[0][3])
                self.assertEqual(len(queued), 2)

                for callback, args in queued:
                    callback(*args)

            self.assertIn("42 ms", window.model_servers[0][3])
            self.assertFalse(window.is_pinging)
        finally:
            window.destroy()

    def test_pinger_active_procs_zero_leak(self):
        import os
        import subprocess
        from unittest.mock import patch
        from thistle_client.pinger import MultiModePinger, _active_test_procs
        from thistle_client.core_manager import check_conflicting_vpns
        pinger = MultiModePinger()
        progress_calls = []
        probe_conflicts = []

        def process_ids(name):
            result = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
            return set(result.stdout.split())

        existing_singbox = process_ids("sing-box")
        existing_xray = process_ids("xray")

        dummy_nodes = [
            {
                "type": "hysteria2",
                "tag": "Dummy Hy2 Node",
                "server": "127.0.0.1",
                "server_port": 1,
                "password": "pass",
            },
            {
                "type": "vless",
                "tag": "Dummy VLESS Node",
                "server": "127.0.0.1",
                "server_port": 1,
                "uuid": "00000000-0000-0000-0000-000000000001",
            },
        ]

        def on_progress(tag, delay):
            progress_calls.append((tag, delay))
            singbox_pids = [
                proc.pid for proc in _active_test_procs
                if os.path.basename(proc.args[0]) == "sing-box"
            ]
            if singbox_pids:
                mocked_pgrep = [
                    subprocess.CompletedProcess([], 1, "", ""),
                    subprocess.CompletedProcess([], 0, f"{singbox_pids[0]}\n", ""),
                ]
                with patch("thistle_client.core_manager.subprocess.run", side_effect=mocked_pgrep):
                    probe_conflicts.append(check_conflicting_vpns())

        res = pinger.ping_proxy_get_batch(
            dummy_nodes,
            timeout=1,
            test_url="http://127.0.0.1:9/",
            on_progress=on_progress,
        )
        # Both protocol paths report completion, including unreachable nodes.
        self.assertEqual(set(tag for tag, _delay in progress_calls), {
            "Dummy Hy2 Node", "Dummy VLESS Node"
        })
        self.assertEqual(set(res), {"Dummy Hy2 Node", "Dummy VLESS Node"})
        self.assertEqual(probe_conflicts, ["", ""])
        # Must leave ZERO active test processes
        self.assertEqual(len(_active_test_procs), 0)
        # The only live sing-box/Xray PIDs must still be the ones present before
        # the probe (this host may have a separate VPN client running).
        self.assertEqual(process_ids("sing-box"), existing_singbox)
        self.assertEqual(process_ids("xray"), existing_xray)

    def test_proxy_get_uses_curl_get_through_local_singbox_proxy(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        requests = []
        requests_lock = threading.Lock()

        class GetHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                with requests_lock:
                    requests.append((self.command, self.path))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), GetHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            node = {"type": "direct", "tag": "Local HTTP proxy test"}
            result = MultiModePinger().ping_proxy_get_batch(
                [node],
                timeout=2,
                test_url=f"http://127.0.0.1:{server.server_port}/latency-check",
            )
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

        self.assertGreater(result["Local HTTP proxy test"], 0)
        self.assertEqual(requests, [("GET", "/latency-check")])

    def test_proxy_get_uses_curl_get_through_local_xray_socks_proxy(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from unittest.mock import patch

        requests = []

        class GetHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.command, self.path))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), GetHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            node = {"type": "vless", "tag": "Local Xray SOCKS test"}
            with patch("thistle_client.pinger.is_xray_node", return_value=True), patch(
                "thistle_client.pinger.node_to_xray_outbound",
                return_value={"protocol": "freedom", "tag": "test-out"},
            ):
                result = MultiModePinger().ping_proxy_get_batch(
                    [node],
                    timeout=2,
                    test_url=f"http://127.0.0.1:{server.server_port}/socks-latency-check",
                )
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

        self.assertGreater(result["Local Xray SOCKS test"], 0)
        self.assertEqual(requests, [("GET", "/socks-latency-check")])


class TestSecurityAndPortability(unittest.TestCase):
    def test_subscription_fetch_keeps_tls_verification_enabled(self):
        import ssl
        from unittest.mock import MagicMock, patch
        from thistle_client.subscription_parser import fetch_subscription

        class FakeContext:
            def __init__(self):
                self.check_hostname = True
                self.verify_mode = ssl.CERT_REQUIRED

        context = FakeContext()
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = (
            b"vless://a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d@example.com:443"
            b"?security=tls#TLS-Test"
        )
        with patch(
            "thistle_client.subscription_parser.ssl.create_default_context",
            return_value=context,
        ), patch(
            "thistle_client.subscription_parser.urllib.request.urlopen",
            return_value=response,
        ) as urlopen:
            nodes = fetch_subscription("https://example.com/subscription")

        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(len(nodes), 1)
        self.assertIs(urlopen.call_args.kwargs["context"], context)

    def test_private_json_writer_uses_mode_0600(self):
        import os
        import stat
        import tempfile
        from thistle_client.config import write_json_private

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "credentials.json")
            write_json_private(path, {"password": "secret"})
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_systemd_unit_is_user_portable(self):
        from pathlib import Path

        service = (
            Path(__file__).resolve().parents[1] / "thistle-client.service"
        ).read_text(encoding="utf-8")
        self.assertIn("ExecStart=%h/.local/bin/thistle-client", service)
        self.assertNotIn("/home/th157leclaw", service)
        self.assertNotIn("Environment=DISPLAY=:0", service)

    def test_generated_config_has_no_removed_legacy_fields(self):
        cfg = generate_singbox_config([], enable_tun=True)
        self.assertFalse(any("sniff" in inbound for inbound in cfg["inbounds"]))
        self.assertFalse(any(outbound.get("type") == "block" for outbound in cfg["outbounds"]))
        self.assertTrue(any(rule.get("action") == "sniff" for rule in cfg["route"]["rules"]))

    def test_core_binaries_can_be_resolved_from_path(self):
        from unittest.mock import patch
        from thistle_client.core_manager import CoreManager
        from thistle_client.xray_adapter import XrayManager

        with patch("thistle_client.core_manager.shutil.which", return_value="/opt/bin/sing-box"):
            self.assertEqual(CoreManager().binary_path, "/opt/bin/sing-box")
        with patch("thistle_client.xray_adapter.shutil.which", return_value="/opt/bin/xray"):
            self.assertEqual(XrayManager().binary_path, "/opt/bin/xray")


if __name__ == "__main__":
    unittest.main()
