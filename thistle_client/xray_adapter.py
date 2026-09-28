#!/usr/bin/env python3
"""
Xray Core adapter and process manager for ThistleClient.
Provides native support for VLESS Reality (with post-quantum MLKEM768 / spiderX),
SplitHTTP (xhttp), gRPC, and Vision protocols.
"""

import json
import os
import signal
import shutil
import socket
import subprocess
import time
import urllib.parse

from thistle_client.config import DATA_DIR, XRAY_SOCKS_PORT, write_json_private

XRAY_BINARY = "/usr/local/bin/xray"
XRAY_CONFIG_FILE = os.path.join(DATA_DIR, "xray_config.json")
XRAY_PID_FILE = os.path.join(DATA_DIR, "xray.pid")
XRAY_LOG_FILE = os.path.join(DATA_DIR, "xray.log")


def get_default_physical_interface() -> str:
    """Detects the default physical network interface (e.g. wlp2s0, enp3s0)."""
    try:
        res = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=2)
        for line in res.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    iface = parts[idx + 1]
                    if not iface.startswith(("thistle", "tun", "happ", "docker", "veth", "br-", "lo")):
                        return iface
    except Exception:
        pass
    return ""


def is_xray_node(node: dict) -> bool:
    """Checks whether a node is handled by Xray (all VLESS, VMess, Trojan)."""
    if not node:
        return False
    proto = node.get("type", "").lower()
    return proto in ("vless", "vmess", "trojan")



def node_to_xray_outbound(node: dict) -> dict:
    """Translates a subscription node dictionary to an Xray outbound object."""
    proto = node.get("type", "vless").lower()
    tag = node.get("tag", "proxy")
    server = node.get("server", "")
    port = int(node.get("server_port", 443))
    raw_q = node.get("_raw_query", {})

    if proto == "vless":
        uuid = node.get("uuid", "")
        flow = node.get("flow", raw_q.get("flow", ""))
        
        # Determine network transport
        net = raw_q.get("type")
        if not net:
            trans_type = node.get("transport", {}).get("type", "tcp").lower()
            if trans_type in ("httpupgrade", "xhttp", "splithttp"):
                net = "xhttp"
            else:
                net = trans_type
        net = net.lower()

        sec = raw_q.get("security", "").lower()
        if not sec:
            if "reality" in node.get("tls", {}):
                sec = "reality"
            elif node.get("tls", {}).get("enabled"):
                sec = "tls"
            else:
                sec = "none"

        fp = raw_q.get("fp", node.get("tls", {}).get("utls", {}).get("fingerprint", "chrome"))
        sni = raw_q.get("sni", node.get("tls", {}).get("server_name", server))
        pbk = raw_q.get("pbk", node.get("tls", {}).get("reality", {}).get("public_key", ""))
        sid = raw_q.get("sid", node.get("tls", {}).get("reality", {}).get("short_id", ""))
        spx = raw_q.get("spx", "")

        path = raw_q.get("path", node.get("transport", {}).get("path", "/"))
        host = raw_q.get("host", node.get("transport", {}).get("host", sni))
        
        # Check for extra JSON mode (3X-UI format)
        extra_mode = ""
        if "extra" in raw_q:
            try:
                extra_json = json.loads(urllib.parse.unquote(raw_q["extra"]))
                extra_mode = extra_json.get("mode", "")
            except Exception:
                pass
        mode = extra_mode or raw_q.get("mode", "packet-up")

        srv_name = raw_q.get("serviceName", node.get("transport", {}).get("service_name", ""))

        stream_settings = {
            "network": net,
            "security": sec
        }

        if sec == "reality":
            reality_dict = {
                "show": False,
                "fingerprint": fp or "chrome",
                "serverName": sni,
                "publicKey": pbk
            }
            if sid:
                reality_dict["shortId"] = sid
            if spx:
                reality_dict["spiderX"] = spx
            stream_settings["realitySettings"] = reality_dict
        elif sec == "tls":
            stream_settings["tlsSettings"] = {
                "serverName": sni,
                "fingerprint": fp or "chrome"
            }
            if alpn := node.get("tls", {}).get("alpn"):
                stream_settings["tlsSettings"]["alpn"] = alpn

        if net in ("xhttp", "splithttp"):
            xhttp_dict = {
                "path": path or "/",
                "mode": mode or "packet-up"
            }
            if host:
                xhttp_dict["host"] = host
            stream_settings["xhttpSettings"] = xhttp_dict
        elif net == "grpc":
            stream_settings["grpcSettings"] = {
                "serviceName": srv_name
            }
        elif net == "ws":
            stream_settings["wsSettings"] = {
                "path": path or "/",
                "headers": {"Host": host} if host else {}
            }

        return {
            "protocol": "vless",
            "tag": tag,
            "settings": {
                "vnext": [{
                    "address": server,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "encryption": "none",
                        "flow": flow
                    }]
                }]
            },
            "streamSettings": stream_settings
        }

    elif proto == "trojan":
        password = node.get("password", "")
        sni = node.get("tls", {}).get("server_name", server)
        return {
            "protocol": "trojan",
            "tag": tag,
            "settings": {
                "servers": [{
                    "address": server,
                    "port": port,
                    "password": password
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"serverName": sni}
            }
        }

    elif proto == "shadowsocks":
        return {
            "protocol": "shadowsocks",
            "tag": tag,
            "settings": {
                "servers": [{
                    "address": server,
                    "port": port,
                    "method": node.get("method", "aes-256-gcm"),
                    "password": node.get("password", "")
                }]
            }
        }

    return {}


class XrayManager:
    def __init__(self, binary_path: str = None):
        self.binary_path = binary_path or shutil.which("xray") or XRAY_BINARY
        self.pid_file = XRAY_PID_FILE
        self.log_file = XRAY_LOG_FILE
        self.config_file = XRAY_CONFIG_FILE
        self.process = None

    def is_running(self) -> bool:
        if os.path.exists(self.pid_file):
            try:
                with open(self.pid_file, "r") as f:
                    pid = int(f.read().strip())
                os.kill(pid, 0)
                return self._is_managed_process(pid)
            except (OSError, ValueError):
                pass
        return False

    def _is_managed_process(self, pid: int) -> bool:
        """Refuse to treat another VPN client's Xray as ours."""
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as proc_file:
                argv = [arg.decode(errors="replace") for arg in proc_file.read().split(b"\0") if arg]
            if not argv or os.path.basename(argv[0]) != os.path.basename(self.binary_path):
                return False
            for index, arg in enumerate(argv[:-1]):
                if arg in ("-c", "--config"):
                    return os.path.realpath(argv[index + 1]) == os.path.realpath(self.config_file)
            return False
        except (OSError, ValueError):
            return False

    def start(self, node: dict, listen_port: int = XRAY_SOCKS_PORT) -> bool:
        """Starts Xray routing outbound traffic for the specified node."""
        self.stop()

        outbound = node_to_xray_outbound(node)
        if not outbound:
            return False

        hosts = {
            "dns.google": "8.8.8.8",
            "cloudflare-dns.com": "1.1.1.1"
        }
        srv = node.get("server", "").strip()
        if srv:
            try:
                ip = socket.gethostbyname(srv)
                hosts[srv] = ip
            except Exception:
                pass

        config = {
            "log": {
                "loglevel": "warning"
            },
            "dns": {
                "hosts": hosts,
                "servers": [
                    "8.8.8.8",
                    "1.1.1.1"
                ]
            },
            "inbounds": [
                {
                    "port": listen_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True
                    }
                }
            ],
            "outbounds": [
                outbound,
                {
                    "protocol": "freedom",
                    "tag": "direct"
                }
            ]
        }

        os.makedirs(os.path.dirname(self.config_file), mode=0o700, exist_ok=True)
        write_json_private(self.config_file, config)

        try:
            log_fd = open(self.log_file, "a")
            self.process = subprocess.Popen(
                [self.binary_path, "run", "-c", self.config_file],
                stdout=log_fd,
                stderr=log_fd,
                preexec_fn=os.setsid
            )
            with open(self.pid_file, "w") as f:
                f.write(str(self.process.pid))

            time.sleep(0.5)
            return self.is_running()
        except Exception as e:
            print(f"[XrayManager] Failed to start xray: {e}")
            return False

    def stop(self) -> bool:
        if os.path.exists(self.pid_file):
            try:
                with open(self.pid_file, "r") as f:
                    pid = int(f.read().strip())
                if self._is_managed_process(pid):
                    try:
                        pgid = os.getpgid(pid)
                        if pgid == pid:
                            os.killpg(pgid, signal.SIGTERM)
                        else:
                            os.kill(pid, signal.SIGTERM)
                    except OSError:
                        pass
                    deadline = time.monotonic() + 1.0
                    while time.monotonic() < deadline:
                        try:
                            os.kill(pid, 0)
                        except OSError:
                            break
                        time.sleep(0.05)
                    else:
                        try:
                            if os.getpgid(pid) == pid:
                                os.killpg(pid, signal.SIGKILL)
                            else:
                                os.kill(pid, signal.SIGKILL)
                        except OSError:
                            pass
            except Exception:
                pass
            finally:
                if os.path.exists(self.pid_file):
                    os.remove(self.pid_file)
        return not self.is_running()
