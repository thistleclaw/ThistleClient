#!/usr/bin/env python3
"""
Process manager for ThistleClient Hybrid Core.
Supervises background lifecycle of Sing-box (TUN driver & DNS hijack)
and Xray-core (VLESS Reality with MLKEM768/spiderX, SplitHTTP, gRPC, and Vision).
"""

import json
import os
import re
import shutil
import subprocess
import time
from thistle_client.config import SINGBOX_CONFIG_FILE, SINGBOX_LOG_FILE, SINGBOX_PID_FILE, XRAY_SOCKS_PORT
from thistle_client.xray_adapter import XrayManager, is_xray_node


from thistle_client.process_lifecycle import matches_process, managed_pids, stop_processes


def _is_managed_singbox_process(pid: int, binary_path: str = "/usr/local/bin/sing-box",
                                config_path: str = SINGBOX_CONFIG_FILE) -> bool:
    return matches_process(pid, binary_path, config_path)


def _tun_route_conflict(config_path: str) -> str:
    """Return a reason when the configured TUN table or rule slot is occupied."""
    try:
        with open(config_path, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)
        tun = next(inbound for inbound in config.get("inbounds", []) if inbound.get("type") == "tun")
        table_index = int(tun["iproute2_table_index"])
        rule_index = int(tun["iproute2_rule_index"])
    except StopIteration:
        return ""
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return "cannot validate TUN routing configuration"

    for family in ("-4", "-6"):
        try:
            rules = subprocess.run(
                ["ip", family, "rule", "show"], capture_output=True, text=True, timeout=2
            )
        except (OSError, subprocess.TimeoutExpired):
            return f"cannot inspect {family} policy routes"
        if rules.returncode != 0:
            return f"cannot inspect {family} policy routes"
        for line in rules.stdout.splitlines():
            priority_text, _, rule = line.partition(":")
            try:
                priority = int(priority_text.strip())
            except ValueError:
                continue
            if priority == rule_index:
                return f"policy rule priority {rule_index} is already in use ({family})"
            if re.search(rf"\b(?:lookup|table)\s+{table_index}(?:\s|$)", rule):
                return f"routing table {table_index} is already referenced ({family})"

        try:
            routes = subprocess.run(
                ["ip", family, "route", "show", "table", str(table_index)],
                capture_output=True, text=True, timeout=2,
            )
        except (OSError, subprocess.TimeoutExpired):
            return f"cannot inspect routing table {table_index} ({family})"
        if routes.returncode != 0:
            if "FIB table does not exist" in routes.stderr:
                continue
            return f"cannot inspect routing table {table_index} ({family})"
        if routes.stdout.strip():
            return f"routing table {table_index} already contains routes ({family})"
    return ""


def check_conflicting_vpns() -> str:
    """Checks if another VPN client (e.g. Happ, singbox-tray, or foreign sing-box) is currently running."""
    my_pid = os.getpid()
    try:
        res = subprocess.run(["pgrep", "-f", "happ|singbox-tray"], capture_output=True, text=True)
        for pid_str in res.stdout.strip().split():
            try:
                pid = int(pid_str)
                if pid == my_pid:
                    continue
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = f.read().lower()
                    if b"grep" in cmd or b"pgrep" in cmd:
                        continue
                    if (b"/opt/happ" in cmd or b"/happ" in cmd or cmd.startswith(b"happ")) and b"python" not in cmd:
                        return "Happ"
                    if b"singbox-tray" in cmd and b"python" not in cmd:
                        return "singbox-tray"
            except Exception:
                pass
    except Exception:
        pass

    try:
        res = subprocess.run(["pgrep", "-x", "sing-box"], capture_output=True, text=True)
        for pid_str in res.stdout.strip().split():
            try:
                pid = int(pid_str)
                try:
                    from thistle_client.pinger import is_active_test_process
                    if is_active_test_process(pid):
                        continue
                except ImportError:
                    pass
                if _is_managed_singbox_process(pid):
                    continue
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = f.read().lower()
                    if not cmd:
                        continue
                    if b"happ" in cmd:
                        return "Happ"
                    return f"sing-box (PID {pid})"
            except Exception:
                pass
    except Exception:
        pass
    return ""


class CoreManager:
    def __init__(self, binary_path: str = None, config_path: str = SINGBOX_CONFIG_FILE):
        self.binary_path = binary_path or shutil.which("sing-box") or "/usr/local/bin/sing-box"
        self.config_path = config_path
        self.pid_file = SINGBOX_PID_FILE
        self.log_file = SINGBOX_LOG_FILE
        self.process = None
        self.xray = XrayManager()
        self.current_node = None
        self.last_error = ""

    def is_conflict_running(self) -> str:
        """Returns name of conflicting VPN process if detected."""
        return check_conflicting_vpns()

    def is_running(self) -> bool:
        """Checks whether sing-box is currently running."""
        return bool(managed_pids(self, self.config_path))

    def start(self, active_node: dict = None) -> bool:
        """Launches core processes (Sing-box TUN + Xray backend if needed)."""
        self.last_error = ""
        if active_node is not None:
            self.current_node = active_node
        node_to_use = active_node if active_node is not None else self.current_node

        if self.is_running():
            return True
        if not os.path.exists(self.config_path):
            self.last_error = "Конфигурация VPN не найдена."
            return False

        conflict = self.is_conflict_running()
        if conflict:
            self.last_error = f"Обнаружен работающий {conflict}. Остановите его перед подключением."
            return False
        route_conflict = _tun_route_conflict(self.config_path)
        if route_conflict:
            self.last_error = f"Конфликт маршрутов: {route_conflict}"
            return False

        # If node requires Xray (Reality, XHTTP), start Xray
        if node_to_use and is_xray_node(node_to_use):
            if not self.xray.start(node_to_use, listen_port=XRAY_SOCKS_PORT):
                self.last_error = self.xray.last_error or "Не удалось запустить Xray."
                return False
        else:
            if not self.xray.stop():
                self.last_error = self.xray.last_error
                return False

        try:
            with open(self.log_file, "a") as log_fd:
                self.process = subprocess.Popen(
                    [self.binary_path, "run", "-c", self.config_path],
                    stdout=log_fd, stderr=log_fd, start_new_session=True,
                )
            with open(self.pid_file, "w") as f:
                f.write(str(self.process.pid))

            time.sleep(1)
            if self.is_running():
                return True
            self.last_error = "Ядро sing-box завершилось при запуске. Проверьте журнал."
        except Exception as e:
            self.last_error = f"Не удалось запустить sing-box: {e}"
        self.stop()
        return False

    def switch_node(self, node: dict) -> bool:
        """Select a node and report failures from both core and selector."""
        if not node:
            self.last_error = "Сервер не выбран."
            return False
        if not self.is_running():
            return self.start(node)
        from thistle_client.clash_api import ClashAPI
        from thistle_client.config import settings
        clash = ClashAPI(port=int(settings.get("network", "clash_port", 9095)))
        if is_xray_node(node):
            if not self.xray.start(node, listen_port=XRAY_SOCKS_PORT):
                self.last_error = self.xray.last_error or "Не удалось переключить Xray."
                return False
            selected = clash.select_proxy("xray-out")
        else:
            selected = clash.select_proxy(node.get("tag", ""))
            if selected:
                self.xray.stop()
        if selected:
            self.current_node = node
            self.last_error = ""
            return True
        return self.restart(node)

    def stop(self) -> bool:
        """Keep ownership metadata until both cores have actually stopped."""
        stopped = stop_processes(self, self.config_path)
        xray_stopped = self.xray.stop() if stopped else False
        if stopped and not xray_stopped:
            self.last_error = self.xray.last_error
        return stopped and xray_stopped

    def restart(self, active_node: dict = None) -> bool:
        if not self.stop():
            return False
        return self.start(active_node if active_node is not None else self.current_node)

    def get_recent_logs(self, max_lines: int = 25) -> str:
        """Retrieves recent lines from singbox.log."""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    return "".join(lines[-max_lines:])
            except Exception as e:
                return f"Error reading log: {e}"
        return "Log is empty."

    def clear_logs(self):
        """Truncates singbox.log."""
        try:
            with open(self.log_file, "w") as f:
                f.truncate(0)
        except Exception:
            pass
