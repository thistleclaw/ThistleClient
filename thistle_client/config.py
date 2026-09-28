#!/usr/bin/env python3
"""
Configuration and Settings manager for ThistleClient.
Manages persistent user preferences, network tuning, and Sing-box parameters.
"""

import json
import os
import copy
import tempfile

BASE_DIR = os.path.expanduser("~/.local/share/thistle-client")
DATA_DIR = os.path.join(BASE_DIR, "data")
CONFIG_DIR = os.path.expanduser("~/.config/thistle-client")
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")
SUBS_FILE = os.path.join(DATA_DIR, "subscriptions.json")
SINGBOX_CONFIG_FILE = os.path.join(DATA_DIR, "singbox_config.json")
SINGBOX_LOG_FILE = os.path.join(DATA_DIR, "singbox.log")
SINGBOX_PID_FILE = os.path.join(DATA_DIR, "singbox.pid")
XRAY_SOCKS_PORT = 20850


def _ensure_private_dir(path: str) -> None:
    """Create a directory and keep it private to the current user."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def write_json_private(path: str, data, *, indent: int = 2) -> None:
    """Atomically write credential-bearing JSON with mode 0600."""
    directory = os.path.dirname(path) or "."
    _ensure_private_dir(directory)
    fd, tmp_path = tempfile.mkstemp(prefix=".thistle-", suffix=".tmp", dir=directory, text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=indent)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


DEFAULT_SETTINGS = {
    "ping": {
        "method": "Proxy-GET",         # Options: "Proxy-GET", "TCP", "Proxy-HEAD", "ICMP"
        "timeout": 4,            # Seconds (1 to 15)
        "url": "http://connectivity-check.ubuntu.com",
        "parallel_workers": 8,
        "auto_ping_on_load": False
    },
    "network": {
        "stack": "mixed",        # "mixed", "system", "gvisor"
        "interface_name": "thistle0",
        "mtu": 1500,
        "auto_route": True,
        "strict_route": True,
        "table_index": 2024,
        "rule_index": 9100,
        "mixed_port": 2080,
        "clash_port": 9095
    },
    "dns": {
        "remote_server": "8.8.8.8",
        "remote_type": "udp",
        "domain_resolver": "dns-direct",
        "strategy": "prefer_ipv4",
        "independent_cache": True,
        "hijack_dns": True
    },
    "routing": {
        "bypass_private": True,
        "auto_detect_interface": True,
        "final_outbound": "PROXY",
        "urltest_interval": "5m",
        "urltest_tolerance": 50
    },
    "app": {
        "autostart": True,
        "notifications": True,
        "close_to_tray": True,       # Minimize window to tray on close
        "tray_theme": "monochrome",  # "monochrome" or "color"
        "log_level": "warn"          # "warn", "info", "debug", "trace"
    }
}


class SettingsManager:
    def __init__(self):
        _ensure_private_dir(CONFIG_DIR)
        _ensure_private_dir(DATA_DIR)
        for sensitive_file in (SETTINGS_FILE, SUBS_FILE, SINGBOX_CONFIG_FILE):
            try:
                if os.path.isfile(sensitive_file):
                    os.chmod(sensitive_file, 0o600)
            except OSError:
                pass
        self.settings = copy.deepcopy(DEFAULT_SETTINGS)
        self.load()

    def load(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._deep_update(self.settings, data)
            except Exception as e:
                print(f"[SettingsManager] Error reading settings: {e}")

    def save(self):
        try:
            write_json_private(SETTINGS_FILE, self.settings)
        except Exception as e:
            print(f"[SettingsManager] Error saving settings: {e}")

    def get(self, section: str, key: str, default=None):
        return self.settings.get(section, {}).get(key, default)

    def set(self, section: str, key: str, value):
        if section not in self.settings:
            self.settings[section] = {}
        self.settings[section][key] = value
        self.save()

    def reset_defaults(self):
        self.settings = copy.deepcopy(DEFAULT_SETTINGS)
        self.save()

    def _deep_update(self, target: dict, source: dict):
        for k, v in source.items():
            if isinstance(v, dict) and k in target and isinstance(target[k], dict):
                self._deep_update(target[k], v)
            else:
                target[k] = v


settings = SettingsManager()
