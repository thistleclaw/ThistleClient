#!/usr/bin/env python3
"""
Configuration and Settings manager for ThistleClient.
Manages persistent user preferences, network tuning, and Sing-box parameters.
"""

import json
import os
import copy

BASE_DIR = os.path.expanduser("~/.local/share/thistle-client")
DATA_DIR = os.path.join(BASE_DIR, "data")
CONFIG_DIR = os.path.expanduser("~/.config/thistle-client")
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")
SUBS_FILE = os.path.join(DATA_DIR, "subscriptions.json")
SINGBOX_CONFIG_FILE = os.path.join(DATA_DIR, "singbox_config.json")
SINGBOX_LOG_FILE = os.path.join(DATA_DIR, "singbox.log")
SINGBOX_PID_FILE = os.path.join(DATA_DIR, "singbox.pid")
XRAY_SOCKS_PORT = 20850

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
        os.makedirs(CONFIG_DIR, exist_ok=True)
        os.makedirs(DATA_DIR, exist_ok=True)
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
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, ensure_ascii=False, indent=2)
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
