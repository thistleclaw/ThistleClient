#!/usr/bin/env python3
"""
Clash REST API client for dynamic Sing-box control.
Provides zero-downtime server switching, traffic monitoring, and latency probes.
"""

import json
import urllib.parse
import urllib.request


class ClashAPI:
    def __init__(self, port: int = 9095, secret: str = ""):
        self.port = port
        self.secret = secret
        self.base_url = f"http://127.0.0.1:{port}"

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.secret:
            h["Authorization"] = f"Bearer {self.secret}"
        return h

    def is_alive(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.base_url}/version", headers=self._headers())
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def get_proxies(self) -> dict:
        """Fetches all proxies and selector groups."""
        try:
            req = urllib.request.Request(f"{self.base_url}/proxies", headers=self._headers())
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("proxies", {})
        except Exception:
            return {}

    def get_current_proxy(self, group: str = "PROXY") -> str:
        """Returns the currently active node tag in the specified group."""
        proxies = self.get_proxies()
        grp = proxies.get(group, {})
        return grp.get("now", "")

    def select_proxy(self, name: str, group: str = "PROXY") -> bool:
        """Dynamically switches active proxy node without restarting the tunnel."""
        try:
            encoded_group = urllib.parse.quote(group)
            url = f"{self.base_url}/proxies/{encoded_group}"
            payload = json.dumps({"name": name}).encode("utf-8")
            req = urllib.request.Request(url, data=payload, headers=self._headers(), method="PUT")
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                return resp.status in (200, 204)
        except Exception:
            return False

    def test_delay(self, name: str, url: str = "http://www.gstatic.com/generate_204", timeout: int = 3000) -> int:
        """Tests latency for a single proxy."""
        try:
            encoded_name = urllib.parse.quote(name)
            encoded_url = urllib.parse.quote(url)
            endpoint = f"{self.base_url}/proxies/{encoded_name}/delay?url={encoded_url}&timeout={timeout}"
            req = urllib.request.Request(endpoint, headers=self._headers())
            with urllib.request.urlopen(req, timeout=timeout / 1000 + 1.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("delay", -1)
        except Exception:
            return -1
