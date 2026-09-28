#!/usr/bin/env python3
"""
Sing-box configuration generator for ThistleClient.
Generates compliant sing-box 1.12+ JSON incorporating all user settings and parameters.
"""

import ipaddress
import json
import socket
from thistle_client.config import settings, XRAY_SOCKS_PORT
from thistle_client.xray_adapter import is_xray_node


def generate_singbox_config(outbounds: list, active_tag: str = "", enable_tun: bool = True) -> dict:
    """Generates complete sing-box 1.12 configuration based on user settings."""
    net_stack = settings.get("network", "stack", "mixed")
    iface_name = settings.get("network", "interface_name", "thistle0")
    mtu = int(settings.get("network", "mtu", 1500))
    table_idx = int(settings.get("network", "table_index", 2024))
    rule_idx = int(settings.get("network", "rule_index", 9100))
    strict_route = bool(settings.get("network", "strict_route", True))
    auto_route = bool(settings.get("network", "auto_route", True))
    mixed_port = int(settings.get("network", "mixed_port", 2080))
    clash_port = int(settings.get("network", "clash_port", 9095))

    dns_remote_server = settings.get("dns", "remote_server", "8.8.8.8")
    dns_remote_type = settings.get("dns", "remote_type", "https")
    dns_strategy = settings.get("dns", "strategy", "prefer_ipv4")
    dns_cache = bool(settings.get("dns", "independent_cache", True))
    hijack_dns = bool(settings.get("dns", "hijack_dns", True))

    bypass_private = bool(settings.get("routing", "bypass_private", True))
    auto_detect_iface = bool(settings.get("routing", "auto_detect_interface", True))
    urltest_interval = settings.get("routing", "urltest_interval", "5m")
    urltest_tolerance = int(settings.get("routing", "urltest_tolerance", 50))
    log_level = settings.get("app", "log_level", "warn")

    # Sanitize and deduplicate tags, stripping internal metadata keys
    reserved = {"PROXY", "AUTO", "direct", "xray-out"}
    native_outbounds = []
    seen = set(reserved)
    for node in outbounds:
        if is_xray_node(node):
            continue
        node_copy = {k: v for k, v in node.items() if not k.startswith("_")}
        base_tag = node_copy.get("tag", "node")
        tag = base_tag
        counter = 1
        while tag in seen:
            tag = f"{base_tag} ({counter})"
            counter += 1
        seen.add(tag)
        node_copy["tag"] = tag
        native_outbounds.append(node_copy)

    native_tags = [n["tag"] for n in native_outbounds]

    active_node = next((n for n in outbounds if n.get("tag") == active_tag), None)
    if active_tag == "direct":
        default_out = "direct"
    elif active_node and is_xray_node(active_node):
        default_out = "xray-out"
    elif active_tag in native_tags:
        default_out = active_tag
    elif outbounds and is_xray_node(outbounds[0]):
        default_out = "xray-out"
    else:
        default_out = native_tags[0] if native_tags else "xray-out"

    inbounds = [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": mixed_port,
            "sniff": True
        }
    ]

    if enable_tun:
        inbounds.insert(0, {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": iface_name,
            "address": ["172.19.0.1/30"],
            "mtu": mtu,
            "auto_route": auto_route,
            "strict_route": strict_route,
            "iproute2_table_index": table_idx,
            "iproute2_rule_index": rule_idx,
            "stack": net_stack,
            "sniff": True
        })

    # Collect all VPN server endpoints to ensure direct routing and local DNS bootstrap
    server_domains = set()
    server_ips_cidr = set()
    for node in outbounds:
        srv = node.get("server", "").strip()
        if srv:
            try:
                ip = ipaddress.ip_address(srv)
                server_ips_cidr.add(f"{ip}/32" if ip.version == 4 else f"{ip}/128")
            except ValueError:
                server_domains.add(srv)
                try:
                    resolved_ip = socket.gethostbyname(srv)
                    server_ips_cidr.add(f"{resolved_ip}/32")
                except Exception:
                    pass

    # Build policy routing rules
    route_rules = [
        {
            "outbound": "direct",
            "process_name": [
                "xray",
                "sing-box",
                "xray.exe",
                "sing-box.exe"
            ]
        }
    ]

    if server_ips_cidr:
        route_rules.append({
            "ip_cidr": sorted(list(server_ips_cidr)),
            "outbound": "direct"
        })
    if server_domains:
        route_rules.append({
            "domain": sorted(list(server_domains)),
            "outbound": "direct"
        })

    if hijack_dns:
        route_rules.append({
            "action": "sniff"
        })
        route_rules.append({
            "protocol": "dns",
            "action": "hijack-dns"
        })
        route_rules.append({
            "port": [53],
            "action": "hijack-dns"
        })
    if bypass_private:
        route_rules.append({
            "ip_is_private": True,
            "outbound": "direct"
        })

    # DNS rules: VPN server domains must be resolved directly through direct UDP DNS
    dns_rules = []
    if server_domains:
        dns_rules.append({
            "domain": sorted(list(server_domains)),
            "server": "dns-direct"
        })

    # Always provide Xray SOCKS bridge for Reality/XHTTP nodes
    xray_bridge = {
        "type": "socks",
        "tag": "xray-out",
        "server": "127.0.0.1",
        "server_port": XRAY_SOCKS_PORT,
        "udp_fragment": True
    }

    final_outbounds = [
        {
            "type": "selector",
            "tag": "PROXY",
            "outbounds": ["xray-out"] + native_tags,
            "default": default_out
        },
        xray_bridge,
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ] + native_outbounds

    dns_server = str(dns_remote_server or "8.8.8.8").strip()
    try:
        ipaddress.ip_address(dns_server)
    except ValueError:
        # A hostname here could require resolving through itself while the TUN
        # is active. Keep the bootstrap resolver numeric to prevent recursion.
        dns_server = "8.8.8.8"
    config = {
        "log": {
            "level": log_level,
            "timestamp": True
        },
        "dns": {
            "servers": [
                {
                    "tag": "dns-direct",
                    "type": "udp",
                    "server": dns_server,
                    "server_port": 53,
                }
            ],
            "rules": dns_rules,
            "strategy": dns_strategy,
            "independent_cache": dns_cache
        },
        "inbounds": inbounds,
        "outbounds": final_outbounds,
        "route": {
            "default_domain_resolver": "dns-direct",
            "rules": route_rules,
            "auto_detect_interface": auto_detect_iface,
            "final": "PROXY"
        },
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{clash_port}",
                "external_ui": "",
                "secret": ""
            }
        }
    }

    return config
