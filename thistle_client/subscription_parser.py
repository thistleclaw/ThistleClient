#!/usr/bin/env python3
"""
Subscription parser for ThistleClient.
Supports: VLESS (Reality, TLS, Vision, WS, gRPC, HTTPUpgrade), Hysteria 2 (with Salamander Obfs),
VMess, Shadowsocks, Trojan, and Base64 subscription feeds.
"""

import base64
import json
import re
import ssl
import urllib.parse
import urllib.request


def safe_b64decode(s: str) -> str:
    """Decodes base64 string with padding and URL-safe handling."""
    s = s.strip().replace(" ", "+")
    missing_padding = len(s) % 4
    if missing_padding:
        s += "=" * (4 - missing_padding)
    try:
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        try:
            return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
        except Exception:
            return ""


def parse_vless(uri: str) -> dict:
    """Parses vless:// URI into a sing-box outbound dictionary."""
    parsed = urllib.parse.urlparse(uri)
    query = urllib.parse.parse_qs(parsed.query)

    uuid = parsed.username
    server = parsed.hostname
    port = parsed.port or 443
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"vless-{server}:{port}"

    net_type = query.get("type", ["tcp"])[0].lower()
    security = query.get("security", ["none"])[0].lower()
    flow = query.get("flow", [""])[0]
    sni = query.get("sni", [""])[0] or server
    fp = query.get("fp", ["chrome"])[0]
    pbk = query.get("pbk", [""])[0]
    sid = query.get("sid", [""])[0]

    raw_query = {k: v[0] for k, v in query.items()}

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": server,
        "server_port": int(port),
        "uuid": uuid,
        "_raw_query": raw_query,
        "_raw_uri": uri
    }

    if flow:
        outbound["flow"] = flow

    if security in ("tls", "reality"):
        tls_dict = {
            "enabled": True,
            "server_name": sni,
            "utls": {"enabled": True, "fingerprint": fp if fp else "chrome"}
        }
        if security == "reality":
            reality_dict = {"enabled": True, "public_key": pbk}
            if sid:
                reality_dict["short_id"] = sid
            tls_dict["reality"] = reality_dict

        if alpn_str := query.get("alpn", [""])[0]:
            tls_dict["alpn"] = [x.strip() for x in alpn_str.split(",") if x.strip()]

        outbound["tls"] = tls_dict

    # Transport protocols
    if net_type == "ws":
        path = query.get("path", ["/"])[0]
        host = query.get("host", [""])[0] or sni
        outbound["transport"] = {
            "type": "ws",
            "path": path,
            "headers": {"Host": host} if host else {}
        }
    elif net_type == "grpc":
        service_name = query.get("serviceName", [""])[0]
        outbound["transport"] = {
            "type": "grpc",
            "service_name": service_name
        }
    elif net_type in ("http", "httpupgrade", "xhttp", "splithttp"):
        path = query.get("path", ["/"])[0]
        host = query.get("host", [""])[0] or sni
        outbound["transport"] = {
            "type": "httpupgrade",
            "path": path,
            "host": host
        }

    return outbound


def parse_hysteria2(uri: str) -> dict:
    """Parses hysteria2:// URI into a sing-box outbound."""
    parsed = urllib.parse.urlparse(uri)
    query = urllib.parse.parse_qs(parsed.query)

    password = parsed.username
    server = parsed.hostname
    port = parsed.port or 443
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"hy2-{server}:{port}"
    sni = query.get("sni", [""])[0] or server
    obfs_type = query.get("obfs", [""])[0]
    obfs_pw = query.get("obfs-password", [""])[0]
    alpn_str = query.get("alpn", [""])[0]

    tls_dict = {
        "enabled": True,
        "server_name": sni,
    }
    if alpn_str:
        tls_dict["alpn"] = [x.strip() for x in alpn_str.split(",") if x.strip()]

    outbound = {
        "type": "hysteria2",
        "tag": tag,
        "server": server,
        "server_port": int(port),
        "password": password,
        "tls": tls_dict
    }
    if obfs_type and obfs_pw:
        outbound["obfs"] = {
            "type": obfs_type,
            "password": obfs_pw
        }
    return outbound


def parse_trojan(uri: str) -> dict:
    """Parses trojan:// URI into a sing-box outbound."""
    parsed = urllib.parse.urlparse(uri)
    query = urllib.parse.parse_qs(parsed.query)

    password = parsed.username
    server = parsed.hostname
    port = parsed.port or 443
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"trojan-{server}:{port}"
    sni = query.get("sni", [""])[0] or server

    outbound = {
        "type": "trojan",
        "tag": tag,
        "server": server,
        "server_port": int(port),
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": sni
        }
    }
    return outbound


def parse_shadowsocks(uri: str) -> dict:
    """Parses ss:// URI into a sing-box outbound."""
    raw = uri[5:]
    tag = "shadowsocks"
    if "#" in raw:
        raw, fragment = raw.split("#", 1)
        tag = urllib.parse.unquote(fragment)

    if "@" in raw:
        user_info, host_port = raw.split("@", 1)
        if ":" not in user_info:
            user_info = safe_b64decode(user_info)
        method, password = user_info.split(":", 1)
        server, port = host_port.split(":", 1)
        if "?" in port:
            port = port.split("?", 1)[0]
    else:
        decoded = safe_b64decode(raw)
        if "@" in decoded and ":" in decoded:
            user_info, host_port = decoded.split("@", 1)
            method, password = user_info.split(":", 1)
            server, port = host_port.split(":", 1)
        else:
            return {}

    return {
        "type": "shadowsocks",
        "tag": tag,
        "server": server,
        "server_port": int(port),
        "method": method,
        "password": password
    }


def parse_vmess(uri: str) -> dict:
    """Parses vmess:// URI into a sing-box outbound."""
    try:
        raw = uri[8:]
        decoded = safe_b64decode(raw)
        data = json.loads(decoded)
        tag = data.get("ps", f"vmess-{data.get('add')}:{data.get('port')}")
        outbound = {
            "type": "vmess",
            "tag": tag,
            "server": data.get("add"),
            "server_port": int(data.get("port", 443)),
            "uuid": data.get("id"),
            "alter_id": int(data.get("aid", 0)),
            "security": data.get("scy", "auto")
        }
        tls = data.get("tls", "")
        if tls in ("tls", "1"):
            outbound["tls"] = {
                "enabled": True,
                "server_name": data.get("sni") or data.get("host") or data.get("add")
            }
        net = data.get("net", "tcp")
        if net == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": data.get("path", "/"),
                "headers": {"Host": data.get("host", "")}
            }
        return outbound
    except Exception:
        return {}


def parse_link(link: str) -> dict:
    """Parses single link of any supported protocol."""
    link = link.strip()
    if link.startswith("vless://"):
        return parse_vless(link)
    elif link.startswith(("hysteria2://", "hy2://")):
        return parse_hysteria2(link)
    elif link.startswith("trojan://"):
        return parse_trojan(link)
    elif link.startswith("ss://"):
        return parse_shadowsocks(link)
    elif link.startswith("vmess://"):
        return parse_vmess(link)
    return {}


def parse_subscription_content(content: str) -> list:
    """Parses raw text content of a subscription feed (plain or base64)."""
    content = content.strip()
    if not content:
        return []

    # If it is base64 encoded list of links
    if not content.startswith(("vless://", "hysteria2://", "hy2://", "vmess://", "ss://", "trojan://", "{", "proxies:")):
        decoded = safe_b64decode(content)
        if decoded:
            content = decoded

    outbounds = []
    seen_tags = set()

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            node = parse_link(line)
            if node and "tag" in node:
                base_tag = node["tag"]
                counter = 1
                while node["tag"] in seen_tags:
                    node["tag"] = f"{base_tag} ({counter})"
                    counter += 1
                seen_tags.add(node["tag"])
                outbounds.append(node)
        except Exception:
            continue

    return outbounds


def fetch_subscription(url: str) -> list:
    """Downloads and parses subscription from URL."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "sing-box/1.12.12 ClashforWindows/0.20.39 ThistleClient/1.0"}
    )
    # Keep the platform CA store and hostname verification enabled. Subscription
    # URLs contain credentials and proxy endpoints, so accepting an invalid
    # certificate would allow a network attacker to replace the feed.
    ctx = ssl.create_default_context()

    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        content = resp.read().decode("utf-8", errors="ignore")
        return parse_subscription_content(content)
