#!/usr/bin/env python3
"""
Multi-mode latency measurement engine for ThistleClient.
Supports:
- Proxy-GET (true end-to-end HTTP latency via isolated multi-inbound test cores)
- TCP Handshake (port-level direct round-trip latency)
- ICMP Echo (system-level ping to server host)
- Proxy-HEAD (proxy tunnel latency via Clash REST API)
"""

import atexit
import json
import os
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from thistle_client.xray_adapter import node_to_xray_outbound, is_xray_node

_active_test_procs = set()
_process_lock = threading.Lock()
_batch_lock = threading.Lock()


def _register_test_process(argv: list) -> subprocess.Popen:
    """Start and track only a process group created for a temporary latency probe."""
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    with _process_lock:
        _active_test_procs.add(proc)
    return proc


def _signal_test_process(proc: subprocess.Popen, sig: int) -> None:
    """Signal the private process group, falling back to its owned leader."""
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            if sig == signal.SIGTERM:
                proc.terminate()
            else:
                proc.kill()
        except OSError:
            pass


def _terminate_and_reap(proc: subprocess.Popen) -> None:
    """Stop an owned probe core and always wait for its direct child."""
    if proc.poll() is None:
        _signal_test_process(proc, signal.SIGTERM)
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            _signal_test_process(proc, signal.SIGKILL)
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                # Keep it registered so the exit cleanup gets another chance.
                return
    else:
        proc.wait()

    with _process_lock:
        _active_test_procs.discard(proc)


def _cleanup_test_procs():
    """Reap all probe cores still owned by this process at interpreter exit."""
    with _process_lock:
        procs = list(_active_test_procs)
    for proc in procs:
        try:
            _terminate_and_reap(proc)
        except Exception:
            pass


def is_active_test_process(pid: int) -> bool:
    """Identify this process's short-lived probe core for conflict checks."""
    with _process_lock:
        return any(proc.pid == pid for proc in _active_test_procs)


atexit.register(_cleanup_test_procs)


def _get_free_ports(count: int) -> list:
    """Find N distinct loopback ports for one serialized probe batch."""
    if count <= 0:
        return []
    socks = []
    ports = []
    for _ in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        ports.append(s.getsockname()[1])
        socks.append(s)
    for s in socks:
        s.close()
    return ports


class MultiModePinger:
    def __init__(self, mixed_port: int = 2080, clash_port: int = 9095):
        self.mixed_port = mixed_port
        self.clash_port = clash_port

    def ping_tcp(self, host: str, port: int, timeout: int = 3) -> int:
        """Measures TCP SYN-ACK connection latency directly to server port."""
        if not host or not port:
            return -1
        t0 = time.perf_counter()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, int(port)))
            ms = round((time.perf_counter() - t0) * 1000)
            sock.close()
            return max(1, ms)
        except Exception:
            return -1

    def ping_icmp(self, host: str, timeout: int = 3) -> int:
        """Measures ICMP round-trip latency using system ping."""
        if not host:
            return -1
        try:
            res = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), host],
                capture_output=True,
                text=True,
                timeout=timeout + 1
            )
            m = re.search(r"time=([\d\.]+)\s*ms", res.stdout)
            if m:
                return round(float(m.group(1)))
            return -1
        except Exception:
            return -1

    def ping_proxy_head(self, tag: str, test_url: str = "http://connectivity-check.ubuntu.com", timeout: int = 3) -> int:
        """Measures proxy latency via Clash REST API HEAD request."""
        try:
            encoded_tag = urllib.parse.quote(tag)
            encoded_url = urllib.parse.quote(test_url)
            timeout_ms = timeout * 1000
            endpoint = f"http://127.0.0.1:{self.clash_port}/proxies/{encoded_tag}/delay?url={encoded_url}&timeout={timeout_ms}"
            req = urllib.request.Request(endpoint)
            with urllib.request.urlopen(req, timeout=timeout + 1.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("delay", -1)
        except Exception:
            return -1

    def ping_proxy_get_batch(self, nodes: list, timeout: int = 4,
                             test_url: str = "http://connectivity-check.ubuntu.com",
                             on_progress=None, max_workers: int = 16) -> dict:
        # Keep free-port allocation, startup, requests, and teardown in one
        # critical section so concurrent callers cannot race on loopback ports.
        with _batch_lock:
            return self._ping_proxy_get_batch_locked(
                nodes, timeout, test_url, on_progress, max_workers
            )

    def _ping_proxy_get_batch_locked(self, nodes: list, timeout: int,
                                     test_url: str, on_progress, max_workers: int) -> dict:
        """Measure a complete HTTP GET through isolated, loopback-only proxies."""
        results = {}
        if not nodes:
            return results

        try:
            timeout = max(1, min(int(timeout), 60))
            parsed_url = urllib.parse.urlsplit(test_url)
            if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
                raise ValueError("Proxy-GET URL must be an absolute HTTP or HTTPS URL")
        except (TypeError, ValueError):
            for node in nodes:
                tag = node.get("tag", "")
                results[tag] = -1
                if on_progress:
                    try:
                        on_progress(tag, -1)
                    except Exception:
                        pass
            return results

        xray_nodes = []
        sb_nodes = []
        for idx, n in enumerate(nodes):
            if is_xray_node(n):
                xray_nodes.append((idx, n))
            else:
                sb_nodes.append((idx, n))

        procs_to_kill = []
        tmp_files = []
        reported = set()

        def report(idx: int, delay: int) -> None:
            if idx in reported:
                return
            reported.add(idx)
            tag = nodes[idx].get("tag", "")
            results[tag] = delay
            if on_progress:
                try:
                    on_progress(tag, delay)
                except Exception:
                    pass

        def write_config(config: dict) -> str:
            handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            tmp_files.append(handle.name)
            try:
                with handle:
                    json.dump(config, handle)
            except Exception:
                try:
                    os.unlink(handle.name)
                    tmp_files.remove(handle.name)
                except OSError:
                    pass
                raise
            return handle.name

        def wait_for_listeners(proc: subprocess.Popen, ports: list, startup_timeout: float) -> set:
            pending = set(ports)
            deadline = time.monotonic() + startup_timeout
            while pending and proc.poll() is None:
                for port in tuple(pending):
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            pending.remove(port)
                    except OSError:
                        pass
                if pending:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(0.025, remaining))
            return set(ports) - pending

        def curl_get(proxy_url: str) -> int:
            """Return curl's transfer time only when an HTTP response completed."""
            try:
                completed = subprocess.run(
                    [
                        "curl", "--silent", "--show-error", "--request", "GET",
                        "--output", os.devnull, "--write-out", "%{http_code} %{time_total}",
                        "--noproxy", "", "--proxy", proxy_url,
                        "--connect-timeout", str(timeout), "--max-time", str(timeout), test_url,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=timeout + 1.0,
                    check=False,
                )
                if completed.returncode != 0:
                    return -1
                status_text, elapsed_text = completed.stdout.strip().split()
                status = int(status_text)
                elapsed = float(elapsed_text)
                if not 200 <= status < 400 or elapsed < 0:
                    return -1
                return max(1, round(elapsed * 1000))
            except (OSError, ValueError, subprocess.TimeoutExpired):
                return -1

        try:
            # Reserve one unique set before either core starts. A batch lock keeps
            # another ThistleClient measurement from selecting the same ports.
            ports = _get_free_ports(len(nodes))
            port_by_idx = {idx: ports[idx] for idx in range(len(nodes))}

            if xray_nodes:
                inbounds = []
                outbounds = []
                rules = []
                for i, (orig_idx, n) in enumerate(xray_nodes):
                    in_tag = f"in_{i}"
                    out_ob = node_to_xray_outbound(n)
                    # Apply SNI reality fix if speedtest.net without www
                    sec = out_ob.get("streamSettings", {}).get("realitySettings", {})
                    if sec.get("serverName", "").lower() == "speedtest.net":
                        sec["serverName"] = "www.speedtest.net"
                    out_tag = f"out_{i}"
                    out_ob["tag"] = out_tag
                    inbounds.append({
                        "tag": in_tag,
                        "port": port_by_idx[orig_idx],
                        "listen": "127.0.0.1",
                        "protocol": "socks",
                        "settings": {"auth": "noauth", "udp": True}
                    })
                    outbounds.append(out_ob)
                    rules.append({
                        "type": "field",
                        "inboundTag": [in_tag],
                        "outboundTag": out_tag
                    })

                xray_hosts = {
                    "dns.google": "8.8.8.8",
                    "cloudflare-dns.com": "1.1.1.1",
                }
                for _, n in xray_nodes:
                    srv = n.get("server", "").strip()
                    if srv and srv not in xray_hosts:
                        try:
                            xray_hosts[srv] = socket.gethostbyname(srv)
                        except Exception:
                            pass

                xray_cfg = {
                    "log": {"loglevel": "error"},
                    "dns": {
                        "hosts": xray_hosts,
                        "servers": ["8.8.8.8", "1.1.1.1"]
                    },
                    "inbounds": inbounds,
                    "outbounds": outbounds,
                    "routing": {
                        "domainStrategy": "AsIs",
                        "rules": rules
                    }
                }
                xray_config = write_config(xray_cfg)
                px = _register_test_process(["xray", "run", "-c", xray_config])
                procs_to_kill.append(px)

            if sb_nodes:
                sb_inbounds = []
                sb_outbounds = []
                sb_rules = []
                for j, (orig_idx, n) in enumerate(sb_nodes):
                    in_tag = f"sb_in_{j}"
                    out_tag = f"sb_out_{j}"
                    clean = {k: v for k, v in n.items() if not k.startswith("_")}
                    clean["tag"] = out_tag
                    sb_inbounds.append({
                        "type": "mixed",
                        "tag": in_tag,
                        "listen": "127.0.0.1",
                        "listen_port": port_by_idx[orig_idx]
                    })
                    sb_outbounds.append(clean)
                    sb_rules.append({
                        "inbound": in_tag,
                        "outbound": out_tag
                    })

                sb_cfg = {
                    "log": {"level": "error"},
                    "dns": {
                        "servers": [{
                            "tag": "dns-direct",
                            "type": "udp",
                            "server": "8.8.8.8",
                        }],
                    },
                    "inbounds": sb_inbounds,
                    "outbounds": sb_outbounds + [{"type": "direct", "tag": "direct"}],
                    "route": {
                        "rules": sb_rules,
                        "final": "direct",
                        "default_domain_resolver": "dns-direct",
                    }
                }
                singbox_config = write_config(sb_cfg)
                ps = _register_test_process(["sing-box", "run", "-c", singbox_config])
                procs_to_kill.append(ps)

            startup_timeout = min(5.0, max(1.0, float(timeout)))
            ready_by_idx = {}
            xray_ready = set()
            sb_ready = set()
            if xray_nodes:
                xray_ready = wait_for_listeners(
                    px, [port_by_idx[idx] for idx, _ in xray_nodes], startup_timeout
                )
                ready_by_idx.update({idx: port_by_idx[idx] in xray_ready for idx, _ in xray_nodes})
            if sb_nodes:
                sb_ready = wait_for_listeners(
                    ps, [port_by_idx[idx] for idx, _ in sb_nodes], startup_timeout
                )
                ready_by_idx.update({idx: port_by_idx[idx] in sb_ready for idx, _ in sb_nodes})

            tasks = []
            for i, (orig_idx, n) in enumerate(xray_nodes):
                if ready_by_idx.get(orig_idx):
                    tasks.append((orig_idx, True, port_by_idx[orig_idx], n))
                else:
                    report(orig_idx, -1)
            for j, (orig_idx, n) in enumerate(sb_nodes):
                if ready_by_idx.get(orig_idx):
                    tasks.append((orig_idx, False, port_by_idx[orig_idx], n))
                else:
                    report(orig_idx, -1)

            def test_worker(item):
                idx, is_x, port, node = item
                proxy_url = f"socks5h://127.0.0.1:{port}" if is_x else f"http://127.0.0.1:{port}"
                return idx, curl_get(proxy_url)

            if tasks:
                try:
                    workers = max(1, min(16, int(max_workers), len(tasks)))
                except (TypeError, ValueError):
                    workers = min(16, len(tasks))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = [pool.submit(test_worker, task) for task in tasks]
                    for future in as_completed(futures):
                        idx, delay = future.result()
                        report(idx, delay)
        except Exception as exc:
            print(f"[Ping] Proxy-GET batch failed: {type(exc).__name__}: {exc}")

        finally:
            for idx in range(len(nodes)):
                report(idx, -1)

            # Stop only process groups created above, then reap every leader.
            for proc in procs_to_kill:
                try:
                    _terminate_and_reap(proc)
                except Exception:
                    pass
            for path in tmp_files:
                try:
                    os.unlink(path)
                except Exception:
                    pass

        return results

    def ping_all(self, nodes: list, method: str = "Proxy-GET", timeout: int = 4,
                 test_url: str = "http://connectivity-check.ubuntu.com",
                 clash_api=None, max_workers: int = 8,
                 on_progress=None) -> dict:
        """Pings all nodes with real-time on_progress callback without touching the active VPN."""
        results = {}
        if not nodes:
            return results

        if method == "Proxy-GET":
            # Batch in chunks of 25 nodes for high stability
            batch_size = 25
            for start in range(0, len(nodes), batch_size):
                chunk = nodes[start:start + batch_size]
                chunk_res = self.ping_proxy_get_batch(
                    chunk, timeout=timeout, test_url=test_url, on_progress=on_progress,
                    max_workers=max_workers,
                )
                results.update(chunk_res)
            return results

        # TCP or ICMP or Proxy-HEAD
        def worker(node):
            tag = node.get("tag", "")
            host = node.get("server", "")
            port = node.get("server_port", 0)

            if method == "TCP":
                delay = self.ping_tcp(host, port, timeout)
            elif method == "ICMP":
                delay = self.ping_icmp(host, timeout)
            else:  # Proxy-HEAD
                delay = self.ping_proxy_head(tag, test_url, timeout)
                if delay == -1:
                    delay = self.ping_tcp(host, port, timeout)

            if on_progress:
                try:
                    on_progress(tag, delay)
                except Exception:
                    pass
            return tag, delay

        workers = min(max_workers, len(nodes))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_node = {executor.submit(worker, n): n for n in nodes}
            for future in future_to_node:
                try:
                    tag, delay = future.result()
                    results[tag] = delay
                except Exception:
                    node = future_to_node[future]
                    tag = node.get("tag", "")
                    results[tag] = -1
                    if on_progress:
                        on_progress(tag, -1)

        return results
