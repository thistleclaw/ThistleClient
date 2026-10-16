"""Encrypted DNS configuration and endpoint-only bootstrap without OS DNS fallback."""
import http.client
import ipaddress
import json
import os
import socket
import ssl
import struct
import threading
import time

from thistle_client.config import DATA_DIR, settings
from thistle_client.storage import write_json

TLS_NAMES = {'8.8.8.8': 'dns.google', '8.8.4.4': 'dns.google',
             '1.1.1.1': 'cloudflare-dns.com', '1.0.0.1': 'cloudflare-dns.com',
             '9.9.9.9': 'dns.quad9.net', '94.140.14.14': 'dns.adguard-dns.com'}
_cache_lock = threading.Lock()


def dns_server(tag, bootstrap=False, preferences=None):
    def get(key, default):
        return settings.get("dns", key, default) if preferences is None else preferences.get(key, default)
    prefix = 'bootstrap_' if bootstrap else 'remote_'
    address = str(get(prefix+'server', '1.1.1.1' if bootstrap else '8.8.8.8')).strip()
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError as exc:
        raise ValueError('DNS: укажите IP резолвера, а имя сертификата — в отдельном поле TLS.') from exc
    transport = 'https' if bootstrap else get('remote_type', 'https')
    # Upgrade legacy plaintext DNS preferences; there is no UDP fallback.
    if transport in ('udp', 'tcp'):
        transport = 'https'
    if transport not in ('https', 'tls'):
        raise ValueError('DNS: поддерживаются только DoH и DoT.')
    name = str(get(prefix+'tls_name', '')).strip() or TLS_NAMES.get(address, address)
    server = {'type': transport, 'tag': tag, 'server': address,
              'server_port': 443 if transport == 'https' else 853,
              'tls': {'enabled': True, 'server_name': name}}
    if transport == 'https':
        path = str(get(prefix+'path', '/dns-query')).strip()
        if not path.startswith('/') or path.startswith('//'):
            raise ValueError('DNS: путь DoH должен начинаться с /.')
        server['path'] = path
    if not bootstrap:
        server['detour'] = 'PROXY'
    return server


def _name(packet, offset):
    labels, end, seen = [], None, set()
    while True:
        if offset in seen or offset >= len(packet):
            raise ValueError('Invalid compressed DNS name')
        seen.add(offset)
        size = packet[offset]
        if size & 0xc0 == 0xc0:
            if offset+1 >= len(packet):
                raise ValueError('Truncated DNS pointer')
            if end is None:
                end = offset+2
            offset = ((size & 0x3f) << 8) | packet[offset+1]
            continue
        if size > 63 or offset+1+size > len(packet):
            raise ValueError('Invalid DNS label')
        offset += 1
        if not size:
            return '.'.join(labels).lower(), end if end is not None else offset
        labels.append(packet[offset:offset+size].decode('ascii'))
        offset += size


def _addresses(packet, hostname, query_type):
    if len(packet) < 12:
        raise ValueError('Truncated DNS reply')
    ident, flags, questions, answers, _, _ = struct.unpack('!6H', packet[:12])
    if ident != 0 or not flags & 0x8000 or flags & 0x020f or questions != 1:
        raise ValueError('DNS bootstrap returned an error')
    question, offset = _name(packet, 12)
    kind, cls = struct.unpack_from('!HH', packet, offset)
    if question != hostname or kind != query_type or cls != 1:
        raise ValueError('Mismatched DNS reply')
    offset += 4
    aliases, alias_ttls, records = {}, {}, []
    for _ in range(answers):
        owner, offset = _name(packet, offset)
        kind, cls, ttl, length = struct.unpack_from('!HHIH', packet, offset)
        offset += 10
        if offset+length > len(packet):
            raise ValueError('Truncated DNS record')
        if cls == 1:
            if kind == 5:
                aliases[owner] = _name(packet, offset)[0]
                alias_ttls[owner] = ttl
            elif kind == query_type and length == (4 if kind == 1 else 16):
                records.append((owner, str(ipaddress.ip_address(packet[offset:offset+length])), ttl))
        offset += length
    allowed = {hostname}
    for _ in range(len(aliases)):
        allowed.update(target for owner, target in aliases.items() if owner in allowed)
    alias_limit = min((ttl for owner, ttl in alias_ttls.items() if owner in allowed), default=0xffffffff)
    return [(address, min(ttl, alias_limit)) for owner, address, ttl in records if owner in allowed]


class _HTTPSByIP(http.client.HTTPSConnection):
    """Connect to a numeric IP while authenticating the configured TLS hostname."""
    def __init__(self, address, name, timeout=5):
        super().__init__(address, timeout=timeout, context=ssl.create_default_context())
        self.tls_name = name

    def connect(self):
        raw = socket.create_connection((self.host, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.tls_name)
        except BaseException:
            raw.close()
            raise


def resolve_endpoint(hostname, timeout=5, cancel_event=None):
    """Resolve only a VPN endpoint; cache valid answers and fail without plaintext DNS."""
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        pass
    hostname = hostname.rstrip('.').encode('idna').decode('ascii').lower()
    labels = hostname.split('.')
    if not hostname or len(hostname) > 253 or any(not label or len(label) > 63 for label in labels):
        raise ValueError('Некорректное имя VPN-сервера.')
    resolver = dns_server('dns-bootstrap', bootstrap=True)
    key = '|'.join((resolver['server'], resolver['tls']['server_name'], resolver['path'], hostname))
    cache_path = os.path.join(DATA_DIR, 'bootstrap_cache.json')
    with _cache_lock:
        try:
            with open(cache_path, encoding='utf-8') as stream:
                cache = json.load(stream)
            if not isinstance(cache, dict):
                cache = {}
        except (OSError, ValueError):
            cache = {}
        entry = cache.get(key, {})
        try:
            if 0 < entry['expires'] - time.time() <= 3600:
                return str(ipaddress.ip_address(entry['address']))
        except (KeyError, ValueError, TypeError):
            pass
    encoded = b''.join(bytes([len(label)])+label.encode('ascii') for label in labels)+b'\0'
    try:
        for query_type in (1, 28):
            if cancel_event is not None and cancel_event.is_set():
                raise RuntimeError("Замер отменён")
            query = struct.pack('!6H', 0, 0x0100, 1, 0, 0, 0)+encoded+struct.pack('!HH', query_type, 1)
            connection = _HTTPSByIP(resolver['server'], resolver['tls']['server_name'], timeout=timeout)
            try:
                connection.request('POST', resolver['path'], body=query,
                                   headers={'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message',
                                            'Host': resolver['tls']['server_name']})
                response = connection.getresponse()
                if response.status != 200 or response.getheader('Content-Type', '').split(';')[0].strip() != 'application/dns-message':
                    raise ValueError('Invalid DoH response')
                answers = _addresses(response.read(65536), hostname, query_type)
            finally:
                connection.close()
            if answers:
                address, ttl = answers[0]
                if ttl > 0:
                    with _cache_lock:
                        # Merge again so concurrent lookups cannot discard each other's entries.
                        try:
                            with open(cache_path, encoding='utf-8') as stream:
                                cache = json.load(stream)
                            if not isinstance(cache, dict):
                                cache = {}
                        except (OSError, ValueError):
                            cache = {}
                        cache = {k: v for k, v in cache.items() if isinstance(v, dict) and isinstance(v.get('expires'), (int, float)) and v['expires'] > time.time()}
                        cache[key] = {'address': address, 'expires': time.time()+min(ttl, 3600)}
                        write_json(cache_path, cache)
                return address
        raise ValueError('VPN-сервер не имеет A/AAAA-записей')
    except Exception as exc:
        raise RuntimeError('Не удалось разрешить адрес VPN-сервера через защищённый DNS. '
                           'Проверьте начальный DoH-резолвер или используйте узел с IP-адресом. '
                           'Открытый DNS не используется.') from exc
