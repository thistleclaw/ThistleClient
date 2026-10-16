"""DNS privacy regressions, including a real local TLS resolver behind a proxy."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import select
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from thistle_client.config_generator import generate_singbox_config
from thistle_client.secure_dns import dns_server, resolve_endpoint, _addresses, _name, _HTTPSByIP
from thistle_client.xray_adapter import XrayManager


def query(name):
    encoded = b''.join(bytes([len(label)])+label.encode() for label in name.split('.'))+b'\0'
    return struct.pack('!6H', 0, 0x100, 1, 0, 0, 0)+encoded+struct.pack('!HH', 1, 1)


def answer(message, address='203.0.113.9'):
    return struct.pack('!6H', 0, 0x8180, 1, 1, 0, 0)+message[12:]+b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 60, 4)+ipaddress.ip_address(address).packed


class ProtectedDNSConfiguration(unittest.TestCase):
    def test_remote_has_explicit_proxy_and_authenticated_tls(self):
        config = generate_singbox_config([], enable_tun=False)
        remote, bootstrap = config['dns']['servers']
        self.assertEqual(remote['type'], 'https')
        self.assertEqual(remote['detour'], 'PROXY')
        self.assertEqual(config['dns']['final'], remote['tag'])
        self.assertTrue(remote['tls']['enabled'])
        self.assertNotIn('insecure', remote['tls'])
        self.assertEqual(bootstrap['type'], 'https')
        self.assertNotIn('detour', bootstrap)
        self.assertEqual(config['route']['default_domain_resolver'], bootstrap['tag'])

    def test_dns_intercept_precedes_endpoint_and_private_network_bypass(self):
        config = generate_singbox_config([{'type': 'hysteria2', 'tag': 'node', 'server': '8.8.8.8', 'server_port': 443}], enable_tun=True)
        rules = config['route']['rules']
        hijack = next(i for i, rule in enumerate(rules) if rule.get('port') == [53])
        for i, rule in enumerate(rules):
            if 'ip_cidr' in rule or 'ip_is_private' in rule:
                self.assertLess(hijack, i)
        tun = config['inbounds'][0]
        self.assertTrue(any(':' in address for address in tun['address']))

    def test_legacy_plaintext_preferences_upgrade_without_unsafe_fallback(self):
        self.assertEqual(dns_server('remote', preferences={'remote_type': 'udp'})['type'], 'https')
        self.assertEqual(dns_server('remote', preferences={'remote_type': 'tls'})['server_port'], 853)
        with self.assertRaises(ValueError):
            dns_server('remote', preferences={'remote_server': 'resolver.example'})
        with self.assertRaises(ValueError):
            dns_server('remote', preferences={'remote_type': 'local'})

    def test_generating_config_does_not_query_the_system_resolver(self):
        with patch('socket.gethostbyname', side_effect=AssertionError('DNS leak')):
            config = generate_singbox_config([{'type': 'vless', 'tag': 'node', 'server': 'vpn.example', 'server_port': 443}], enable_tun=False)
        self.assertEqual(config['dns']['rules'], [{'domain': ['vpn.example'], 'server': 'dns-bootstrap'}])

    def test_legacy_settings_migrate_on_load(self):
        from thistle_client.config import SettingsManager
        with tempfile.TemporaryDirectory() as directory, patch('thistle_client.config.SETTINGS_FILE', directory+'/settings.json'):
            Path(directory+'/settings.json').write_text(json.dumps({'dns': {'remote_type': 'udp', 'hijack_dns': False}}))
            loaded = SettingsManager()
            self.assertEqual(loaded.get('dns', 'remote_type'), 'https')
            self.assertTrue(loaded.get('dns', 'hijack_dns'))
            self.assertEqual(json.loads(Path(directory+'/settings.json').read_text())['dns']['remote_type'], 'https')


class EndpointBootstrapTests(unittest.TestCase):
    def test_direct_ping_resolves_endpoint_without_os_dns(self):
        from thistle_client.pinger import MultiModePinger
        with patch('thistle_client.pinger.resolve_endpoint', return_value='203.0.113.8') as resolve,              patch('thistle_client.pinger.socket.create_connection') as connect:
            self.assertGreater(MultiModePinger().ping_tcp('vpn.example', 443), 0)
            resolve.assert_called_once_with('vpn.example', timeout=3)
            connect.assert_called_once_with(('203.0.113.8', 443), timeout=3)

    def test_numeric_endpoint_requires_no_dns(self):
        with patch('thistle_client.secure_dns._HTTPSByIP') as connection:
            self.assertEqual(resolve_endpoint('203.0.113.7'), '203.0.113.7')
            self.assertEqual(resolve_endpoint('2001:db8::7'), '2001:db8::7')
            connection.assert_not_called()

    def test_wire_reply_is_validated_and_compression_cycles_rejected(self):
        request = query('vpn.example')
        self.assertEqual(_addresses(answer(request), 'vpn.example', 1), [('203.0.113.9', 60)])
        with self.assertRaises(ValueError):
            _addresses(answer(request), 'other.example', 1)
        with self.assertRaises(ValueError):
            _name(b'\xc0\x00', 0)

    def test_valid_cache_avoids_network_and_expired_cache_does_not(self):
        with tempfile.TemporaryDirectory() as directory, patch('thistle_client.secure_dns.DATA_DIR', directory), \
             patch('thistle_client.secure_dns._HTTPSByIP') as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.getheader.return_value = 'application/dns-message'
            response.read.return_value = answer(query('vpn.example'))
            self.assertEqual(resolve_endpoint('vpn.example'), '203.0.113.9')
            self.assertEqual(resolve_endpoint('vpn.example'), '203.0.113.9')
            self.assertEqual(connection.call_count, 1)
            cache_path = Path(directory)/'bootstrap_cache.json'
            cache = json.loads(cache_path.read_text())
            for entry in cache.values():
                entry['expires'] = 0
            cache_path.write_text(json.dumps(cache))
            self.assertEqual(resolve_endpoint('vpn.example'), '203.0.113.9')
            self.assertEqual(connection.call_count, 2)

    def test_tls_failure_never_falls_back_to_system_dns(self):
        with tempfile.TemporaryDirectory() as directory, patch('thistle_client.secure_dns.DATA_DIR', directory), \
             patch('thistle_client.secure_dns._HTTPSByIP', side_effect=ssl.SSLCertVerificationError('bad cert')), \
             patch('socket.gethostbyname') as system:
            with self.assertRaisesRegex(RuntimeError, 'Открытый DNS не используется'):
                resolve_endpoint('vpn.example')
            system.assert_not_called()

    def test_python_bootstrap_checks_certificates_and_hostname(self):
        connection = _HTTPSByIP('1.1.1.1', 'cloudflare-dns.com')
        self.assertTrue(connection._context.check_hostname)
        self.assertEqual(connection._context.verify_mode, ssl.CERT_REQUIRED)
        connection.close()

    def test_xray_pins_numeric_address_and_preserves_tls_server_name(self):
        node = {'type': 'vless', 'tag': 'node', 'server': 'vpn.example', 'server_port': 443,
                'uuid': '00000000-0000-0000-0000-000000000001', 'tls': {'enabled': True, 'server_name': 'vpn.example'}}
        manager = XrayManager()
        with tempfile.TemporaryDirectory() as directory:
            manager.config_file = directory+'/xray.json'
            manager.pid_file = directory+'/xray.pid'
            manager.log_file = directory+'/xray.log'
            with patch.object(manager, 'stop', return_value=True), \
                 patch('thistle_client.xray_adapter.resolve_endpoint', return_value='203.0.113.8'), \
                 patch('thistle_client.xray_adapter.subprocess.Popen') as launch, \
                 patch.object(manager, 'is_running', return_value=True), \
                 patch('thistle_client.xray_adapter.time.sleep'):
                launch.return_value.pid = 12345
                self.assertTrue(manager.start(node))
            config = json.loads(Path(manager.config_file).read_text())
            self.assertNotIn('dns', config)
            self.assertEqual(config['outbounds'][0]['settings']['vnext'][0]['address'], '203.0.113.8')
            self.assertEqual(config['outbounds'][0]['streamSettings']['tlsSettings']['serverName'], 'vpn.example')

    def test_failed_bootstrap_keeps_old_xray_running(self):
        manager = XrayManager()
        with patch('thistle_client.xray_adapter.resolve_endpoint', side_effect=RuntimeError('DoH blocked')), \
             patch.object(manager, 'stop') as stop:
            self.assertFalse(manager.start({'type': 'vless', 'server': 'vpn.example', 'server_port': 443}))
            stop.assert_not_called()
            self.assertIn('DoH blocked', manager.last_error)


@unittest.skipUnless(shutil.which('sing-box') and shutil.which('openssl'), 'integration tools unavailable')
class DoHThroughProxyIntegration(unittest.TestCase):
    def test_dns_uses_proxy_and_does_not_fall_back_when_doh_fails(self):
        """No TUN, public DNS, host routes or production ports are used here."""
        with tempfile.TemporaryDirectory() as directory:
            cert, key = directory+'/cert.pem', directory+'/key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-keyout', key, '-out', cert, '-subj', '/CN=localhost',
                            '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            paths, connects = [], []
            failure = threading.Event()

            class Resolver(BaseHTTPRequestHandler):
                protocol_version = 'HTTP/1.1'
                def do_POST(self):
                    body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                    paths.append(self.path)
                    if failure.is_set():
                        self.send_response(503)
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                        return
                    response = answer(body)
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/dns-message')
                    self.send_header('Content-Length', str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)
                def log_message(self, *args):
                    pass

            class Proxy(BaseHTTPRequestHandler):
                def do_CONNECT(self):
                    connects.append(self.path)
                    host, port = self.path.rsplit(':', 1)
                    with socket.create_connection((host, int(port)), timeout=2) as upstream:
                        self.send_response(200)
                        self.end_headers()
                        pair = [self.connection, upstream]
                        while True:
                            readable, _, _ = select.select(pair, [], [], 3)
                            if not readable:
                                return
                            for source in readable:
                                try:
                                    data = source.recv(65536)
                                    if not data:
                                        return
                                    (upstream if source is self.connection else self.connection).sendall(data)
                                except OSError:
                                    return
                def log_message(self, *args):
                    pass

            resolver = ThreadingHTTPServer(('127.0.0.1', 0), Resolver)
            resolver.daemon_threads = True
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            resolver.socket = context.wrap_socket(resolver.socket, server_side=True)
            proxy = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
            proxy.daemon_threads = True
            threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (resolver, proxy)]
            for thread in threads:
                thread.start()
            from thistle_client.pinger import _get_free_ports
            mixed_port, dns_port = _get_free_ports(2)
            config = generate_singbox_config([{'type': 'http', 'tag': 'probe', 'server': '127.0.0.1', 'server_port': proxy.server_port}], active_tag='probe', enable_tun=False)
            config['inbounds'][0]['listen_port'] = mixed_port
            config['inbounds'].append({'type': 'direct', 'tag': 'dns-test', 'listen': '127.0.0.1', 'listen_port': dns_port,
                                       'network': 'udp', 'override_address': '8.8.8.8', 'override_port': 53})
            config.pop('experimental', None)
            for server in config['dns']['servers']:
                server.update(server='127.0.0.1', server_port=resolver.server_port)
                server['tls'] = {'enabled': True, 'server_name': 'localhost', 'certificate_path': cert}
                server['path'] = '/dns-query' if server['tag'] == 'dns-remote' else '/bootstrap'
            config_path = directory+'/core.json'
            Path(config_path).write_text(json.dumps(config))
            with open(directory+'/core.log', 'w+') as log:
                process = subprocess.Popen(['sing-box', 'run', '-c', config_path], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic()+3
                    while True:
                        if process.poll() is not None:
                            log.seek(0)
                            self.fail(log.read())
                        try:
                            with socket.create_connection(('127.0.0.1', mixed_port), timeout=.1):
                                break
                        except OSError:
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(.02)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                        client.settimeout(2)
                        client.sendto(query('success.example'), ('127.0.0.1', dns_port))
                        response, _ = client.recvfrom(65536)
                        self.assertEqual(_addresses(response, 'success.example', 1)[0][0], '203.0.113.9')
                        self.assertTrue(connects)
                        self.assertEqual(set(connects), {f'127.0.0.1:{resolver.server_port}'})
                        self.assertIn('/dns-query', paths)
                        self.assertNotIn('/bootstrap', paths)
                        failure.set()
                        client.sendto(query('failure.example'), ('127.0.0.1', dns_port))
                        try:
                            rejected, _ = client.recvfrom(65536)
                            self.assertNotEqual(struct.unpack('!H', rejected[2:4])[0] & 15, 0)
                        except socket.timeout:
                            pass
                        self.assertNotIn('/bootstrap', paths, 'ordinary DNS fell back outside the proxy')
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    for server in (resolver, proxy):
                        server.shutdown()
                        server.server_close()
                    for thread in threads:
                        thread.join(timeout=2)
