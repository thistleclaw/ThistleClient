"""Probe DNS regressions against real temporary Xray and sing-box processes."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from thistle_client import pinger


class ProbeDNSTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('xray') and shutil.which('curl'), 'probe tools unavailable')
    def test_vless_probe_resolves_only_endpoint_and_sends_target_domain_to_server(self):
        requests = []
        class HTTPResponse(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.path, self.headers.get('Host')))
                self.send_response(204)
                self.end_headers()
            def log_message(self, *args):
                pass
        http = ThreadingHTTPServer(('127.0.0.1', 0), HTTPResponse)
        http.daemon_threads = True
        http_thread = threading.Thread(target=http.serve_forever, daemon=True)
        http_thread.start()
        user_id = '00000000-0000-0000-0000-000000000001'
        server_port = pinger._get_free_ports(1)[0]
        configs = []
        baseline = set(pinger._active_test_procs)
        register = pinger._register_test_process
        def capture_config(argv):
            configs.append(json.loads(Path(argv[-1]).read_text()))
            return register(argv)
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory)/'vless-server.json'
            config_path.write_text(json.dumps({
                'log': {'loglevel': 'warning'},
                # Only the test VPN server knows this hostname. No public DNS is used.
                'dns': {'hosts': {'ping-target.invalid': '127.0.0.1'}, 'servers': []},
                'inbounds': [{'protocol': 'vless', 'listen': '127.0.0.1', 'port': server_port,
                              'settings': {'clients': [{'id': user_id}], 'decryption': 'none'},
                              'streamSettings': {'network': 'tcp', 'security': 'none'}}],
                'outbounds': [{'protocol': 'freedom', 'settings': {
                    'domainStrategy': 'UseIP', 'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]
                }, 'streamSettings': {'sockopt': {'domainStrategy': 'UseIP'}}}],
            }))
            with open(Path(directory)/'server.log', 'w+') as log:
                server = subprocess.Popen(['xray', 'run', '-c', str(config_path)], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic()+3
                    while True:
                        if server.poll() is not None:
                            log.seek(0)
                            self.fail(log.read())
                        try:
                            with socket.create_connection(('127.0.0.1', server_port), timeout=.1):
                                break
                        except OSError:
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(.02)
                    node = {'type': 'vless', 'tag': 'private DNS probe', 'server': 'vpn-endpoint.invalid',
                            'server_port': server_port, 'uuid': user_id}
                    with patch('thistle_client.xray_adapter.resolve_endpoint', return_value='127.0.0.1') as encrypted, \
                         patch('socket.gethostbyname', side_effect=AssertionError('Plaintext DNS lookup')) as system, \
                         patch('thistle_client.pinger._register_test_process', side_effect=capture_config):
                        result = pinger.MultiModePinger().ping_proxy_get_batch(
                            [node], test_url=f'http://ping-target.invalid:{http.server_port}/probe', timeout=2)
                    self.assertGreater(result[node['tag']], 0, f'probe failed: {result}')
                    system.assert_not_called()
                    encrypted.assert_called_once_with('vpn-endpoint.invalid', timeout=1, cancel_event=unittest.mock.ANY)
                    self.assertEqual(requests, [('/probe', f'ping-target.invalid:{http.server_port}')])
                    self.assertEqual(len(configs), 1)
                    self.assertNotIn('dns', configs[0], 'temporary Xray must not have a plaintext resolver')
                    self.assertEqual(configs[0]['outbounds'][0]['settings']['vnext'][0]['address'], '127.0.0.1')
                    self.assertEqual(set(pinger._active_test_procs), baseline)
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        server.kill(); server.wait()
                    http.shutdown()
                    http.server_close()
                    http_thread.join(timeout=2)

    def test_failed_encrypted_bootstrap_never_starts_a_probe_or_uses_system_dns(self):
        node = {'type': 'vless', 'tag': 'blocked DNS', 'server': 'vpn.invalid', 'server_port': 443,
                'uuid': '00000000-0000-0000-0000-000000000001'}
        with patch('thistle_client.xray_adapter.resolve_endpoint', side_effect=RuntimeError('DoH blocked')), \
             patch('socket.gethostbyname') as system, \
             patch('thistle_client.pinger._register_test_process') as launch:
            result = pinger.MultiModePinger().ping_proxy_get_batch([node], timeout=1)
        self.assertEqual(result, {node['tag']: -1})
        system.assert_not_called()
        launch.assert_not_called()

    @unittest.skipUnless(shutil.which('sing-box') and shutil.which('curl'), 'probe tools unavailable')
    def test_native_probe_keeps_only_encrypted_endpoint_dns(self):
        configs = []
        register = pinger._register_test_process
        def capture_config(argv):
            configs.append(json.loads(Path(argv[-1]).read_text()))
            return register(argv)
        with patch('socket.gethostbyname', side_effect=AssertionError('Plaintext DNS lookup')) as system, \
             patch('thistle_client.pinger._register_test_process', side_effect=capture_config):
            result = pinger.MultiModePinger().ping_proxy_get_batch(
                [{'type': 'direct', 'tag': 'local'}], test_url='http://127.0.0.1:1/', timeout=1)
        self.assertEqual(result, {'local': -1})
        system.assert_not_called()
        self.assertEqual(len(configs), 1)
        self.assertTrue(all(server['type'] == 'https' for server in configs[0]['dns']['servers']))
