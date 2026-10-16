"""Regression tests: use private configs; never start a TUN or change host routes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from thistle_client.core_manager import CoreManager, check_conflicting_vpns
from thistle_client.process_lifecycle import stop_processes
from thistle_client.storage import normalize_selection, write_json


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.core = CoreManager(config_path=str(self.base / 'core.json'))
        self.core.pid_file = str(self.base / 'core.pid')
        self.core.log_file = str(self.base / 'core.log')
        # No host Xray state may be touched by these tests.
        self.core.xray = Mock(last_error='Xray failed')
        self.core.xray.stop.return_value = True
        self.core.is_conflict_running = Mock(return_value='')
        write_json(self.core.config_path, {
            'log': {'level': 'error'},
            'inbounds': [],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}],
        })

    def tearDown(self):
        stop_processes(self.core, self.core.config_path)
        self.directory.cleanup()

    @unittest.skipUnless(shutil.which('sing-box'), 'sing-box not installed')
    def test_repeated_start_stop_reaps_children_and_releases_pid_file(self):
        for _ in range(3):
            self.assertTrue(self.core.start(), self.core.last_error)
            child = self.core.process
            self.assertTrue(self.core.stop(), self.core.last_error)
            self.assertIsNotNone(child.returncode)
            self.assertFalse(Path(f'/proc/{child.pid}').exists())
            self.assertFalse(Path(self.core.pid_file).exists())
            self.assertFalse(self.core.is_running())

    @unittest.skipUnless(shutil.which('sing-box'), 'sing-box not installed')
    def test_recover_core_without_pid_file_and_never_duplicate_it(self):
        self.assertTrue(self.core.start())
        child = self.core.process
        Path(self.core.pid_file).unlink()
        recovered = CoreManager(config_path=self.core.config_path)
        recovered.pid_file = self.core.pid_file
        recovered.xray = self.core.xray
        self.assertTrue(recovered.is_running())
        self.assertTrue(recovered.start())
        self.assertIsNone(recovered.process)
        self.assertTrue(recovered.stop())
        child.wait(timeout=2)
        self.assertFalse(self.core.is_running())

    @unittest.skipUnless(shutil.which('sing-box'), 'sing-box not installed')
    def test_recovered_unresponsive_core_is_killed_and_confirmed_stopped(self):
        import signal
        self.assertTrue(self.core.start())
        child = self.core.process
        os.kill(child.pid, signal.SIGSTOP)
        recovered = CoreManager(config_path=self.core.config_path)
        recovered.pid_file = self.core.pid_file
        recovered.xray = self.core.xray
        self.assertTrue(recovered.stop(), recovered.last_error)
        self.assertFalse(recovered.is_running())
        child.wait(timeout=2)
        self.assertEqual(child.returncode, -signal.SIGKILL)

    def test_refused_stop_retains_pid_and_reports_failure(self):
        Path(self.core.pid_file).write_text('12345')
        with patch('thistle_client.process_lifecycle.managed_pids', return_value=[12345]), \
             patch('thistle_client.process_lifecycle.os.kill', side_effect=PermissionError('denied')):
            self.assertFalse(self.core.stop())
        self.assertEqual(Path(self.core.pid_file).read_text(), '12345')
        self.assertIn('12345', self.core.last_error)
        self.core.xray.stop.assert_not_called()
        Path(self.core.pid_file).unlink()

    def test_restart_does_not_start_after_failed_stop(self):
        with patch.object(self.core, 'stop', return_value=False), patch.object(self.core, 'start') as start:
            self.assertFalse(self.core.restart())
            start.assert_not_called()

    def test_xray_failure_prevents_singbox_start(self):
        self.core.xray.start.return_value = False
        with patch('thistle_client.core_manager.is_xray_node', return_value=True), \
             patch('thistle_client.core_manager.subprocess.Popen') as launch:
            self.assertFalse(self.core.start({'tag': 'xray'}))
            self.assertEqual(self.core.last_error, 'Xray failed')
            launch.assert_not_called()

    @unittest.skipUnless(shutil.which('sing-box'), 'sing-box not installed')
    def test_failed_singbox_start_stops_xray_and_cleans_pid(self):
        Path(self.core.config_path).write_text('{"unknown_field": true}')
        with patch('thistle_client.core_manager.is_xray_node', return_value=True):
            self.core.xray.start.return_value = True
            self.assertFalse(self.core.start({'tag': 'xray'}))
        self.core.xray.stop.assert_called()
        self.assertFalse(Path(self.core.pid_file).exists())
        self.assertIsNone(self.core.process)
        self.assertTrue(self.core.last_error)

    def test_stale_pid_never_kills_unrelated_process(self):
        Path(self.core.pid_file).write_text(str(os.getpid()))
        with patch('thistle_client.process_lifecycle.os.kill') as kill:
            self.assertTrue(self.core.stop())
            kill.assert_not_called()

    def test_switch_does_not_claim_success_when_restart_fails(self):
        with patch.object(self.core, 'is_running', return_value=True), \
             patch('thistle_client.core_manager.is_xray_node', return_value=False), \
             patch('thistle_client.clash_api.ClashAPI.select_proxy', return_value=False), \
             patch.object(self.core, 'restart', return_value=False):
            self.assertFalse(self.core.switch_node({'tag': 'missing'}))

    @unittest.skipUnless(shutil.which('sing-box'), 'sing-box not installed')
    def test_exited_unreaped_singbox_is_not_a_foreign_vpn(self):
        proc = subprocess.Popen([shutil.which('sing-box'), 'invalid-command'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            # Do not poll/wait: leave a zombie, just as the previous manager did.
            deadline = time.monotonic() + 3
            while Path(f'/proc/{proc.pid}/cmdline').read_bytes():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.01)
            results = [subprocess.CompletedProcess([], 1, '', ''),
                       subprocess.CompletedProcess([], 0, str(proc.pid), '')]
            with patch('thistle_client.core_manager.subprocess.run', side_effect=results):
                self.assertEqual(check_conflicting_vpns(), '')
        finally:
            proc.wait(timeout=2)


class StateTests(unittest.TestCase):
    def test_missing_selected_node_is_reconciled_after_refresh(self):
        data = {'subs': {'one': {'nodes': [{'tag': 'new'}]}},
                'active_sub': 'one', 'active_node': 'old'}
        normalize_selection(data)
        self.assertEqual(data['active_node'], 'new')
        data['subs'].clear()
        normalize_selection(data)
        self.assertEqual((data['active_sub'], data['active_node']), ('', ''))

    def test_atomic_write_preserves_previous_file_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data.json'
            write_json(str(path), {'value': 'old'})
            with patch('thistle_client.storage.os.replace', side_effect=OSError('disk error')):
                with self.assertRaises(OSError):
                    write_json(str(path), {'value': 'new'})
            self.assertEqual(json.loads(path.read_text()), {'value': 'old'})
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_second_plain_launch_forwards_show_without_creating_another_app(self):
        from thistle_client.main import main
        with tempfile.TemporaryDirectory() as directory, \
             patch('thistle_client.main.get_ipc_socket_path', return_value=directory + '/ipc'), \
             patch('thistle_client.main.sys.argv', ['thistle-client']), \
             patch('thistle_client.main.fcntl.flock', side_effect=BlockingIOError), \
             patch('thistle_client.main.send_ipc_command', return_value=True) as send, \
             patch('thistle_client.main.ThistleTrayApp') as app:
            main()
            send.assert_called_once_with('SHOW')
            app.assert_not_called()

    def test_first_connect_command_is_executed_after_app_start(self):
        from thistle_client.main import main
        with tempfile.TemporaryDirectory() as directory, \
             patch('thistle_client.main.get_ipc_socket_path', return_value=directory + '/ipc'), \
             patch('thistle_client.main.sys.argv', ['thistle-client', '--connect']), \
             patch('thistle_client.main.ThistleTrayApp') as app, \
             patch('thistle_client.main.start_ipc_server', return_value=None), \
             patch('thistle_client.main.Gtk.main'), \
             patch('thistle_client.main.GLib.idle_add') as idle:
            main()
            idle.assert_called_once_with(app.return_value.connect_vpn)

    def test_disconnect_during_connect_is_applied_after_completion(self):
        import threading
        from thistle_client.main import ThistleTrayApp
        app = ThistleTrayApp.__new__(ThistleTrayApp)
        app.core = Mock(last_error="")
        app.core_busy = False
        app.pending_connection = None
        app.manager_window = None
        app.update_icon_state = Mock()
        app.build_menu = Mock()
        app.notify = Mock()
        app.on_toggle_vpn = Mock()
        callbacks = []
        completed = threading.Event()

        def queue(callback, *args):
            callbacks.append((callback, args))
            completed.set()

        with patch('thistle_client.main.GLib.idle_add', side_effect=queue):
            app.run_core_action(lambda: True, 'connected')
            app.disconnect_vpn()
            self.assertFalse(app.pending_connection)
            self.assertTrue(completed.wait(2))
            finish, args = callbacks.pop(0)
            app.core.is_running.return_value = True
            finish(*args)
            request, args = callbacks.pop(0)
            request(*args)
        self.assertFalse(app.core_busy)
        app.on_toggle_vpn.assert_called_once_with(None)
