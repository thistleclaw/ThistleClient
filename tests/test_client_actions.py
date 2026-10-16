"""Subscription scheduling, clipboard actions, symbolic widgets and ping cancellation."""
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import shutil
import threading
import time
import unittest
from unittest.mock import Mock, patch

from thistle_client.main import ThistleTrayApp
from thistle_client.pinger import MultiModePinger, _active_test_procs
from thistle_client.subscription_updates import subscription_due


class SubscriptionActionsTests(unittest.TestCase):
    def app(self):
        app = ThistleTrayApp.__new__(ThistleTrayApp)
        app.data = {'subs': {'feed': {'url': 'https://example.com/feed', 'nodes': [{'tag': 'old'}]}},
                    'active_sub': 'feed', 'active_node': 'old'}
        app.refreshing_subscriptions = set()
        app.refresh_attempts = {}
        app.core_busy = False
        app.is_pinging = False
        app.delays = {}
        app.save_data = Mock()
        app.sync_config = Mock()
        app.build_menu = Mock()
        app.notify = Mock()
        return app

    def test_scheduler_only_updates_due_urls_and_honors_disable_and_backoff(self):
        now = time.time()
        current = datetime.fromtimestamp(now).isoformat()
        self.assertTrue(subscription_due({'url': 'https://example.com'}, now, 24))
        self.assertFalse(subscription_due({'url': ''}, now, 24))
        self.assertFalse(subscription_due({'url': 'https://example.com', 'updated_at': current}, now, 24))
        self.assertTrue(subscription_due({'url': 'https://example.com', 'updated_at': current}, now+86401, 24))
        app = self.app()
        app.refresh_subscription = Mock()
        with patch('thistle_client.main.settings.get', side_effect=lambda section,key,default=None: default):
            self.assertFalse(app.auto_refresh_subscriptions(False))
            app.refresh_subscription.assert_called_once_with('feed', automatic=True)
            app.refresh_subscription.reset_mock()
            app.refresh_attempts['feed'] = time.monotonic()
            app.auto_refresh_subscriptions()
            app.refresh_subscription.assert_not_called()
        with patch('thistle_client.main.settings.get', return_value=False):
            app.auto_refresh_subscriptions()
            app.refresh_subscription.assert_not_called()

    def run_refresh(self, app, nodes, before_apply=None):
        queued = []
        ready = threading.Event()
        def dispatch(callback, *args):
            queued.append((callback, args))
            ready.set()
        with patch('thistle_client.main.fetch_subscription', return_value=nodes) as fetch, \
             patch('thistle_client.main.GLib.idle_add', side_effect=dispatch):
            app.refresh_subscription('feed', automatic=True)
            self.assertTrue(ready.wait(2))
            # An in-flight manual/automatic refresh must not spawn a duplicate.
            app.refresh_subscription('feed')
            self.assertEqual(fetch.call_count, 1)
            if before_apply:
                before_apply()
            callback, args = queued[0]
            callback(*args)

    def test_unchanged_feed_updates_timestamp_without_restarting_vpn(self):
        app = self.app()
        self.run_refresh(app, [{'tag': 'old'}])
        app.sync_config.assert_not_called()
        app.save_data.assert_called_once()
        self.assertIn('updated_at', app.data['subs']['feed'])
        self.assertFalse(app.refreshing_subscriptions)

    def test_changed_active_feed_is_applied(self):
        app = self.app()
        self.run_refresh(app, [{'tag': 'new'}])
        app.sync_config.assert_called_once_with(True, restart=True)
        self.assertEqual(app.data['subs']['feed']['nodes'], [{'tag': 'new'}])

    def test_deleted_feed_is_not_resurrected_by_late_result(self):
        app = self.app()
        self.run_refresh(app, [{'tag': 'new'}], before_apply=lambda: app.data['subs'].clear())
        app.save_data.assert_not_called()
        self.assertFalse(app.refreshing_subscriptions)

    def test_empty_response_preserves_existing_nodes_and_clears_inflight_state(self):
        app = self.app()
        self.run_refresh(app, [])
        self.assertEqual(app.data['subs']['feed']['nodes'], [{'tag': 'old'}])
        app.save_data.assert_not_called()
        self.assertFalse(app.refreshing_subscriptions)

    def test_clipboard_gets_exact_url_and_no_url_leaves_clipboard_alone(self):
        from thistle_client.ui_helpers import copy_subscription_url
        app = self.app()
        with patch('thistle_client.ui_helpers.Gtk.Clipboard.get') as get:
            self.assertTrue(copy_subscription_url(app.data))
            get.return_value.set_text.assert_called_once_with('https://example.com/feed', -1)
            get.return_value.store.assert_called_once()
            get.reset_mock()
            app.data['subs']['feed']['url'] = ''
            self.assertFalse(copy_subscription_url(app.data))
            get.assert_not_called()


class PingCancellationTests(unittest.TestCase):
    def test_cancel_before_start_launches_no_processes(self):
        event = threading.Event()
        event.set()
        with patch('thistle_client.pinger._register_test_process') as launch:
            result = MultiModePinger().ping_all([{'tag': 'test', 'type': 'direct'}], cancel_event=event)
            self.assertEqual(result, {})
            launch.assert_not_called()

    def test_cancel_prevents_later_chunks(self):
        event = threading.Event()
        def batch(*args, **kwargs):
            event.set()
            return {'first': 20}
        pinger = MultiModePinger()
        with patch.object(pinger, 'ping_proxy_get_batch', side_effect=batch) as measure:
            result = pinger.ping_all([{'tag': str(i)} for i in range(60)], cancel_event=event)
        self.assertEqual(result, {'first': 20})
        self.assertEqual(measure.call_count, 1)

    @unittest.skipUnless(shutil.which('sing-box') and shutil.which('curl'), 'probe tools unavailable')
    def test_cancel_interrupts_running_http_and_reaps_temporary_core(self):
        entered, release, cancel = threading.Event(), threading.Event(), threading.Event()
        class SlowResponse(BaseHTTPRequestHandler):
            def do_GET(self):
                entered.set()
                release.wait(8)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), SlowResponse)
        server.daemon_threads = True
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        result = {}
        baseline = set(_active_test_procs)
        worker = threading.Thread(target=lambda: result.update(MultiModePinger().ping_all(
            [{'type': 'direct', 'tag': 'one'}, {'type': 'direct', 'tag': 'two'}],
            timeout=15, max_workers=1, test_url=f'http://127.0.0.1:{server.server_port}/', cancel_event=cancel)))
        try:
            worker.start()
            self.assertTrue(entered.wait(4))
            started = time.monotonic()
            cancel.set()
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive(), 'cancel waited for the HTTP timeout')
            self.assertLess(time.monotonic()-started, 2)
            self.assertEqual(result, {})
            self.assertEqual(set(_active_test_procs), baseline)
        finally:
            cancel.set()
            release.set()
            worker.join(timeout=5)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

    def test_stop_button_and_unmeasured_rows_are_restored(self):
        from thistle_client.manager_gui import ThistleManagerWindow
        window = ThistleManagerWindow()
        try:
            window.data = {'active_sub': 'feed', 'subs': {'feed': {'nodes': [{'tag': 'one'}]}}}
            window.update_server_list()
            window.begin_ping()
            self.assertTrue(window.btn_stop_ping.get_visible())
            window.on_stop_ping()
            self.assertTrue(window.ping_cancel.is_set())
            window.finish_ping({}, 'feed')
            self.assertFalse(window.btn_stop_ping.get_visible())
            self.assertNotIn('замер', window.model_servers[0][3])
            self.assertFalse(window.is_pinging)
        finally:
            window.destroy()

    def test_symbolic_button_has_image_independent_of_button_image_preference(self):
        from thistle_client.ui_helpers import button_icon, menu_item
        from gi.repository import Gtk
        button = button_icon(Gtk.Button(label='Обновить'), 'view-refresh-symbolic')
        item = menu_item('Подписки', 'folder-symbolic')
        try:
            self.assertTrue(button.get_always_show_image())
            self.assertEqual(button.get_image().get_icon_name()[0], 'view-refresh-symbolic')
            self.assertIsInstance(item.get_child().get_children()[0], Gtk.Image)
        finally:
            button.destroy()
            item.destroy()
