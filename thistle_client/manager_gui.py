#!/usr/bin/env python3
"""
ThistleClient Control Center GUI.
High-end desktop interface for managing VPN connection, node switching, subscriptions, and multi-mode ping tests.
"""

import json
import os
import sys
import threading
import time

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk, Pango, GdkPixbuf

from thistle_client.config import (
    settings, SUBS_FILE, SINGBOX_CONFIG_FILE, SINGBOX_LOG_FILE, DATA_DIR
)
from thistle_client.config_generator import generate_singbox_config
from thistle_client.core_manager import CoreManager
from thistle_client.clash_api import ClashAPI
from thistle_client.pinger import MultiModePinger
from thistle_client.settings_dialog import SettingsDialog
from thistle_client.subscription_parser import fetch_subscription, parse_subscription_content


class ThistleManagerWindow(Gtk.Window):
    def __init__(self, tray_app=None):
        super().__init__(title="ThistleClient — Управление VPN")
        self.tray_app = tray_app
        self.set_default_size(680, 540)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.set_border_width(14)

        # Set window icon
        logo_path = os.path.join(os.path.dirname(__file__), "..", "icons", "thistle-logo.svg")
        if os.path.exists(logo_path):
            self.set_icon_from_file(logo_path)

        clash_port = int(settings.get("network", "clash_port", 9095))
        mixed_port = int(settings.get("network", "mixed_port", 2080))
        if self.tray_app:
            self.clash_api = self.tray_app.clash_api
            self.core = self.tray_app.core
            self.pinger = self.tray_app.pinger
        else:
            self.clash_api = ClashAPI(port=clash_port)
            self.core = CoreManager(config_path=SINGBOX_CONFIG_FILE)
            self.pinger = MultiModePinger(mixed_port=mixed_port, clash_port=clash_port)

        self.delays = {}
        self.is_pinging = False
        self._ping_scope = None

        self.load_data()
        self.build_ui()

        # Connect delete-event for close-to-tray handling
        self.connect("delete-event", self.on_delete_event)

        # Check for auto ping on load
        if settings.get("ping", "auto_ping_on_load", False):
            GLib.idle_add(self.on_ping_clicked, None)

        # Periodic status check
        GLib.timeout_add_seconds(2, self.on_timer_tick)

    def on_delete_event(self, widget, event):
        close_to_tray = settings.get("app", "close_to_tray", True)
        if close_to_tray and self.tray_app is not None:
            self.hide()
            return True  # Cancel destruction, minimize to tray
        else:
            Gtk.main_quit()
            return False

    def refresh_all(self):
        self.load_data()
        if self.tray_app:
            self.delays = self.tray_app.delays
        self.update_sub_list()
        self.update_server_list()
        self.update_status_ui()

    def load_data(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        self.data = {"subs": {}, "active_sub": "", "active_node": ""}
        if os.path.exists(SUBS_FILE):
            try:
                with open(SUBS_FILE, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except Exception:
                pass

    def save_data(self):
        try:
            with open(SUBS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            if self.tray_app:
                self.tray_app.data = self.data
                self.tray_app.update_icon_state()
                self.tray_app.build_menu()
        except Exception:
            pass

    def get_current_nodes(self) -> list:
        sub_name = self.data.get("active_sub")
        if sub_name and sub_name in self.data.get("subs", {}):
            return self.data["subs"][sub_name].get("nodes", [])
        return []

    def sync_config(self, enable_tun: bool = True, restart: bool = False):
        nodes = self.get_current_nodes()
        active_node = self.data.get("active_node", "")
        cfg = generate_singbox_config(nodes, active_tag=active_node, enable_tun=enable_tun)
        with open(SINGBOX_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)

        if restart and self.core.is_running():
            active_dict = self.get_active_node_dict()
            self.core.restart(active_node=active_dict)
        if self.tray_app:
            self.tray_app.update_icon_state()
            self.tray_app.build_menu()

    def build_ui(self):
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.add(vbox)

        # 1. Header Card (Status, Power Button, Settings)
        header_frame = Gtk.Frame()
        header_frame.set_shadow_type(Gtk.ShadowType.ETCHED_IN)
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        header_box.set_border_width(12)
        header_frame.add(header_box)

        status_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.lbl_title = Gtk.Label(xalign=0)
        self.lbl_title.set_markup("<b><big>ThistleClient</big></b> — Высокоскоростной прокси-туннель")
        self.lbl_status = Gtk.Label(xalign=0)
        self.lbl_status.set_markup("<b>Статус:</b> Определение...")

        status_vbox.pack_start(self.lbl_title, False, False, 0)
        status_vbox.pack_start(self.lbl_status, False, False, 0)
        header_box.pack_start(status_vbox, True, True, 0)

        # Action Buttons
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.btn_settings = Gtk.Button(label="⚙️ Настройки")
        self.btn_settings.connect("clicked", self.on_open_settings)

        self.btn_toggle = Gtk.Button(label="Включить VPN")
        self.btn_toggle.connect("clicked", self.on_toggle_clicked)

        btn_box.pack_start(self.btn_settings, False, False, 0)
        btn_box.pack_start(self.btn_toggle, False, False, 0)
        header_box.pack_end(btn_box, False, False, 0)

        vbox.pack_start(header_frame, False, False, 0)

        # Conflict Warning Banner
        self.conflict_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.conflict_box.set_no_show_all(True)
        self.lbl_conflict = Gtk.Label(xalign=0)
        self.lbl_conflict.set_line_wrap(True)
        self.conflict_box.pack_start(self.lbl_conflict, True, True, 0)
        vbox.pack_start(self.conflict_box, False, False, 0)

        # 2. Subscriptions Section
        sub_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        lbl_sub = Gtk.Label(label="<b>Подписка:</b>", use_markup=True)
        self.combo_subs = Gtk.ComboBoxText()
        self.combo_subs.connect("changed", self.on_sub_changed)

        btn_add_sub = Gtk.Button(label="➕ Добавить")
        btn_add_sub.connect("clicked", self.on_add_sub_dialog)

        btn_refresh_sub = Gtk.Button(label="🔄 Обновить")
        btn_refresh_sub.connect("clicked", self.on_refresh_sub_clicked)

        btn_del_sub = Gtk.Button(label="❌ Удалить")
        btn_del_sub.connect("clicked", self.on_delete_sub_clicked)

        sub_box.pack_start(lbl_sub, False, False, 0)
        sub_box.pack_start(self.combo_subs, True, True, 0)
        sub_box.pack_start(btn_add_sub, False, False, 0)
        sub_box.pack_start(btn_refresh_sub, False, False, 0)
        sub_box.pack_start(btn_del_sub, False, False, 0)
        vbox.pack_start(sub_box, False, False, 0)

        # 3. Servers List Section
        srv_header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        srv_label = Gtk.Label(label="<b>Список серверов</b>", xalign=0, use_markup=True)

        self.lbl_ping_mode = Gtk.Label(xalign=0)
        self.lbl_ping_mode.set_markup(f"<small><span foreground='#888888'>Метод: Proxy-GET</span></small>")

        self.btn_ping = Gtk.Button(label="⚡ Измерить пинг")
        self.btn_ping.connect("clicked", self.on_ping_clicked)

        srv_header.pack_start(srv_label, False, False, 0)
        srv_header.pack_start(self.lbl_ping_mode, False, False, 4)
        srv_header.pack_end(self.btn_ping, False, False, 0)
        vbox.pack_start(srv_header, False, False, 0)

        # TreeView with Columns
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_shadow_type(Gtk.ShadowType.IN)

        # Model: [DisplayTag, Proto, Host, DelayMarkup, RawDelay, RawTag]
        self.model_servers = Gtk.ListStore(str, str, str, str, int, str)
        self.tree_servers = Gtk.TreeView(model=self.model_servers)
        self.tree_servers.connect("row-activated", self.on_server_row_activated)

        col_tag = Gtk.TreeViewColumn("Имя сервера", Gtk.CellRendererText(), text=0)
        col_tag.set_sort_column_id(0)
        col_tag.set_resizable(True)

        col_type = Gtk.TreeViewColumn("Протокол", Gtk.CellRendererText(), text=1)
        col_type.set_resizable(True)

        col_host = Gtk.TreeViewColumn("Хост:Порт", Gtk.CellRendererText(), text=2)
        col_host.set_resizable(True)

        # Color-coded delay renderer using markup
        renderer_ping = Gtk.CellRendererText()
        col_ping = Gtk.TreeViewColumn("Задержка", renderer_ping, markup=3)
        col_ping.set_sort_column_id(4)
        col_ping.set_resizable(True)

        self.tree_servers.append_column(col_tag)
        self.tree_servers.append_column(col_type)
        self.tree_servers.append_column(col_host)
        self.tree_servers.append_column(col_ping)

        scroll.add(self.tree_servers)
        vbox.pack_start(scroll, True, True, 0)

        # Bottom Bar: Connect Button
        bottom_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.btn_select_server = Gtk.Button(label="Подключиться к выбранному серверу")
        self.btn_select_server.connect("clicked", self.on_select_server_clicked)
        bottom_box.pack_start(self.btn_select_server, True, True, 0)
        vbox.pack_start(bottom_box, False, False, 0)

        self.update_sub_list()
        self.update_server_list()
        self.update_status_ui()

    def update_status_ui(self):
        is_running = self.core.is_running()
        active_node = self.data.get("active_node") or "Не выбран"
        has_nodes = bool(self.get_current_nodes())

        if is_running:
            self.lbl_status.set_markup(f"<b>Статус:</b> <span foreground='#00E676'>● Подключено ({active_node})</span>")
            self.btn_toggle.set_label("Отключить VPN")
            self.btn_toggle.get_style_context().remove_class("suggested-action")
            self.btn_toggle.get_style_context().add_class("destructive-action")
            self.conflict_box.hide()
        else:
            self.lbl_status.set_markup("<b>Статус:</b> <span foreground='#FF9100'>○ Отключено</span>")
            self.btn_toggle.set_label("Включить VPN")
            self.btn_toggle.get_style_context().remove_class("destructive-action")
            self.btn_toggle.get_style_context().add_class("suggested-action")

            conflict = self.core.is_conflict_running()
            if conflict:
                self.lbl_conflict.set_markup(
                    f"<span foreground='#FF9100'>⚠️ <b>Внимание:</b> Запущен сторонний VPN (<b>{conflict}</b>). "
                    f"Остановите его перед включением ThistleClient во избежание конфликта маршрутов.</span>"
                )
                self.conflict_box.show_all()
            else:
                self.conflict_box.hide()

        self.btn_ping.set_sensitive(not self.is_pinging and has_nodes)
        timeout_sec = settings.get("ping", "timeout", 4)
        self.lbl_ping_mode.set_markup(f"<small><span foreground='#888888'>Метод: <b>Proxy-GET</b> ({timeout_sec}с)</span></small>")

    def update_sub_list(self):
        self.combo_subs.remove_all()
        subs = self.data.get("subs", {})
        active = self.data.get("active_sub")
        active_idx = 0
        idx = 0
        for name in subs.keys():
            self.combo_subs.append_text(name)
            if name == active:
                active_idx = idx
            idx += 1
        if subs:
            self.combo_subs.set_active(active_idx)

    @staticmethod
    def format_delay(delay) -> tuple:
        if delay is None:
            return "<span foreground='#757575'>—</span>", 99999
        elif delay == "loading":
            return "<span foreground='#888888'>⏳ замер...</span>", 99997
        elif delay == -1:
            return "<span foreground='#FF5252'>Недоступен</span>", 99998
        elif delay < 150:
            return f"<span foreground='#00E676'><b>{delay} ms</b></span>", delay
        elif delay < 350:
            return f"<span foreground='#FFD600'><b>{delay} ms</b></span>", delay
        else:
            return f"<span foreground='#FF9100'><b>{delay} ms</b></span>", delay

    def update_server_list(self):
        self.model_servers.clear()
        nodes = self.get_current_nodes()
        active = self.data.get("active_node", "")

        for node in nodes:
            tag = node.get("tag", "")
            proto = node.get("type", "").upper()
            host = f"{node.get('server', '')}:{node.get('server_port', '')}"
            delay = self.delays.get(tag, None)
            delay_markup, delay_val = self.format_delay(delay)

            display_tag = f"● {tag}" if tag == active else f"  {tag}"
            self.model_servers.append([display_tag, proto, host, delay_markup, delay_val, tag])

    def on_timer_tick(self) -> bool:
        if self.is_visible():
            self.update_status_ui()
        return True

    def get_active_node_dict(self) -> dict:
        tag = self.data.get("active_node")
        for n in self.get_current_nodes():
            if n.get("tag") == tag:
                return n
        nodes = self.get_current_nodes()
        return nodes[0] if nodes else None

    def prompt_conflict_if_any(self) -> bool:
        """Checks for conflicting VPN (e.g. Happ) and prompts user."""
        conflict = self.core.is_conflict_running()
        if not conflict:
            return True
        dialog = Gtk.MessageDialog(
            transient_for=self,
            flags=0,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.NONE,
            text=f"Обнаружен активный VPN ({conflict})"
        )
        dialog.format_secondary_text(
            f"В системе уже работает {conflict}, который управляет сетевыми маршрутами (TUN).\n\n"
            f"Одновременная работа двух VPN-клиентов приведет к конфликту маршрутов и обрыву связи.\n\n"
            f"Пожалуйста, сначала остановите {conflict} перед включением ThistleClient."
        )
        dialog.add_button("Понятно", Gtk.ResponseType.CLOSE)
        dialog.run()
        dialog.destroy()
        return False

    def on_toggle_clicked(self, widget):
        if self.core.is_running():
            self.core.stop()
        else:
            if not self.prompt_conflict_if_any():
                return
            if not self.get_current_nodes():
                self.show_error("Нет доступных серверов. Добавьте подписку.")
                return
            active_node = self.get_active_node_dict()
            self.sync_config(enable_tun=True)
            success = self.core.start(active_node=active_node)
            if not success:
                err_msg = "Не удалось запустить ядро VPN."
                logs = self.core.get_recent_logs(15)
                if logs and logs != "Log is empty.":
                    err_msg += "\n\nЖурнал:\n" + logs
                self.show_error(err_msg)
        self.update_status_ui()
        self.update_server_list()
        if self.tray_app:
            self.tray_app.update_icon_state()
            self.tray_app.build_menu()

    def on_sub_changed(self, widget):
        sub_name = self.combo_subs.get_active_text()
        if sub_name and sub_name != self.data.get("active_sub"):
            self.data["active_sub"] = sub_name
            nodes = self.get_current_nodes()
            if nodes:
                self.data["active_node"] = nodes[0].get("tag", "")
            self.save_data()
            self.delays = {}
            if self.core.is_running():
                self.core.switch_node(self.get_active_node_dict())
            self.sync_config(enable_tun=True)
            self.update_server_list()
            self.update_status_ui()
            if self.tray_app:
                self.tray_app.update_icon_state()
                self.tray_app.build_menu()

    def on_server_row_activated(self, tree, path, column):
        self.activate_selected_server()

    def on_select_server_clicked(self, widget):
        self.activate_selected_server()

    def activate_selected_server(self):
        selection = self.tree_servers.get_selection()
        model, tree_iter = selection.get_selected()
        if tree_iter:
            raw_tag = model[tree_iter][5]
            self.data["active_node"] = raw_tag
            self.save_data()

            node = self.get_active_node_dict()
            if self.core.is_running():
                self.core.switch_node(node)
                self.sync_config(enable_tun=True)
            else:
                if not self.prompt_conflict_if_any():
                    self.update_server_list()
                    return
                self.sync_config(enable_tun=True)
                success = self.core.start(active_node=node)
                if not success:
                    err_msg = "Не удалось запустить ядро VPN."
                    logs = self.core.get_recent_logs(15)
                    if logs and logs != "Log is empty.":
                        err_msg += "\n\nЖурнал:\n" + logs
                    self.show_error(err_msg)
            self.update_server_list()
            self.update_status_ui()
            if self.tray_app:
                self.tray_app.update_icon_state()
                self.tray_app.build_menu()

    def update_single_node_ping(self, tag: str, delay: int, ping_scope=None):
        """Live progressive UI update for a single node."""
        if ping_scope is not None and self.data.get("active_sub", "") != ping_scope:
            return
        self.delays[tag] = delay
        markup, val = self.format_delay(delay)
        for row in self.model_servers:
            node_tag = row[5]
            if node_tag == tag:
                row[3] = markup
                row[4] = val
        if self.tray_app:
            self.tray_app.delays[tag] = delay

    def begin_ping(self):
        """Mark every visible row as in progress on the GTK main thread."""
        self.is_pinging = True
        self._ping_scope = self.data.get("active_sub", "")
        if self.tray_app:
            self.tray_app.delays.clear()
            self.delays = self.tray_app.delays
        else:
            self.delays.clear()
        self.btn_ping.set_label("⏳ Замер...")
        self.btn_ping.set_sensitive(False)
        loading_markup, loading_val = self.format_delay("loading")
        for row in self.model_servers:
            row[3] = loading_markup
            row[4] = loading_val

    def on_ping_clicked(self, widget):
        # The tray app owns the single shared job when this window belongs to it.
        if self.tray_app:
            self.tray_app.on_measure_ping(None)
            return

        nodes = self.get_current_nodes()
        if not nodes or self.is_pinging:
            return

        self.begin_ping()
        ping_scope = self._ping_scope

        # Force method to Proxy-GET per requirements
        method = "Proxy-GET"
        timeout = int(settings.get("ping", "timeout", 4))
        test_url = settings.get("ping", "url", "http://connectivity-check.ubuntu.com")
        workers = int(settings.get("ping", "parallel_workers", 8))

        def worker():
            results = {}
            try:
                def on_progress(tag: str, delay: int):
                    GLib.idle_add(self.update_single_node_ping, tag, delay, ping_scope)

                results = self.pinger.ping_all(
                    nodes,
                    method=method,
                    timeout=timeout,
                    test_url=test_url,
                    clash_api=self.clash_api,
                    max_workers=workers,
                    on_progress=on_progress
                )
            except Exception as e:
                print(f"[Ping] Error during ping_all: {e}")
            finally:
                GLib.idle_add(self.finish_ping, results, ping_scope)

        threading.Thread(target=worker, daemon=True).start()

    def finish_ping(self, results: dict, ping_scope=None):
        same_scope = ping_scope is None or self.data.get("active_sub", "") == ping_scope
        if same_scope and results:
            self.delays.update(results)
        self.is_pinging = False
        self._ping_scope = None
        self.btn_ping.set_label("⚡ Измерить пинг")
        has_nodes = bool(self.get_current_nodes())
        self.btn_ping.set_sensitive(has_nodes)

        # Final sweep to make sure all rows reflect their true delay (no stuck loading)
        if same_scope:
            for row in self.model_servers:
                node_tag = row[5]
                if node_tag in self.delays:
                    markup, val = self.format_delay(self.delays[node_tag])
                    row[3] = markup
                    row[4] = val

        if self.tray_app:
            self.tray_app.is_pinging = False
            if same_scope:
                self.tray_app.delays.update(results)
            self.tray_app.build_menu()

    def apply_ping_results(self, results: dict):
        self.finish_ping(results)

    def on_open_settings(self, widget):
        dlg = SettingsDialog(parent=self, on_saved_callback=self.on_settings_saved)
        if dlg.run() == Gtk.ResponseType.OK:
            dlg.save_values()
        dlg.destroy()

    def on_settings_saved(self):
        # Refresh ports and endpoints
        clash_port = int(settings.get("network", "clash_port", 9095))
        mixed_port = int(settings.get("network", "mixed_port", 2080))
        self.clash_api = ClashAPI(port=clash_port)
        self.pinger = MultiModePinger(mixed_port=mixed_port, clash_port=clash_port)
        self.sync_config(enable_tun=self.core.is_running())
        self.update_status_ui()
        self.update_server_list()
        if self.tray_app:
            self.tray_app.on_settings_saved()

    def on_add_sub_dialog(self, widget):
        dialog = Gtk.Dialog(title="Добавить подписку", parent=self, flags=0)
        dialog.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OK, Gtk.ResponseType.OK)
        dialog.set_default_size(500, 200)

        content = dialog.get_content_area()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(12)

        entry_name = Gtk.Entry()
        entry_name.set_placeholder_text("Название: MyVPN")

        entry_url = Gtk.Entry()
        entry_url.set_placeholder_text("URL подписки или vless://... / Base64")

        box.pack_start(Gtk.Label(label="Название:", xalign=0), False, False, 0)
        box.pack_start(entry_name, False, False, 0)
        box.pack_start(Gtk.Label(label="Ссылка или ключ:", xalign=0), False, False, 0)
        box.pack_start(entry_url, False, False, 0)
        content.add(box)
        dialog.show_all()

        if dialog.run() == Gtk.ResponseType.OK:
            name = entry_name.get_text().strip() or f"Подписка {len(self.data.get('subs', {})) + 1}"
            raw = entry_url.get_text().strip()
            if raw:
                try:
                    if raw.startswith(("http://", "https://")):
                        nodes = fetch_subscription(raw)
                        url = raw
                    else:
                        nodes = parse_subscription_content(raw)
                        url = ""

                    if nodes:
                        if "subs" not in self.data:
                            self.data["subs"] = {}
                        self.data["subs"][name] = {"url": url, "nodes": nodes, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
                        self.data["active_sub"] = name
                        self.data["active_node"] = nodes[0].get("tag", "")
                        self.save_data()
                        self.sync_config(enable_tun=True)
                        self.update_sub_list()
                        self.update_server_list()
                        self.update_status_ui()
                    else:
                        self.show_error("Не удалось распознать серверы по указанной ссылке.")
                except Exception as e:
                    self.show_error(f"Ошибка загрузки: {e}")

        dialog.destroy()

    def on_refresh_sub_clicked(self, widget):
        sub_name = self.data.get("active_sub")
        sub_data = self.data.get("subs", {}).get(sub_name)
        if not sub_data or not sub_data.get("url"):
            self.show_error("У текущей подписки нет сетевого URL для обновления.")
            return

        def worker():
            try:
                nodes = fetch_subscription(sub_data["url"])
                if nodes:
                    sub_data["nodes"] = nodes
                    sub_data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                    self.save_data()
                    GLib.idle_add(self.sync_config, True)
                    GLib.idle_add(self.update_server_list)
                    GLib.idle_add(self.show_info, f"Подписка '{sub_name}' успешно обновлена ({len(nodes)} серв.)")
                else:
                    GLib.idle_add(self.show_error, "Серверы в подписке не найдены.")
            except Exception as e:
                GLib.idle_add(self.show_error, f"Ошибка: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def on_delete_sub_clicked(self, widget):
        sub_name = self.data.get("active_sub")
        if not sub_name or sub_name not in self.data.get("subs", {}):
            return

        del self.data["subs"][sub_name]
        remaining = list(self.data["subs"].keys())
        if remaining:
            self.data["active_sub"] = remaining[0]
            nodes = self.get_current_nodes()
            self.data["active_node"] = nodes[0].get("tag", "") if nodes else ""
        else:
            self.data["active_sub"] = ""
            self.data["active_node"] = ""

        self.save_data()
        self.sync_config(enable_tun=True)
        self.update_sub_list()
        self.update_server_list()
        self.update_status_ui()

    def show_error(self, msg: str):
        dialog = Gtk.MessageDialog(parent=self, flags=0, message_type=Gtk.MessageType.ERROR,
                                   buttons=Gtk.ButtonsType.OK, text="Ошибка")
        dialog.format_secondary_text(msg)
        dialog.run()
        dialog.destroy()

    def show_info(self, msg: str):
        dialog = Gtk.MessageDialog(parent=self, flags=0, message_type=Gtk.MessageType.INFO,
                                   buttons=Gtk.ButtonsType.OK, text="Уведомление")
        dialog.format_secondary_text(msg)
        dialog.run()
        dialog.destroy()


def main():
    from thistle_client.main import main as app_main
    if "--gui" not in sys.argv and "-g" not in sys.argv:
        sys.argv.append("--gui")
    app_main()


if __name__ == "__main__":
    main()
