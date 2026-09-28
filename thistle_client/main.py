#!/usr/bin/env python3
"""
ThistleClient - Lightweight System Tray Indicator for Linux Mint Cinnamon / X11.
Features:
- Adaptive monochrome SVG systray icon
- Multi-mode ping latency measurement (TCP, ICMP, Proxy-HEAD, Proxy-GET)
- Zero-downtime server switching via Clash API
- Full subscription CRUD
- Instant settings dialog integration
"""

import json
import os
import socket
import subprocess
import sys
import threading
import time
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

from thistle_client.config import (
    settings, SUBS_FILE, SINGBOX_CONFIG_FILE, DATA_DIR, write_json_private
)
from thistle_client.config_generator import generate_singbox_config
from thistle_client.core_manager import CoreManager
from thistle_client.clash_api import ClashAPI
from thistle_client.pinger import MultiModePinger
from thistle_client.settings_dialog import SettingsDialog
from thistle_client.subscription_parser import fetch_subscription, parse_subscription_content

ICONS_DIR = os.path.join(os.path.dirname(__file__), "..", "icons")
ICON_ACTIVE = os.path.join(ICONS_DIR, "thistle-active.svg")
ICON_INACTIVE = os.path.join(ICONS_DIR, "thistle-inactive.svg")
ICON_SYMBOLIC = os.path.join(ICONS_DIR, "thistle-symbolic.svg")


class ThistleTrayApp:
    def __init__(self, show_gui: bool = False):
        clash_port = int(settings.get("network", "clash_port", 9095))
        mixed_port = int(settings.get("network", "mixed_port", 2080))
        self.clash_api = ClashAPI(port=clash_port)
        self.core = CoreManager(config_path=SINGBOX_CONFIG_FILE)
        self.pinger = MultiModePinger(mixed_port=mixed_port, clash_port=clash_port)

        self.delays = {}
        self.is_pinging = False
        self.manager_window = None

        self.load_data()

        # Initialize Gtk.StatusIcon
        self.status_icon = Gtk.StatusIcon()
        self.status_icon.set_title("ThistleClient")
        self.update_icon_state()
        self.status_icon.set_visible(True)

        self.menu = Gtk.Menu()
        self.build_menu()

        # Left click toggles/restores manager window, right click opens context menu
        self.status_icon.connect("popup-menu", self.on_popup_menu)
        self.status_icon.connect("activate", self.on_activate)

        if settings.get("app", "notifications", True):
            self.notify("ThistleClient", "Индикатор активен в системном трее")

        # Periodic check for core status
        GLib.timeout_add_seconds(2, self.check_status_tick)

        if show_gui:
            self.show_manager_window()

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
            write_json_private(SUBS_FILE, self.data)
        except Exception as e:
            print(f"Failed to save data: {e}")

    def notify(self, title: str, message: str):
        if not settings.get("app", "notifications", True):
            return
        try:
            subprocess.run(["notify-send", "-a", "ThistleClient", title, message], check=False)
        except Exception:
            pass

    def update_icon_state(self):
        is_running = self.core.is_running()
        active_node = self.data.get("active_node") or "Не выбран"
        icon_file = ICON_ACTIVE if is_running else ICON_INACTIVE
        tooltip = f"ThistleClient: Подключено ({active_node})" if is_running else "ThistleClient: Отключено"

        try:
            self.status_icon.set_from_file(icon_file)
        except Exception:
            self.status_icon.set_from_icon_name("network-vpn" if is_running else "network-offline")

        self.status_icon.set_tooltip_text(tooltip)

    def get_current_nodes(self) -> list:
        sub_name = self.data.get("active_sub")
        if sub_name and sub_name in self.data.get("subs", {}):
            return self.data["subs"][sub_name].get("nodes", [])
        return []

    def sync_config(self, enable_tun: bool = True, restart: bool = False):
        nodes = self.get_current_nodes()
        active_node = self.data.get("active_node", "")
        cfg = generate_singbox_config(nodes, active_tag=active_node, enable_tun=enable_tun)
        write_json_private(SINGBOX_CONFIG_FILE, cfg)

        if restart and self.core.is_running():
            active_dict = self.get_active_node_dict()
            self.core.restart(active_node=active_dict)
            self.notify("ThistleClient", "Конфигурация обновлена и туннель перезапущен")

    def build_menu(self):
        for child in self.menu.get_children():
            self.menu.remove(child)

        is_running = self.core.is_running()
        active_node = self.data.get("active_node") or "Не выбран"
        active_sub = self.data.get("active_sub") or "Нет"
        nodes = self.get_current_nodes()

        # 1. Header Status
        status_text = f"● Подключено: {active_node}" if is_running else "○ Отключено"
        status_item = Gtk.MenuItem(label=status_text)
        status_item.set_sensitive(False)
        self.menu.append(status_item)

        conflict = self.core.is_conflict_running()
        if conflict and not is_running:
            conflict_item = Gtk.MenuItem(label=f"⚠️ Запущен {conflict} (конфликт)")
            conflict_item.set_sensitive(False)
            self.menu.append(conflict_item)

        # 2. Toggle VPN
        toggle_label = "Отключить VPN" if is_running else "Включить VPN"
        toggle_item = Gtk.MenuItem(label=toggle_label)
        toggle_item.connect("activate", self.on_toggle_vpn)
        self.menu.append(toggle_item)

        self.menu.append(Gtk.SeparatorMenuItem())

        # 3. Servers Submenu
        servers_menu_item = Gtk.MenuItem(label=f"🌐 Серверы ({active_sub})")
        servers_sub = Gtk.Menu()

        if nodes:
            server_group = None
            for node in nodes:
                tag = node.get("tag", "Без имени")
                delay = self.delays.get(tag, None)
                label = f"{tag} ({delay} ms)" if delay and delay > 0 else tag
                if delay == -1:
                    label = f"{tag} (недоступен)"

                item = Gtk.RadioMenuItem(group=server_group, label=label)
                if server_group is None:
                    server_group = item

                if tag == self.data.get("active_node"):
                    item.set_active(True)

                item.connect("toggled", self.on_select_server, tag)
                servers_sub.append(item)
        else:
            empty_item = Gtk.MenuItem(label="Нет серверов (добавьте подписку)")
            empty_item.set_sensitive(False)
            servers_sub.append(empty_item)

        servers_menu_item.set_submenu(servers_sub)
        self.menu.append(servers_menu_item)

        # 4. Measure Latency / Ping
        ping_label = "⏳ Идет замер пинга..." if self.is_pinging else "⚡ Измерить пинг (Proxy-GET)"
        ping_item = Gtk.MenuItem(label=ping_label)
        ping_item.set_sensitive(not self.is_pinging and bool(nodes))
        ping_item.connect("activate", self.on_measure_ping)
        self.menu.append(ping_item)

        self.menu.append(Gtk.SeparatorMenuItem())

        # 5. Subscriptions Submenu (CRUD)
        subs_menu_item = Gtk.MenuItem(label="📁 Подписки")
        subs_sub = Gtk.Menu()
        all_subs = self.data.get("subs", {})

        if all_subs:
            sub_group = None
            for s_name, s_data in all_subs.items():
                count = len(s_data.get("nodes", []))
                s_item = Gtk.RadioMenuItem(group=sub_group, label=f"{s_name} ({count} серв.)")
                if sub_group is None:
                    sub_group = s_item

                if s_name == active_sub:
                    s_item.set_active(True)

                s_item.connect("toggled", self.on_switch_sub, s_name)
                subs_sub.append(s_item)

            subs_sub.append(Gtk.SeparatorMenuItem())

        add_sub_item = Gtk.MenuItem(label="➕ Добавить подписку...")
        add_sub_item.connect("activate", self.on_add_subscription_dialog)
        subs_sub.append(add_sub_item)

        update_sub_item = Gtk.MenuItem(label="🔄 Обновить текущую подписку")
        update_sub_item.set_sensitive(bool(active_sub and all_subs.get(active_sub, {}).get("url")))
        update_sub_item.connect("activate", self.on_refresh_subscription)
        subs_sub.append(update_sub_item)

        del_sub_item = Gtk.MenuItem(label="❌ Удалить текущую подписку")
        del_sub_item.set_sensitive(bool(active_sub and active_sub in all_subs))
        del_sub_item.connect("activate", self.on_delete_subscription)
        subs_sub.append(del_sub_item)

        subs_menu_item.set_submenu(subs_sub)
        self.menu.append(subs_menu_item)

        # 6. Settings
        settings_item = Gtk.MenuItem(label="⚙️ Настройки...")
        settings_item.connect("activate", self.on_open_settings)
        self.menu.append(settings_item)

        # 7. Control Window
        gui_item = Gtk.MenuItem(label="🖥️ Окно управления...")
        gui_item.connect("activate", self.on_open_gui)
        self.menu.append(gui_item)

        self.menu.append(Gtk.SeparatorMenuItem())

        # 8. Quit
        quit_item = Gtk.MenuItem(label="🚪 Закрыть ThistleClient")
        quit_item.connect("activate", self.on_quit)
        self.menu.append(quit_item)

        self.menu.show_all()

    def on_popup_menu(self, icon, button, activate_time):
        self.build_menu()
        self.menu.popup(None, None, Gtk.StatusIcon.position_menu, icon, button, activate_time)

    def on_activate(self, icon):
        if self.manager_window and self.manager_window.is_visible():
            self.manager_window.hide()
        else:
            self.show_manager_window()

    def show_manager_window(self):
        if self.manager_window is None:
            from thistle_client.manager_gui import ThistleManagerWindow
            self.manager_window = ThistleManagerWindow(tray_app=self)
        self.manager_window.refresh_all()
        self.manager_window.show_all()
        self.manager_window.present()

    def connect_vpn(self):
        if not self.core.is_running():
            self.on_toggle_vpn(None)

    def disconnect_vpn(self):
        if self.core.is_running():
            self.on_toggle_vpn(None)

    def check_status_tick(self) -> bool:
        self.update_icon_state()
        return True

    def get_active_node_dict(self) -> dict:
        tag = self.data.get("active_node")
        for n in self.get_current_nodes():
            if n.get("tag") == tag:
                return n
        nodes = self.get_current_nodes()
        return nodes[0] if nodes else None

    def on_toggle_vpn(self, widget):
        if self.core.is_running():
            self.core.stop()
            self.notify("ThistleClient", "VPN отключен")
        else:
            conflict = self.core.is_conflict_running()
            if conflict:
                self.notify("ThistleClient: Конфликт", f"Обнаружен работающий {conflict}! Остановите его перед включением ThistleClient.")
                if self.manager_window and self.manager_window.is_visible():
                    self.manager_window.present()
                return
            if not self.get_current_nodes():
                self.notify("ThistleClient", "Ошибка: нет серверов. Сначала добавьте подписку.")
                return
            active_node = self.get_active_node_dict()
            self.sync_config(enable_tun=True)
            success = self.core.start(active_node=active_node)
            if success:
                self.notify("ThistleClient", "VPN успешно подключен")
            else:
                self.notify("ThistleClient", "Ошибка запуска ядром VPN. Проверьте журнал.")

        self.update_icon_state()
        self.build_menu()
        if self.manager_window and self.manager_window.is_visible():
            self.manager_window.refresh_all()

    def on_select_server(self, widget, tag: str):
        if not widget.get_active():
            return
        previous_tag = self.data.get("active_node", "")
        self.data["active_node"] = tag
        self.save_data()

        node = self.get_active_node_dict()
        if self.core.is_running():
            if not self.core.switch_node(node):
                self.data["active_node"] = previous_tag
                self.save_data()
                self.notify("ThistleClient", f"Не удалось переключиться на сервер: {tag}")
                self.update_icon_state()
                self.build_menu()
                if self.manager_window and self.manager_window.is_visible():
                    self.manager_window.refresh_all()
                return
            self.sync_config(enable_tun=True)
            self.notify("ThistleClient", f"Сервер переключен: {tag}")
        self.update_icon_state()
        self.build_menu()

    def on_measure_ping(self, widget):
        nodes = self.get_current_nodes()
        if (not nodes or self.is_pinging
                or (self.manager_window and self.manager_window.is_pinging)):
            return

        self.is_pinging = True
        self.delays.clear()
        ping_scope = self.data.get("active_sub", "")
        if self.manager_window:
            self.manager_window.begin_ping()
        self.build_menu()

        method = "Proxy-GET"
        timeout = int(settings.get("ping", "timeout", 4))
        test_url = settings.get("ping", "url", "http://connectivity-check.ubuntu.com")
        workers = int(settings.get("ping", "parallel_workers", 8))

        def on_node_progress(tag: str, delay: int):
            GLib.idle_add(self.on_ping_progress, tag, delay, ping_scope)

        def worker():
            results = {}
            try:
                results = self.pinger.ping_all(
                    nodes,
                    method=method,
                    timeout=timeout,
                    test_url=test_url,
                    clash_api=self.clash_api,
                    max_workers=workers,
                    on_progress=on_node_progress
                )
            except Exception as e:
                print(f"[Ping] Error during ping_all: {e}")
            finally:
                GLib.idle_add(self.apply_ping_results, results, ping_scope)

        threading.Thread(target=worker, daemon=True).start()

    def on_ping_progress(self, tag: str, delay: int, ping_scope=None):
        if ping_scope is not None and self.data.get("active_sub", "") != ping_scope:
            return
        self.delays[tag] = delay
        if self.manager_window and self.manager_window.is_visible():
            self.manager_window.update_single_node_ping(tag, delay, ping_scope)

    def apply_ping_results(self, results: dict, ping_scope=None):
        same_scope = ping_scope is None or self.data.get("active_sub", "") == ping_scope
        if same_scope and results:
            self.delays.update(results)
        self.is_pinging = False
        if self.manager_window:
            self.manager_window.finish_ping(results if same_scope else {}, ping_scope)
        else:
            self.build_menu()
        self.notify("ThistleClient", "Замер задержки завершен")

    def on_switch_sub(self, widget, sub_name: str):
        if not widget.get_active():
            return
        self.data["active_sub"] = sub_name
        nodes = self.get_current_nodes()
        if nodes:
            self.data["active_node"] = nodes[0].get("tag", "")
        self.save_data()
        self.delays = {}
        was_running = self.core.is_running()
        self.sync_config(enable_tun=True, restart=was_running)
        self.update_icon_state()
        self.build_menu()
        if self.manager_window and self.manager_window.is_visible():
            self.manager_window.refresh_all()

    def on_open_settings(self, widget):
        dlg = SettingsDialog(on_saved_callback=self.on_settings_saved)
        if dlg.run() == Gtk.ResponseType.OK:
            dlg.save_values()
        dlg.destroy()

    def on_settings_saved(self):
        clash_port = int(settings.get("network", "clash_port", 9095))
        mixed_port = int(settings.get("network", "mixed_port", 2080))
        self.clash_api = ClashAPI(port=clash_port)
        self.pinger = MultiModePinger(mixed_port=mixed_port, clash_port=clash_port)
        was_running = self.core.is_running()
        self.sync_config(enable_tun=was_running, restart=was_running)
        self.update_icon_state()
        self.build_menu()
        if self.manager_window and self.manager_window.is_visible():
            self.manager_window.refresh_all()

    def on_open_gui(self, widget):
        self.show_manager_window()

    def on_add_subscription_dialog(self, widget):
        dialog = Gtk.Dialog(title="Добавить подписку", flags=0)
        dialog.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OK, Gtk.ResponseType.OK)
        dialog.set_default_size(500, 220)

        content_area = dialog.get_content_area()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(15)

        lbl_name = Gtk.Label(label="Название подписки:", xalign=0)
        entry_name = Gtk.Entry()
        entry_name.set_placeholder_text("Например: MyVPN")

        lbl_url = Gtk.Label(label="Ссылка на подписку (URL или vless://... / Base64):", xalign=0)
        entry_url = Gtk.Entry()
        entry_url.set_placeholder_text("https://... или vless://...")

        box.pack_start(lbl_name, False, False, 0)
        box.pack_start(entry_name, False, False, 0)
        box.pack_start(lbl_url, False, False, 0)
        box.pack_start(entry_url, False, False, 0)
        content_area.add(box)
        dialog.show_all()

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            name = entry_name.get_text().strip() or f"Подписка {len(self.data.get('subs', {})) + 1}"
            raw_input = entry_url.get_text().strip()
            if raw_input:
                try:
                    if raw_input.startswith(("http://", "https://")):
                        nodes = fetch_subscription(raw_input)
                        url = raw_input
                    else:
                        nodes = parse_subscription_content(raw_input)
                        url = ""

                    if nodes:
                        if "subs" not in self.data:
                            self.data["subs"] = {}
                        self.data["subs"][name] = {"url": url, "nodes": nodes, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
                        self.data["active_sub"] = name
                        self.data["active_node"] = nodes[0].get("tag", "")
                        self.save_data()
                        was_running = self.core.is_running()
                        self.sync_config(enable_tun=True, restart=was_running)
                        self.update_icon_state()
                        self.build_menu()
                        self.notify("ThistleClient", f"Подписка '{name}' добавлена! Найдено серверов: {len(nodes)}")
                    else:
                        self.notify("ThistleClient", "Ошибка: не удалось распознать серверы")
                except Exception as e:
                    self.notify("ThistleClient", f"Ошибка: {e}")

        dialog.destroy()

    def on_refresh_subscription(self, widget):
        sub_name = self.data.get("active_sub")
        sub_data = self.data.get("subs", {}).get(sub_name)
        if not sub_data or not sub_data.get("url"):
            return

        def worker():
            try:
                nodes = fetch_subscription(sub_data["url"])
                if nodes:
                    sub_data["nodes"] = nodes
                    sub_data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                    self.save_data()
                    was_running = self.core.is_running()
                    GLib.idle_add(self.sync_config, True, was_running)
                    GLib.idle_add(self.update_icon_state)
                    GLib.idle_add(self.build_menu)
                    GLib.idle_add(self.notify, "ThistleClient", f"Подписка '{sub_name}' обновлена ({len(nodes)} серв.)")
                else:
                    GLib.idle_add(self.notify, "ThistleClient", "Серверы в подписке не найдены")
            except Exception as e:
                GLib.idle_add(self.notify, "ThistleClient", f"Ошибка обновления: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def on_delete_subscription(self, widget):
        sub_name = self.data.get("active_sub")
        if not sub_name or sub_name not in self.data.get("subs", {}):
            return

        was_running = self.core.is_running()
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
        if remaining:
            self.sync_config(enable_tun=True, restart=was_running)
        else:
            if was_running:
                self.core.stop()
            self.sync_config(enable_tun=False)
        self.update_icon_state()
        self.build_menu()
        self.notify("ThistleClient", f"Подписка '{sub_name}' удалена")

    def on_quit(self, widget=None):
        try:
            sock_path = get_ipc_socket_path()
            if os.path.exists(sock_path):
                os.unlink(sock_path)
        except OSError:
            pass
        if self.manager_window:
            self.manager_window.destroy()
        Gtk.main_quit()


IPC_SOCKET_NAME = "thistle-client.sock"


def get_ipc_socket_path() -> str:
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir and os.path.exists(runtime_dir):
        return os.path.join(runtime_dir, IPC_SOCKET_NAME)
    return os.path.join(DATA_DIR, IPC_SOCKET_NAME)


def send_ipc_command(cmd: str) -> bool:
    sock_path = get_ipc_socket_path()
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect(sock_path)
        s.sendall(cmd.encode("utf-8") + b"\n")
        s.close()
        return True
    except (FileNotFoundError, ConnectionRefusedError, OSError):
        return False


def start_ipc_server(app) -> socket.socket:
    sock_path = get_ipc_socket_path()
    try:
        if os.path.exists(sock_path):
            os.unlink(sock_path)
    except OSError:
        pass

    try:
        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(sock_path)
        server_sock.listen(5)
    except Exception as e:
        print(f"[ThistleClient] Warning: Failed to start IPC server: {e}")
        return None

    def listen_loop():
        while True:
            try:
                conn, _ = server_sock.accept()
                raw_data = conn.recv(1024).decode("utf-8", errors="ignore").strip()
                conn.close()
                if raw_data == "SHOW":
                    GLib.idle_add(app.show_manager_window)
                elif raw_data == "CONNECT":
                    GLib.idle_add(app.connect_vpn)
                elif raw_data == "DISCONNECT":
                    GLib.idle_add(app.disconnect_vpn)
                elif raw_data == "TOGGLE":
                    GLib.idle_add(app.on_toggle_vpn, None)
                elif raw_data == "QUIT":
                    GLib.idle_add(app.on_quit)
            except Exception:
                break

    t = threading.Thread(target=listen_loop, daemon=True)
    t.start()
    return server_sock


def main():
    show_gui = "--gui" in sys.argv or "-g" in sys.argv

    # Check CLI commands
    cmd = None
    if "--connect" in sys.argv:
        cmd = "CONNECT"
    elif "--disconnect" in sys.argv:
        cmd = "DISCONNECT"
    elif "--toggle" in sys.argv:
        cmd = "TOGGLE"
    elif "--quit" in sys.argv:
        cmd = "QUIT"
    elif show_gui:
        cmd = "SHOW"

    # If an instance is already running, forward command and exit
    if cmd and send_ipc_command(cmd):
        sys.exit(0)

    app = ThistleTrayApp(show_gui=show_gui)
    ipc_server = start_ipc_server(app)

    try:
        Gtk.main()
    finally:
        if ipc_server:
            try:
                ipc_server.close()
            except Exception:
                pass
        try:
            sock_path = get_ipc_socket_path()
            if os.path.exists(sock_path):
                os.unlink(sock_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
