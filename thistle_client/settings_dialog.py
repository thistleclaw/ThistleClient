#!/usr/bin/env python3
"""
Comprehensive GTK 3 Settings Dialog for ThistleClient.
Configures latency probes, TUN parameters, UDP DNS resolvers, routing tables, and system autostart.
"""

import os
import subprocess
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Pango

from thistle_client.config import settings, SINGBOX_LOG_FILE


class SettingsDialog(Gtk.Dialog):
    def __init__(self, parent=None, on_saved_callback=None):
        super().__init__(title="Настройки ThistleClient", parent=parent, flags=0)
        self.set_default_size(620, 520)
        self.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)
        self.set_border_width(12)
        self.on_saved_callback = on_saved_callback

        self.add_buttons(
            "Отмена", Gtk.ResponseType.CANCEL,
            "💾 Сохранить и применить", Gtk.ResponseType.OK
        )

        # Style the OK button as suggested action
        btn_ok = self.get_widget_for_response(Gtk.ResponseType.OK)
        if btn_ok:
            btn_ok.get_style_context().add_class("suggested-action")

        content = self.get_content_area()
        self.build_ui(content)
        self.load_values()

    def build_ui(self, content_area):
        notebook = Gtk.Notebook()
        notebook.set_tab_pos(Gtk.PositionType.TOP)
        content_area.pack_start(notebook, True, True, 6)

        # Page 1: Latency & Ping
        notebook.append_page(self.build_ping_page(), Gtk.Label(label="⚡ Пинг и Задержка"))

        # Page 2: Network & TUN
        notebook.append_page(self.build_network_page(), Gtk.Label(label="🌐 Сеть и TUN"))

        # Page 3: DNS
        notebook.append_page(self.build_dns_page(), Gtk.Label(label="🔒 DNS Резолвер"))

        # Page 4: Routing
        notebook.append_page(self.build_routing_page(), Gtk.Label(label="🔀 Маршрутизация"))

        # Page 5: App & Logs
        notebook.append_page(self.build_app_page(), Gtk.Label(label="⚙️ Приложение"))

        content_area.show_all()

    def _create_group(self, title: str) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        lbl = Gtk.Label(xalign=0)
        lbl.set_markup(f"<b>{title}</b>")
        box.pack_start(lbl, False, False, 2)
        return box

    def _create_row(self, label_text: str, widget: Gtk.Widget, tooltip: str = "") -> Gtk.Box:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        lbl = Gtk.Label(label=label_text, xalign=0)
        lbl.set_hexpand(True)
        if tooltip:
            lbl.set_tooltip_text(tooltip)
            widget.set_tooltip_text(tooltip)
        row.pack_start(lbl, True, True, 0)
        row.pack_end(widget, False, False, 0)
        return row

    # --- Page 1: Ping Settings ---
    def build_ping_page(self) -> Gtk.ScrolledWindow:
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        vbox.set_border_width(12)
        scrolled.add(vbox)

        # Method Group
        grp_method = self._create_group("Метод измерения задержки (Ping)")
        self.combo_ping_method = Gtk.ComboBoxText()
        self.combo_ping_method.append("Proxy-GET", "Proxy-GET (Честный HTTP замер через прокси)")
        self.combo_ping_method.set_sensitive(False)
        grp_method.pack_start(self._create_row("Метод пинга:", self.combo_ping_method,
                                               "Замер выполняет HTTP GET через изолированный прокси узла."), False, False, 0)

        # Timeout Spin
        adj_timeout = Gtk.Adjustment(value=4, lower=1, upper=15, step_increment=1)
        self.spin_ping_timeout = Gtk.SpinButton(adjustment=adj_timeout)
        grp_method.pack_start(self._create_row("Таймаут замера (секунды):", self.spin_ping_timeout,
                                               "Максимальное время ожидания ответа узла до статуса 'Недоступен'."), False, False, 0)

        # Test URL
        self.combo_test_url = Gtk.ComboBoxText.new_with_entry()
        for url in [
            "http://connectivity-check.ubuntu.com",
            "http://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "http://connectivitycheck.gstatic.com/generate_204",
            "https://yandex.ru"
        ]:
            self.combo_test_url.append_text(url)
        grp_method.pack_start(self._create_row("URL для проверки (Proxy):", self.combo_test_url,
                                               "URL, к которому направляются проверочные HTTP запросы через прокси."), False, False, 0)

        # Workers
        adj_workers = Gtk.Adjustment(value=8, lower=1, upper=32, step_increment=1)
        self.spin_workers = Gtk.SpinButton(adjustment=adj_workers)
        grp_method.pack_start(self._create_row("Параллельных потоков замера:", self.spin_workers,
                                               "Число одновременных сетевых потоков для пинга списка серверов."), False, False, 0)

        # Auto Ping Checkbox
        self.chk_auto_ping = Gtk.CheckButton(label="Автоматически замерять пинг при открытии серверов")
        grp_method.pack_start(self.chk_auto_ping, False, False, 0)

        vbox.pack_start(grp_method, False, False, 0)
        return scrolled

    # --- Page 2: Network & TUN ---
    def build_network_page(self) -> Gtk.ScrolledWindow:
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        vbox.set_border_width(12)
        scrolled.add(vbox)

        grp_tun = self._create_group("Сетевой драйвер TUN")
        self.combo_stack = Gtk.ComboBoxText()
        self.combo_stack.append("mixed", "mixed (gVisor Userspace + System TCP, надежный)")
        self.combo_stack.append("system", "system (Чистый Kernel TUN, максимальная скорость)")
        self.combo_stack.append("gvisor", "gvisor (Userspace TCP/IP)")
        grp_tun.pack_start(self._create_row("Режим стека TUN:", self.combo_stack), False, False, 0)

        self.entry_iface = Gtk.Entry()
        grp_tun.pack_start(self._create_row("Имя интерфейса TUN:", self.entry_iface), False, False, 0)

        self.combo_mtu = Gtk.ComboBoxText()
        for mtu in ["1500", "1420", "1360", "1280"]:
            self.combo_mtu.append(mtu, f"{mtu} байт")
        grp_tun.pack_start(self._create_row("MTU туннеля:", self.combo_mtu), False, False, 0)

        self.chk_strict_route = Gtk.CheckButton(label="Строгая изоляция маршрутов (strict_route)")
        grp_tun.pack_start(self.chk_strict_route, False, False, 0)

        self.chk_auto_route = Gtk.CheckButton(label="Автоматическая маршрутизация системы (auto_route)")
        grp_tun.pack_start(self.chk_auto_route, False, False, 0)

        vbox.pack_start(grp_tun, False, False, 0)

        # Routing Table IDs
        grp_routing = self._create_group("Изоляция таблиц ядра Linux (iproute2)")
        adj_table = Gtk.Adjustment(value=2024, lower=100, upper=60000, step_increment=1)
        self.spin_table = Gtk.SpinButton(adjustment=adj_table)
        grp_routing.pack_start(self._create_row("Индекс таблицы маршрутизации:", self.spin_table,
                                                "Номер таблицы (по умолч. 2024, предотвращает конфликт с таблицей 2022)."), False, False, 0)

        adj_rule = Gtk.Adjustment(value=9100, lower=100, upper=60000, step_increment=1)
        self.spin_rule = Gtk.SpinButton(adjustment=adj_rule)
        grp_routing.pack_start(self._create_row("Индекс приоритета ip rule:", self.spin_rule,
                                               "Приоритет правила ядра Linux (по умолч. 9100)."), False, False, 0)

        vbox.pack_start(grp_routing, False, False, 0)

        # Ports
        grp_ports = self._create_group("Локальные порты прокси")
        adj_mixed = Gtk.Adjustment(value=2080, lower=1024, upper=65535, step_increment=1)
        self.spin_mixed_port = Gtk.SpinButton(adjustment=adj_mixed)
        grp_ports.pack_start(self._create_row("Mixed Proxy порт (SOCKS5/HTTP):", self.spin_mixed_port), False, False, 0)

        adj_clash = Gtk.Adjustment(value=9095, lower=1024, upper=65535, step_increment=1)
        self.spin_clash_port = Gtk.SpinButton(adjustment=adj_clash)
        grp_ports.pack_start(self._create_row("Clash REST API контроллер порт:", self.spin_clash_port), False, False, 0)

        vbox.pack_start(grp_ports, False, False, 0)
        return scrolled

    # --- Page 3: DNS Settings ---
    def build_dns_page(self) -> Gtk.ScrolledWindow:
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        vbox.set_border_width(12)
        scrolled.add(vbox)

        grp_dns = self._create_group("DNS сервер (UDP)")
        self.combo_dns_server = Gtk.ComboBoxText.new_with_entry()
        self.combo_dns_server.append("8.8.8.8", "Google DNS (8.8.8.8)")
        self.combo_dns_server.append("1.1.1.1", "Cloudflare DNS (1.1.1.1)")
        self.combo_dns_server.append("94.140.14.14", "AdGuard DNS (94.140.14.14)")
        self.combo_dns_server.append("9.9.9.9", "Quad9 DNS (9.9.9.9)")
        grp_dns.pack_start(self._create_row("DNS сервер:", self.combo_dns_server,
                                            "Прямой UDP DNS по IP-адресу; DNS-запросы приложений перехватываются sing-box."), False, False, 0)

        self.combo_strategy = Gtk.ComboBoxText()
        self.combo_strategy.append("prefer_ipv4", "Предпочитать IPv4 (prefer_ipv4)")
        self.combo_strategy.append("prefer_ipv6", "Предпочитать IPv6 (prefer_ipv6)")
        self.combo_strategy.append("ipv4_only", "Только IPv4 (ipv4_only)")
        grp_dns.pack_start(self._create_row("Стратегия резолвинга адресов:", self.combo_strategy), False, False, 0)

        self.chk_hijack_dns = Gtk.CheckButton(label="Перехватывать системные DNS запросы (Hijack DNS)")
        grp_dns.pack_start(self.chk_hijack_dns, False, False, 0)

        self.chk_dns_cache = Gtk.CheckButton(label="Независимый кэш DNS (Independent Cache)")
        grp_dns.pack_start(self.chk_dns_cache, False, False, 0)

        vbox.pack_start(grp_dns, False, False, 0)
        return scrolled

    # --- Page 4: Routing ---
    def build_routing_page(self) -> Gtk.ScrolledWindow:
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        vbox.set_border_width(12)
        scrolled.add(vbox)

        grp_routing = self._create_group("Правила маршрутизации")
        self.chk_bypass_lan = Gtk.CheckButton(label="Обход локальных сетей (Bypass Private IPs: 10.0.0.0/8, 192.168.0.0/16)")
        grp_routing.pack_start(self.chk_bypass_lan, False, False, 0)

        self.chk_auto_detect_iface = Gtk.CheckButton(label="Авто-определение внешнего шлюза (auto_detect_interface)")
        grp_routing.pack_start(self.chk_auto_detect_iface, False, False, 0)

        vbox.pack_start(grp_routing, False, False, 0)

        grp_auto = self._create_group("Авто-переключение серверов (URLTest)")
        self.combo_interval = Gtk.ComboBoxText()
        for iv in ["1m", "3m", "5m", "10m", "15m"]:
            self.combo_interval.append(iv, iv)
        grp_auto.pack_start(self._create_row("Интервал тестирования:", self.combo_interval), False, False, 0)

        adj_tol = Gtk.Adjustment(value=50, lower=10, upper=300, step_increment=10)
        self.spin_tolerance = Gtk.SpinButton(adjustment=adj_tol)
        grp_auto.pack_start(self._create_row("Порог задержки (Tolerance ms):", self.spin_tolerance), False, False, 0)

        vbox.pack_start(grp_auto, False, False, 0)
        return scrolled

    # --- Page 5: App & System ---
    def build_app_page(self) -> Gtk.ScrolledWindow:
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        vbox.set_border_width(12)
        scrolled.add(vbox)

        grp_app = self._create_group("Параметры приложения")
        self.chk_autostart = Gtk.CheckButton(label="Запускать индикатор при входе в систему (Autostart)")
        grp_app.pack_start(self.chk_autostart, False, False, 0)

        self.chk_close_to_tray = Gtk.CheckButton(label="При закрытии окна сворачивать в трей (Close to Tray)")
        self.chk_close_to_tray.set_tooltip_text("Если флажок установлен, при нажатии на крестик окно скрывается в системный трей вместо завершения процесса.")
        grp_app.pack_start(self.chk_close_to_tray, False, False, 0)

        self.chk_notifications = Gtk.CheckButton(label="Всплывающие уведомления на рабочем столе (notify-send)")
        grp_app.pack_start(self.chk_notifications, False, False, 0)

        self.combo_theme = Gtk.ComboBoxText()
        self.combo_theme.append("monochrome", "Монохромный стиль (SVG)")
        self.combo_theme.append("color", "Цветной стиль")
        grp_app.pack_start(self._create_row("Тема иконки в системном трее:", self.combo_theme), False, False, 0)

        self.combo_log_level = Gtk.ComboBoxText()
        for lvl in ["warn", "info", "debug", "trace"]:
            self.combo_log_level.append(lvl, lvl.upper())
        grp_app.pack_start(self._create_row("Уровень детализации журнала Sing-box:", self.combo_log_level), False, False, 0)

        vbox.pack_start(grp_app, False, False, 0)

        # Log & Tools
        grp_tools = self._create_group("Диагностика и Журнал")
        btn_view_logs = Gtk.Button(label="📄 Открыть журнал singbox.log")
        btn_view_logs.connect("clicked", self.on_view_logs_clicked)

        btn_clear_logs = Gtk.Button(label="🧹 Очистить журнал")
        btn_clear_logs.connect("clicked", self.on_clear_logs_clicked)

        btn_reset_defaults = Gtk.Button(label="🔄 Сбросить все настройки по умолчанию")
        btn_reset_defaults.connect("clicked", self.on_reset_defaults_clicked)

        tools_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        tools_box.pack_start(btn_view_logs, True, True, 0)
        tools_box.pack_start(btn_clear_logs, True, True, 0)
        grp_tools.pack_start(tools_box, False, False, 0)
        grp_tools.pack_start(btn_reset_defaults, False, False, 0)

        vbox.pack_start(grp_tools, False, False, 0)
        return scrolled

    # --- Data Binding ---
    def load_values(self):
        # Ping
        self.combo_ping_method.set_active_id("Proxy-GET")
        self.spin_ping_timeout.set_value(int(settings.get("ping", "timeout", 4)))
        entry_test_url = self.combo_test_url.get_child()
        if entry_test_url:
            entry_test_url.set_text(settings.get("ping", "url", "http://connectivity-check.ubuntu.com"))
        self.spin_workers.set_value(int(settings.get("ping", "parallel_workers", 8)))
        self.chk_auto_ping.set_active(bool(settings.get("ping", "auto_ping_on_load", False)))

        # Network
        self.combo_stack.set_active_id(settings.get("network", "stack", "mixed"))
        self.entry_iface.set_text(settings.get("network", "interface_name", "thistle0"))
        self.combo_mtu.set_active_id(str(settings.get("network", "mtu", 1500)))
        self.chk_strict_route.set_active(bool(settings.get("network", "strict_route", True)))
        self.chk_auto_route.set_active(bool(settings.get("network", "auto_route", True)))
        self.spin_table.set_value(int(settings.get("network", "table_index", 2024)))
        self.spin_rule.set_value(int(settings.get("network", "rule_index", 9100)))
        self.spin_mixed_port.set_value(int(settings.get("network", "mixed_port", 2080)))
        self.spin_clash_port.set_value(int(settings.get("network", "clash_port", 9095)))

        # DNS
        entry_dns_server = self.combo_dns_server.get_child()
        if entry_dns_server:
            entry_dns_server.set_text(settings.get("dns", "remote_server", "8.8.8.8"))
        self.combo_strategy.set_active_id(settings.get("dns", "strategy", "prefer_ipv4"))
        self.chk_hijack_dns.set_active(bool(settings.get("dns", "hijack_dns", True)))
        self.chk_dns_cache.set_active(bool(settings.get("dns", "independent_cache", True)))

        # Routing
        self.chk_bypass_lan.set_active(bool(settings.get("routing", "bypass_private", True)))
        self.chk_auto_detect_iface.set_active(bool(settings.get("routing", "auto_detect_interface", True)))
        self.combo_interval.set_active_id(settings.get("routing", "urltest_interval", "5m"))
        self.spin_tolerance.set_value(int(settings.get("routing", "urltest_tolerance", 50)))

        # App
        self.chk_autostart.set_active(bool(settings.get("app", "autostart", True)))
        self.chk_close_to_tray.set_active(bool(settings.get("app", "close_to_tray", True)))
        self.chk_notifications.set_active(bool(settings.get("app", "notifications", True)))
        self.combo_theme.set_active_id(settings.get("app", "tray_theme", "monochrome"))
        self.combo_log_level.set_active_id(settings.get("app", "log_level", "warn"))

    def save_values(self):
        # Ping
        settings.set("ping", "method", "Proxy-GET")
        settings.set("ping", "timeout", int(self.spin_ping_timeout.get_value()))
        entry_url = self.combo_test_url.get_child()
        if entry_url:
            settings.set("ping", "url", entry_url.get_text().strip())
        settings.set("ping", "parallel_workers", int(self.spin_workers.get_value()))
        settings.set("ping", "auto_ping_on_load", self.chk_auto_ping.get_active())

        # Network
        settings.set("network", "stack", self.combo_stack.get_active_id() or "mixed")
        settings.set("network", "interface_name", self.entry_iface.get_text().strip() or "thistle0")
        settings.set("network", "mtu", int(self.combo_mtu.get_active_id() or "1500"))
        settings.set("network", "strict_route", self.chk_strict_route.get_active())
        settings.set("network", "auto_route", self.chk_auto_route.get_active())
        settings.set("network", "table_index", int(self.spin_table.get_value()))
        settings.set("network", "rule_index", int(self.spin_rule.get_value()))
        settings.set("network", "mixed_port", int(self.spin_mixed_port.get_value()))
        settings.set("network", "clash_port", int(self.spin_clash_port.get_value()))

        # DNS
        entry_dns_server = self.combo_dns_server.get_child()
        if entry_dns_server:
            settings.set("dns", "remote_server", entry_dns_server.get_text().strip() or "8.8.8.8")
        settings.set("dns", "strategy", self.combo_strategy.get_active_id() or "prefer_ipv4")
        settings.set("dns", "hijack_dns", self.chk_hijack_dns.get_active())
        settings.set("dns", "independent_cache", self.chk_dns_cache.get_active())

        # Routing
        settings.set("routing", "bypass_private", self.chk_bypass_lan.get_active())
        settings.set("routing", "auto_detect_interface", self.chk_auto_detect_iface.get_active())
        settings.set("routing", "urltest_interval", self.combo_interval.get_active_id() or "5m")
        settings.set("routing", "urltest_tolerance", int(self.spin_tolerance.get_value()))

        # App
        settings.set("app", "autostart", self.chk_autostart.get_active())
        settings.set("app", "close_to_tray", self.chk_close_to_tray.get_active())
        settings.set("app", "notifications", self.chk_notifications.get_active())
        settings.set("app", "tray_theme", self.combo_theme.get_active_id() or "monochrome")
        settings.set("app", "log_level", self.combo_log_level.get_active_id() or "warn")

        settings.save()
        if self.on_saved_callback:
            self.on_saved_callback()

    def on_view_logs_clicked(self, widget):
        log_dialog = Gtk.Dialog(title="Журнал Sing-box", parent=self, flags=0)
        log_dialog.set_default_size(580, 380)
        log_dialog.add_button("Закрыть", Gtk.ResponseType.CLOSE)

        box = log_dialog.get_content_area()
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        tv = Gtk.TextView()
        tv.set_editable(False)
        tv.set_monospace(True)
        tv.get_style_context().add_class("view")

        log_content = "Журнал пуст."
        if os.path.exists(SINGBOX_LOG_FILE):
            try:
                with open(SINGBOX_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    log_content = "".join(lines[-100:]) or "Журнал пуст."
            except Exception as e:
                log_content = f"Ошибка чтения журнала: {e}"

        buf = tv.get_buffer()
        buf.set_text(log_content)
        scrolled.add(tv)
        box.pack_start(scrolled, True, True, 6)
        log_dialog.show_all()
        log_dialog.run()
        log_dialog.destroy()

    def on_clear_logs_clicked(self, widget):
        try:
            with open(SINGBOX_LOG_FILE, "w") as f:
                f.truncate(0)
            self._show_info("Журнал успешно очищен.")
        except Exception as e:
            self._show_error(f"Ошибка очистки: {e}")

    def on_reset_defaults_clicked(self, widget):
        confirm = Gtk.MessageDialog(
            parent=self, flags=0, message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO, text="Сбросить настройки?"
        )
        confirm.format_secondary_text("Все параметры вернутся к рекомендуемым значениям по умолчанию.")
        if confirm.run() == Gtk.ResponseType.YES:
            settings.reset_defaults()
            self.load_values()
            self._show_info("Настройки сброшены по умолчанию.")
        confirm.destroy()

    def _show_info(self, msg: str):
        d = Gtk.MessageDialog(parent=self, flags=0, message_type=Gtk.MessageType.INFO,
                              buttons=Gtk.ButtonsType.OK, text=msg)
        d.run()
        d.destroy()

    def _show_error(self, msg: str):
        d = Gtk.MessageDialog(parent=self, flags=0, message_type=Gtk.MessageType.ERROR,
                              buttons=Gtk.ButtonsType.OK, text=msg)
        d.run()
        d.destroy()
