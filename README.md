<div align="center">

<img src="icons/thistle-logo.svg" alt="ThistleClient Logo" width="128" height="128">

# 🌿 ThistleClient

**Ультралегковесный, бескомпромиссный гибридный VPN-клиент для Linux**  
*Ultra-lightweight, uncompromising hybrid VPN client for Linux*

[![Platform](https://img.shields.io/badge/Platform-Linux%20(X11%20%2F%20Wayland)-blue.svg?style=flat-square)]()
[![Cores](https://img.shields.io/badge/Cores-Sing--box%20%2B%20Xray-8a2be2.svg?style=flat-square)]()
[![RAM Usage](https://img.shields.io/badge/RAM-~25%20MB%20(vs%20400MB%20Happ)-brightgreen.svg?style=flat-square)]()
[![GUI](https://img.shields.io/badge/GUI-Native%20GTK%203%20%2B%20Tray-orange.svg?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)]()

---

### [ 🇷🇺 Русская версия ](#-русская-версия) &nbsp;•&nbsp; [ 🇬🇧 English Version ](#-english-version)

---

</div>

<br>

<a name="-русская-версия"></a>
# 🇷🇺 Русская версия

## 💡 О проекте

Большинство популярных клиентов для обхода блокировок (Happ, v2rayA, Nekoray) построены на базе тяжелых фреймворков (Electron, Chromium, Qt WebEngine), потребляя **350–500 МБ оперативной памяти** в фоне исключительно на отрисовку интерфейса. При этом многие из них используют поверхностный замер задержки (TCP SYN ping вместо реального HTTP-ответа), вызывают конфликты таблиц маршрутизации ядра и оставляют зомби-процессы.

**ThistleClient** решает эти проблемы на уровне архитектуры:
- **Нативный стек:** Написан на чистом **Python 3 + PyGObject (GTK 3)** без браузерных движков.
- **Минимальный аппетит к памяти:** Всего **~20–25 МБ RAM** в работающем состоянии.
- **Гибридное ядро:** **Sing-box** отвечает за высокопроизводительный TUN (`thistle0`), перехват DNS и Hysteria 2, а **Xray-core** обслуживает VLESS (Reality, XHTTP, gRPC, WebSocket).
- **Честный Proxy-GET замер:** Реальное HTTP-время ответа через изолированные временные прокси без прерывания активного VPN и с гарантированным удалением временных процессов (zero leaks).
- **Плавный Live-интерфейс:** Прогрессивное обновление каждой строки серверов в `Gtk.TreeView` прямо во время замера в реальном времени.
- **Защита системной маршрутизации:** Автоматическая проверка слотов `ip rule` и таблиц `ip route`, предотвращающая конфликты с другими VPN-сервисами.

---

## ✨ Возможности

### ⚡ Честный и безопасный замер пинга (Proxy-GET)
- **Изолированный замер:** Создаёт временные inbounds на свободных портах ОС. Активный VPN-туннель пользователя **не прерывается** во время теста.
- **Честный HTTP Round-Trip:** Запрос выполняется через `curl` по локальному прокси к проверочному эндпоинту (`connectivity-check.ubuntu.com`), измеряя фактическое время прохождения пакетов до реального веб-ресурса.
- **Живое прогрессивное отображение:** Все ноды опрашиваются параллельно, а интерфейс мгновенно выводит задержку по мере ответа каждого сервера (`GLib.idle_add`).
- **Нулевая утечка процессов:** Все временные инстансы регистрируются в менеджере процессов и надежно уничтожаются групповым сигналом (`killpg`) с завершающим `reap`.

### 🌐 Поддерживаемые протоколы
- **VLESS (через Xray-core):**
  - **Reality** (с поддержкой `pbk`, `sid`, `spx`, маскировки SNI и Chrome/Edge fingerprint)
  - **XHTTP / SplitHTTP** (`mode=packet-up`, настраиваемый padding)
  - **gRPC** (мультиплексированный транспорт)
  - **WebSocket** (`ws` + TLS)
  - **TCP / Vision** (`xtls-rprx-vision`)
- **Hysteria 2 (через Sing-box):**
  - Полная поддержка обфускации **Salamander** (`obfs=salamander`)
  - Нативная работа по UDP (QUIC / HTTP/3)
- **Shadowsocks & Trojan:** TLS с валидацией SNI и AEAD шифрованием.

### 🛡️ Безопасность сети и ядра Linux
- **Защита политик маршрутизации:** Использует отдельную таблицу маршрутизации (`2024`) и приоритет правила (`9100`). Перед стартом проверяет `ip rule` и `ip route` — при коллизиях предотвращает сбой сети.
- **Умное распознавание чужих процессов:** Читает `/proc/<pid>/cmdline` и не трогает процессы других приложений (Happ, системный sing-box).
- **DNS без петель (Direct UDP):** Upstream DNS направляется напрямую на `8.8.8.8` без recursive-bootstrap петель через прокси. Sing-box перехватывает порт 53 через `hijack-dns`.
- **Обход локальных сетей (Bypass Private IPs):** Локальный трафик (192.168.0.0/16, 10.0.0.0/8, 127.0.0.0/8) всегда следует напрямую.

---

## 📊 Сравнение с аналогами

| Параметр | **ThistleClient** | **Happ VPN** | **v2rayA** | **Nekoray** |
| :--- | :---: | :---: | :---: | :---: |
| **Потребление RAM** | **~25 МБ** | ~400 МБ | ~180 МБ | ~120 МБ |
| **Графический стек** | **Нативный GTK 3** | Electron / Web | Web / Vue | Qt 5/6 |
| **Иконка в трее** | **Адаптивный SVG** | Растровый PNG | Веб-интерфейс | Растровый PNG |
| **Метод замера пинга** | **Изолированный Proxy-GET** | HTTP GET (с прерыванием) | Ping / HTTP | TCP / HTTP |
| **Живое обновление пинга** | **✅ Да (узел за узлом)** | ❌ Нет | ❌ Нет | ❌ Нет |
| **VLESS Reality + XHTTP** | **✅ Да (Xray backend)** | ✅ Да | ⚠️ Частично | ✅ Да |
| **Hysteria 2 (+Salamander)** | **✅ Да (Sing-box native)**| ✅ Да | ❌ Нет | ⚠️ Без Salamander |
| **Защита от конфликтов TUN** | **✅ Да (`ip rule` guard)** | ⚠️ Фиксированная | ⚠️ iptables | ⚠️ tun2socks |

---

## 🚀 Установка

### 1. Системные зависимости (Ubuntu / Debian / Linux Mint)
```bash
sudo apt update
sudo apt install -y python3 python3-gi python3-gi-cairo gir1.2-gtk-3.0 curl iproute2 libcap2-bin
```

> [!NOTE]
> Убедитесь, что в системе установлены бинарные файлы ядер:
> - Sing-box: `/usr/local/bin/sing-box` (или в `$PATH`)
> - Xray-core: `/usr/local/bin/xray` (или в `$PATH`)

> [!IMPORTANT]
> ThistleClient запускает TUN из пользовательского `systemd --user` сервиса. Для `auto_route` бинарнику sing-box нужен `CAP_NET_ADMIN` (и `CAP_NET_RAW` для сетевых операций):
> ```bash
> sudo setcap cap_net_admin,cap_net_raw+ep "$(readlink -f "$(command -v sing-box)")"
> ```
> После обновления sing-box file capabilities могут сброситься; установщик проверяет это и выводит предупреждение.

### 2. Установка ThistleClient
```bash
git clone https://github.com/thistleclaw/ThistleClient.git
cd ThistleClient
chmod +x install.sh
./install.sh
```

Скрипт установки автоматически:
1. Установит файлы приложения в `~/.local/share/thistle-client`.
2. Создаст исполняемый файл в `~/.local/bin/thistle-client`.
3. Зарегистрирует ярлык в меню приложений системы (`ThistleClient.desktop`).
4. Настроит автозапуск через пользовательский сервис `systemd --user`.

---

## 🖥️ Использование

### Запуск трей-индикатора:
```bash
thistle-client
```
В трее появится минималистичная иконка ThistleClient. По клику доступно контекстное меню:
- Включение / выключение VPN в один клик.
- Быстрый выбор сервера из списка с отображением актуальной задержки.
- Кнопка **⚡ Измерить пинг** с прогрессивным отображением.
- Управление подписками (Добавить, Обновить текущую, Удалить).
- Быстрый переход в «Окно управления» или «Настройки».

### Запуск окна управления (GUI):
```bash
thistle-client --gui
```

---

## 🧪 Тестирование

Проект покрыт автоматическим набором из 30 юнит-тестов (парсеры VLESS/Hy2, изоляция портов, трансляция Xray, проверка маршрутизации и отсутствие утечек процессов):

```bash
python3 -m unittest discover tests
```

---
<br>

<a name="-english-version"></a>
# 🇬🇧 English Version

## 💡 About The Project

Most popular Linux proxy and VPN clients (Happ, v2rayA, Nekoray) rely on heavy runtimes (Electron, Chromium, Qt WebEngine), eating up **350–500 MB of RAM** in the background merely to render UI elements. Furthermore, many use simplistic TCP handshake pings that fail to reflect actual bypass capability, trigger routing table collisions, or leave orphaned proxy processes behind.

**ThistleClient** provides an ultra-lean, production-grade alternative:
- **Native GUI Stack:** Built purely with **Python 3 + PyGObject (GTK 3)** without web engines.
- **Featherweight Footprint:** Consumes merely **~20–25 MB of RAM** while running.
- **Hybrid Core Architecture:** **Sing-box** powers the high-performance TUN interface (`thistle0`), DNS hijacking, and native Hysteria 2, while **Xray-core** powers VLESS (Reality, XHTTP, gRPC, WebSocket).
- **Honest Proxy-GET Latency:** Measures genuine end-to-end HTTP round-trip time through isolated ephemeral test proxies without interrupting the active VPN connection and with zero process leaks.
- **Progressive Live UI:** Dynamic node-by-node updates in `Gtk.TreeView` in real-time as each probe finishes.
- **Kernel Routing Guard:** Proactively checks `ip rule` priority slots and `ip route` tables to eliminate silent network collisions.

---

## ✨ Features

### ⚡ Honest & Isolated Proxy-GET Latency Engine
- **Non-Disruptive Testing:** Binds temporary inbounds to dynamic ephemeral loopback ports. Active user VPN tunnels **remain intact** throughout testing.
- **Real HTTP Round-Trip:** Uses `curl` through local proxies to fetch `http://connectivity-check.ubuntu.com`, measuring true censorship-bypass performance rather than raw TCP connectivity.
- **Live Progressive Rendering:** All nodes are probed concurrently; delays update smoothly in the GTK table the instant each node responds (`GLib.idle_add`).
- **Guaranteed Zero Process Leaks:** Test instances are tracked in a global process registry and reaped via process-group termination (`killpg`) and exit hooks (`atexit`).

### 🌐 Supported Protocols
- **VLESS (via Xray-core backend):**
  - **Reality** (supporting `pbk`, `sid`, `spx`, SNI preservation, Chrome/Edge fingerprint)
  - **XHTTP / SplitHTTP** (`mode=packet-up`, configurable padding)
  - **gRPC** (multiplexed transport)
  - **WebSocket** (`ws` + TLS)
  - **TCP / Vision** (`xtls-rprx-vision`)
- **Hysteria 2 (via native Sing-box):**
  - Full support for **Salamander** obfuscation (`obfs=salamander`)
  - Direct UDP-based QUIC / HTTP/3 transport
- **Shadowsocks & Trojan:** TLS with SNI verification and AEAD encryption.

### 🛡️ Linux Kernel & Routing Protection
- **Policy Routing Isolation:** Dedicated routing table (`2024`) and rule priority (`9100`). Pre-flight checks on `ip rule` and `ip route` prevent clobbering existing VPN tunnels.
- **Foreign Process Protection:** Inspects `/proc/<pid>/cmdline` arguments to avoid interfering with third-party VPN daemons.
- **Loop-Free DNS (Direct UDP):** Upstream DNS targets `8.8.8.8` directly over UDP without recursive proxy bootstrapping loops. Sing-box intercepts port 53 via `hijack-dns`.
- **Private Network Bypass:** Automatically routes private subnets (`192.168.0.0/16`, `10.0.0.0/8`, `127.0.0.0/8`) directly outside the tunnel.

---

## 📊 Comparison Table

| Metric | **ThistleClient** | **Happ VPN** | **v2rayA** | **Nekoray** |
| :--- | :---: | :---: | :---: | :---: |
| **RAM Consumption** | **~25 MB** | ~400 MB | ~180 MB | ~120 MB |
| **UI Framework** | **Native GTK 3** | Electron / Web | Web / Vue | Qt 5/6 |
| **Tray Icon** | **Adaptive SVG** | Raster PNG | Web-only | Raster PNG |
| **Latency Measurement** | **Isolated Proxy-GET**| HTTP GET (disruptive)| Ping / HTTP | TCP / HTTP |
| **Live UI Delay Updates**| **✅ Yes (node-by-node)**| ❌ No | ❌ No | ❌ No |
| **VLESS Reality + XHTTP**| **✅ Yes (Xray core)** | ✅ Yes | ⚠️ Partial | ✅ Yes |
| **Hysteria 2 (+Salamander)**|**✅ Yes (Sing-box native)**| ✅ Yes | ❌ No | ⚠️ No Salamander |
| **TUN Routing Collision Guard**|**✅ Yes (`ip rule` check)**| ⚠️ Fixed | ⚠️ iptables | ⚠️ tun2socks |

---

## 🚀 Quick Start

### 1. Install System Dependencies (Ubuntu / Debian / Mint)
```bash
sudo apt update
sudo apt install -y python3 python3-gi python3-gi-cairo gir1.2-gtk-3.0 curl iproute2 libcap2-bin
```

> [!NOTE]
> Ensure the following core binaries are available in your `$PATH` or `/usr/local/bin`:
> - Sing-box: `/usr/local/bin/sing-box` (or in `$PATH`)
> - Xray-core: `/usr/local/bin/xray` (or in `$PATH`)

> [!IMPORTANT]
> ThistleClient starts its TUN from a `systemd --user` service. With `auto_route`, the sing-box binary needs `CAP_NET_ADMIN` (and `CAP_NET_RAW` for network operations):
> ```bash
> sudo setcap cap_net_admin,cap_net_raw+ep "$(readlink -f "$(command -v sing-box)")"
> ```
> File capabilities may be cleared when sing-box is upgraded; the installer checks this and prints a warning.

### 2. Install ThistleClient
```bash
git clone https://github.com/thistleclaw/ThistleClient.git
cd ThistleClient
chmod +x install.sh
./install.sh
```

The installer will:
1. Install client files into `~/.local/share/thistle-client`.
2. Link the executable into `~/.local/bin/thistle-client`.
3. Install the desktop launcher (`ThistleClient.desktop`).
4. Configure and enable the `systemd --user` background service.

---

## 🛠️ Usage

### Run System Tray Indicator:
```bash
thistle-client
```
Clicking the tray icon opens the context menu:
- 1-click VPN connect/disconnect.
- Quick server selection with latency badges.
- **⚡ Measure Latency** button with progressive live updates.
- Subscription CRUD management (Add, Update, Delete).
- Shortcuts to the Control Center and Settings Dialog.

### Open Control Center GUI:
```bash
thistle-client --gui
```

---

## 🧪 Testing

The test suite contains 30 automated unit tests verifying VLESS/Hy2 parsers, Xray outbound translation, dynamic port isolation, routing checks, and leak-free process management:

```bash
python3 -m unittest discover tests
```

---

## 📁 Repository Structure

```
ThistleClient/
├── thistle-client            # Main launcher script
├── thistle-client.desktop    # Application menu entry
├── thistle-client.service    # Systemd user service unit
├── install.sh                # Automated installer
├── uninstall.sh              # Clean uninstaller
├── requirements.txt          # Python dependencies
├── LICENSE                   # MIT License
├── README.md                 # Bilingual documentation
├── tests/                    # Unit test suite
│   └── test_thistle.py       # 30 automated tests
├── thistle_client/           # Application package
│   ├── config.py             # Settings manager
│   ├── pinger.py             # Isolated Proxy-GET engine
│   ├── clash_api.py          # Sing-box REST client
│   ├── config_generator.py   # Sing-box 1.12+ config builder
│   ├── xray_adapter.py       # Xray backend manager
│   ├── core_manager.py       # Process supervisor & route guard
│   ├── subscription_parser.py# Subscription & protocol parser
│   ├── settings_dialog.py    # 25+ parameters configuration window
│   ├── manager_gui.py        # Control Center GTK window
│   └── main.py               # Status tray indicator
└── icons/                    # Adaptive vector icons (SVG)
    ├── thistle-active.svg    # Connected state icon
    ├── thistle-inactive.svg  # Disconnected state icon
    ├── thistle-symbolic.svg  # Desktop symbolic icon
    └── thistle-logo.svg      # High-resolution emblem
```

---

## 📄 License

Released under the permissive [MIT License](LICENSE).
