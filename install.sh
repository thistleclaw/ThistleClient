#!/usr/bin/env bash
set -euo pipefail

# ThistleClient Installation Script
REPO_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
TARGET_DIR="$HOME/.local/share/thistle-client"
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
SERVICE_DIR="$HOME/.config/systemd/user"
CONFIG_DIR="$HOME/.config/thistle-client"

echo "=== Установка ThistleClient ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "Ошибка: python3 не найден. Установите python3."
    exit 1
fi

SINGBOX_BIN="$(command -v sing-box 2>/dev/null || true)"
XRAY_BIN="$(command -v xray 2>/dev/null || true)"
if [[ -z "$SINGBOX_BIN" ]]; then
    echo "Ошибка: sing-box не найден в PATH."
    exit 1
fi
if [[ -z "$XRAY_BIN" ]]; then
    echo "Ошибка: xray не найден в PATH."
    exit 1
fi

mkdir -p "$TARGET_DIR" "$BIN_DIR" "$APP_DIR" "$SERVICE_DIR" "$TARGET_DIR/data" "$TARGET_DIR/icons" "$CONFIG_DIR"
chmod 700 "$TARGET_DIR/data" "$CONFIG_DIR"

rm -rf "$TARGET_DIR/thistle_client"
cp -r "$REPO_DIR/thistle_client" "$TARGET_DIR/"
cp -r "$REPO_DIR/icons"/* "$TARGET_DIR/icons/"
cp "$REPO_DIR/thistle-client" "$TARGET_DIR/thistle-client"
chmod +x "$TARGET_DIR/thistle-client"

ln -sf "$TARGET_DIR/thistle-client" "$BIN_DIR/thistle-client"

cp "$REPO_DIR/thistle-client.desktop" "$APP_DIR/thistle-client.desktop"
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APP_DIR" 2>/dev/null || true
fi

cp "$REPO_DIR/thistle-client.service" "$SERVICE_DIR/thistle-client.service"
systemctl --user daemon-reload
systemctl --user enable thistle-client.service

SINGBOX_REAL="$(readlink -f "$SINGBOX_BIN")"
if command -v getcap >/dev/null 2>&1; then
    SINGBOX_CAPS="$(getcap "$SINGBOX_REAL" 2>/dev/null || true)"
    if [[ "$EUID" -ne 0 && "$SINGBOX_CAPS" != *"cap_net_admin"* ]]; then
        echo
        echo "ВНИМАНИЕ: у sing-box нет CAP_NET_ADMIN; системный TUN может не запуститься."
        echo "Выдайте capability вручную:"
        echo "  sudo setcap cap_net_admin,cap_net_raw+ep \"$SINGBOX_REAL\""
        echo "После обновления бинарника sing-box capability может потребоваться выдать снова."
    fi
fi

echo "=== ThistleClient успешно установлен! ==="
echo "Для запуска трей-индикатора: thistle-client"
echo "Для открытия окна управления: thistle-client --gui"
