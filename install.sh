#!/usr/bin/env bash
set -e

# ThistleClient Installation Script
REPO_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
TARGET_DIR="$HOME/.local/share/thistle-client"
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
SERVICE_DIR="$HOME/.config/systemd/user"

echo "=== Установка ThistleClient ==="

# 1. Check prerequisites
if ! command -v python3 >/dev/null 2>&1; then
    echo "Ошибка: python3 не найден. Установите python3."
    exit 1
fi

if ! command -v /usr/local/bin/sing-box >/dev/null 2>&1 && ! command -v sing-box >/dev/null 2>&1; then
    echo "Предупреждение: sing-box не найден в /usr/local/bin/sing-box."
fi

# 2. Prepare directories
mkdir -p "$TARGET_DIR" "$BIN_DIR" "$APP_DIR" "$SERVICE_DIR" "$TARGET_DIR/data" "$TARGET_DIR/icons"

# 3. Copy application files
cp -r "$REPO_DIR/thistle_client" "$TARGET_DIR/"
cp -r "$REPO_DIR/icons"/* "$TARGET_DIR/icons/"
cp "$REPO_DIR/thistle-client" "$TARGET_DIR/thistle-client"
chmod +x "$TARGET_DIR/thistle-client"

# 4. Link launcher
ln -sf "$TARGET_DIR/thistle-client" "$BIN_DIR/thistle-client"

# 5. Install desktop entry
cp "$REPO_DIR/thistle-client.desktop" "$APP_DIR/thistle-client.desktop"
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APP_DIR" 2>/dev/null || true
fi

# 6. Install systemd user service
cp "$REPO_DIR/thistle-client.service" "$SERVICE_DIR/thistle-client.service"
systemctl --user daemon-reload
systemctl --user enable thistle-client.service

echo "=== ThistleClient успешно установлен! ==="
echo "Для запуска трей-индикатора: thistle-client"
echo "Для открытия окна управления: thistle-client --gui"
