#!/usr/bin/env bash
set -e

echo "=== Удаление ThistleClient ==="

systemctl --user stop thistle-client.service 2>/dev/null || true
systemctl --user disable thistle-client.service 2>/dev/null || true
rm -f "$HOME/.config/systemd/user/thistle-client.service"
systemctl --user daemon-reload 2>/dev/null || true

rm -f "$HOME/.local/bin/thistle-client"
rm -f "$HOME/.local/share/applications/thistle-client.desktop"
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
fi

echo "Файлы приложения удалены. Данные подписок и настроек сохранены в ~/.local/share/thistle-client и ~/.config/thistle-client."
echo "Для полной очистки удалите их вручную:"
echo "rm -rf ~/.local/share/thistle-client ~/.config/thistle-client"
