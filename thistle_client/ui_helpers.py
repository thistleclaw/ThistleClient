"""Theme-aware symbolic icons shared by the GTK window, menus and settings."""
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk


def button_icon(button, name):
    button.set_image(Gtk.Image.new_from_icon_name(name, Gtk.IconSize.BUTTON))
    button.set_always_show_image(True)
    return button


def menu_item(label, icon):
    item = Gtk.MenuItem()
    item.add(icon_label(label, icon))
    return item


def icon_label(label, icon):
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    box.pack_start(Gtk.Image.new_from_icon_name(icon, Gtk.IconSize.MENU), False, False, 0)
    box.pack_start(Gtk.Label(label=label, xalign=0), True, True, 0)
    box.show_all()
    return box


def copy_subscription_url(data):
    url = data.get("subs", {}).get(data.get("active_sub"), {}).get("url", "")
    if not url:
        return False
    clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
    clipboard.set_text(url, -1)
    clipboard.store()
    return True
