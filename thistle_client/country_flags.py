"""Offline country badges: bundled SVG flags and ASCII codes, independent of emoji fonts."""
from functools import lru_cache
from pathlib import Path
import re
import xml.etree.ElementTree as ET

import gi
gi.require_version('Gtk', '3.0')
gi.require_version('GdkPixbuf', '2.0')
from gi.repository import Gtk, GdkPixbuf

FLAGS_DIR = Path(__file__).resolve().parent.parent / 'icons' / 'flags'
_FLAG = re.compile('[\U0001f1e6-\U0001f1ff]{2}\ufe0f?')
_SVG = 'http://www.w3.org/2000/svg'
ET.register_namespace('', _SVG)


def country_presentation(node):
    """Return presentation only; never rewrite the tag used by selectors and saved state."""
    tag = node.get('tag', '') if isinstance(node, dict) else node
    tag = str(tag or '')
    match = _FLAG.search(tag)
    code = ''
    if isinstance(node, dict):
        candidate = str(node.get('_country_code', node.get('country_code', ''))).upper()
        if re.fullmatch('[A-Z]{2}', candidate):
            code = candidate
    if match:
        code = code or ''.join(chr(ord(char)-0x1f1e6+ord('A')) for char in match.group()[:2])
        tag = (tag[:match.start()] + tag[match.end():]).strip()
        tag = re.sub(r'[ \t]{2,}', ' ', tag)
    return code, tag


def dark_badge(widget):
    color = widget.get_style_context().get_color(Gtk.StateFlags.NORMAL)
    return color.red + color.green + color.blue > 1.5


@lru_cache(maxsize=512)
def country_badge(code, dark=False):
    """Render once per country/theme; custom or missing flags still have a readable code."""
    code = str(code).upper()
    if not re.fullmatch('[A-Z]{2}', code):
        return None
    background, border, foreground = ('#26313f', '#4a596b', '#f2f5f8') if dark else ('#f0f3f7', '#cad3df', '#263445')
    svg = ET.Element(f'{{{_SVG}}}svg', {'width': '58', 'height': '24', 'viewBox': '0 0 58 24'})
    ET.SubElement(svg, f'{{{_SVG}}}rect', {'x': '.5', 'y': '.5', 'width': '57', 'height': '23',
                                        'rx': '5', 'fill': background, 'stroke': border})
    flag_path = FLAGS_DIR / (code.lower()+'.svg')
    has_flag = flag_path.is_file()
    if has_flag:
        defs = ET.SubElement(svg, f'{{{_SVG}}}defs')
        clip = ET.SubElement(defs, f'{{{_SVG}}}clipPath', {'id': 'thistleBadgeClip'})
        ET.SubElement(clip, f'{{{_SVG}}}rect', {'x': '4', 'y': '3', 'width': '24', 'height': '18', 'rx': '2'})
        group = ET.SubElement(svg, f'{{{_SVG}}}g', {'clip-path': 'url(#thistleBadgeClip)'})
        flag = ET.parse(flag_path).getroot()
        flag.attrib.update(x='4', y='3', width='24', height='18')
        group.append(flag)
        ET.SubElement(svg, f'{{{_SVG}}}rect', {'x': '4', 'y': '3', 'width': '24', 'height': '18', 'rx': '2',
                                            'fill': 'none', 'stroke': border, 'stroke-width': '.5'})
    text = ET.SubElement(svg, f'{{{_SVG}}}text', {'x': '33' if has_flag else '29', 'y': '16',
                                               'font-family': 'DejaVu Sans, sans-serif', 'font-size': '10',
                                               'font-weight': '700', 'fill': foreground,
                                               'text-anchor': 'start' if has_flag else 'middle'})
    text.text = code
    loader = GdkPixbuf.PixbufLoader.new_with_type('svg')
    loader.write(ET.tostring(svg, encoding='utf-8'))
    loader.close()
    return loader.get_pixbuf()


def server_menu_content(node, suffix='', widget=None):
    code, name = country_presentation(node)
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    if code:
        box.pack_start(Gtk.Image.new_from_pixbuf(country_badge(code, dark_badge(widget or box))), False, False, 0)
    label = Gtk.Label(label=name+suffix, xalign=0)
    box.pack_start(label, True, True, 0)
    box.set_tooltip_text(f'{code}: {name}' if code else name)
    box.show_all()
    return box
