"""Country badges must render offline without changing server identities."""
from pathlib import Path
import unittest
from unittest.mock import Mock
import xml.etree.ElementTree as ET

from thistle_client.country_flags import FLAGS_DIR, country_presentation, country_badge, server_menu_content
from thistle_client.manager_gui import ThistleManagerWindow


class CountryBadgeTests(unittest.TestCase):
    def test_flag_becomes_country_code_and_clean_display_only(self):
        node = {'tag': '🇩🇪 Германия · Франкфурт', 'type': 'vless'}
        self.assertEqual(country_presentation(node), ('DE', 'Германия · Франкфурт'))
        self.assertEqual(node['tag'], '🇩🇪 Германия · Франкфурт')
        self.assertEqual(country_presentation('🇪🇺\ufe0f Europe'), ('EU', 'Europe'))
        self.assertEqual(country_presentation({'tag': 'Server', '_country_code': 'nl'}), ('NL', 'Server'))
        self.assertEqual(country_presentation('Автовыбор'), ('', 'Автовыбор'))

    def test_badge_is_cached_and_supports_light_dark_and_unknown_country(self):
        light = country_badge('RU', False)
        dark = country_badge('RU', True)
        self.assertEqual((light.get_width(), light.get_height()), (58, 24))
        self.assertIs(light, country_badge('RU', False))
        self.assertNotEqual(bytes(light.get_pixels()), bytes(dark.get_pixels()))
        self.assertIsNotNone(country_badge('ZZ'))
        self.assertIsNone(country_badge('../ru'))
        self.assertIsNone(country_badge(''))

    def test_every_bundled_flag_renders_and_has_no_external_resources(self):
        assets = list(FLAGS_DIR.glob('*.svg'))
        self.assertGreaterEqual(len(assets), 250)
        self.assertTrue((FLAGS_DIR/'LICENSE').is_file())
        for asset in assets:
            with self.subTest(country=asset.stem):
                self.assertIsNotNone(country_badge(asset.stem.upper()))
                for element in ET.parse(asset).iter():
                    self.assertNotIn(element.tag.rsplit('}', 1)[-1], ('script', 'foreignObject', 'image'))
                    for name, value in element.attrib.items():
                        if name.rsplit('}', 1)[-1] == 'href':
                            self.assertTrue(value.startswith('#'))

    def window(self):
        window = ThistleManagerWindow()
        window.data = {'subs': {'feed': {'nodes': [
            {'tag': '🇳🇱 Amsterdam', 'type': 'vless', 'server': '203.0.113.8', 'server_port': 443},
            {'tag': 'Автовыбор', 'type': 'vless', 'server': '203.0.113.9', 'server_port': 443},
        ]}}, 'active_sub': 'feed', 'active_node': '🇳🇱 Amsterdam'}
        window.update_server_list()
        return window

    def test_list_preserves_raw_tag_and_separates_artwork_from_text(self):
        window = self.window()
        try:
            row = window.model_servers[0]
            self.assertEqual(row[0], '● Amsterdam')
            self.assertEqual(row[5], '🇳🇱 Amsterdam')
            self.assertEqual(row[8], 'NL')
            self.assertIsNotNone(row[6])
            self.assertIsNone(window.model_servers[1][6])
            self.assertEqual(window.tree_servers.get_columns()[0].get_sort_column_id(), 8)
        finally:
            window.destroy()

    def test_selecting_badge_row_uses_original_tag_for_connection(self):
        window = self.window()
        try:
            window.core = Mock()
            window.core.is_running.return_value = True
            window.core.switch_node.return_value = True
            window.save_data = Mock()
            window.sync_config = Mock()
            window.tree_servers.get_selection().select_path(0)
            window.activate_selected_server()
            self.assertEqual(window.data['active_node'], '🇳🇱 Amsterdam')
            self.assertEqual(window.core.switch_node.call_args.args[0]['tag'], '🇳🇱 Amsterdam')
        finally:
            window.destroy()

    def test_tray_entry_has_image_and_readable_label(self):
        box = server_menu_content({'tag': '🇺🇸 New York'}, ' (48 ms)')
        try:
            image, label = box.get_children()
            self.assertIsNotNone(image.get_pixbuf())
            self.assertEqual(label.get_text(), 'New York (48 ms)')
            self.assertEqual(box.get_tooltip_text(), 'US: New York')
        finally:
            box.destroy()
