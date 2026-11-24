from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.generate_donate_qr import generate
from ui.about_view import donate_details
from ui.localization import LANGUAGES, Translator


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_ADDRESS = "2w9LCVJbNjuxcKieTPPbq1GhewxzXnSR5xh5KmGrB9YG"
DONATE_KEYS = (
    "donate_button",
    "donate_dialog_title",
    "donate_network_label",
    "donate_wallet_label",
    "donate_copy_button",
    "donate_copy_success",
    "donate_copy_failed",
    "donate_qr_note",
    "donate_qr_unavailable",
    "donate_optional_note",
    "donate_network_warning",
)


class DonateFeatureTests(unittest.TestCase):
    def test_wallet_configuration_is_exact(self) -> None:
        self.assertEqual(
            donate_details(),
            {"network": "Solana", "wallet_address": EXPECTED_ADDRESS},
        )

    def test_donate_strings_are_translated_in_every_locale(self) -> None:
        catalog = json.loads((ROOT / "i18n" / "translations.json").read_text(encoding="utf-8"))
        english_keys = set(catalog["en-US"])
        for language in LANGUAGES:
            with self.subTest(language=language):
                self.assertEqual(set(catalog[language]), english_keys)
                translator = Translator(language)
                for key in DONATE_KEYS:
                    self.assertTrue(translator.text(key))
                    self.assertNotEqual(translator.text(key), key)

    def test_generated_qr_is_a_png_asset(self) -> None:
        output = generate()
        self.assertEqual(output, ROOT / "assets" / "solana_donate_qr.png")
        self.assertTrue(output.is_file())
        self.assertTrue(output.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))


if __name__ == "__main__":
    unittest.main()
