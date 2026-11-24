from __future__ import annotations

import json
from pathlib import Path

import qrcode
from qrcode.constants import ERROR_CORRECT_H


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "donate.json"
OUTPUT_PATH = ROOT / "assets" / "solana_donate_qr.png"


def generate() -> Path:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("Donation configuration must be a JSON object")
    network = config.get("network")
    address = config.get("wallet_address")
    if network != "Solana" or not isinstance(address, str) or not address.strip():
        raise ValueError("Donation configuration must contain a Solana network and wallet address")

    code = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_H,
        box_size=8,
        border=4,
    )
    code.add_data(address.strip())
    code.make(fit=True)
    image = code.make_image(fill_color="#101820", back_color="white").convert("RGB")
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT_PATH, format="PNG", optimize=True)
    return OUTPUT_PATH


if __name__ == "__main__":
    print(f"Generated {generate()}")
