from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "assets"
SIZE = 512
BACKGROUND = "#0B0F17"
PANEL = "#131A26"
BORDER = "#223047"
EMERALD = "#10B981"
GOLD = "#E79E29"
WHITE = "#E7EDF5"


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = (
        ("C:/Windows/Fonts/segoeuib.ttf", "C:/Windows/Fonts/arialbd.ttf")
        if bold else ("C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/arial.ttf")
    )
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            continue
    return ImageFont.load_default()


def generate() -> tuple[Path, Path]:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    image = Image.new("RGBA", (SIZE, SIZE), BACKGROUND)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((24, 24, 488, 488), radius=96, fill=PANEL, outline=BORDER, width=8)
    shield = [(256, 58), (418, 120), (405, 286), (360, 370), (256, 454), (152, 370), (107, 286), (94, 120)]
    draw.polygon(shield, fill="#10271F", outline=GOLD)
    draw.line(shield + [shield[0]], fill=GOLD, width=12, joint="curve")
    inner = [(256, 86), (390, 137), (379, 279), (341, 343), (256, 411), (171, 343), (133, 279), (122, 137)]
    draw.line(inner + [inner[0]], fill=EMERALD, width=7, joint="curve")
    draw.line([(181, 249), (231, 299), (331, 191)], fill=WHITE, width=23, joint="curve")
    draw.text((256, 371), "AI FBI", font=_font(45, bold=True), fill=GOLD, anchor="mm", stroke_width=2, stroke_fill=BACKGROUND)

    png_path = OUTPUT / "ai_fbi.png"
    ico_path = OUTPUT / "ai_fbi.ico"
    image.save(png_path, format="PNG", optimize=True)
    image.save(ico_path, format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    return png_path, ico_path


if __name__ == "__main__":
    png, ico = generate()
    print(f"Generated {png} and {ico}")
