"""
AgentShield AI — Generate Application Icons.
"""

from __future__ import annotations

import os
from PIL import Image, ImageDraw


def generate_icons():
    os.makedirs("apps/desktop/assets", exist_ok=True)
    img = Image.new("RGBA", (256, 256), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Draw dark slate blue shield with cyan border
    shield_points = [
        (128, 20),
        (226, 50),
        (206, 170),
        (128, 236),
        (50, 170),
        (30, 50),
    ]
    draw.polygon(shield_points, fill=(24, 32, 54, 255), outline=(0, 200, 240, 255), width=6)

    # Inner accent: lock icon
    draw.ellipse([(110, 80), (146, 116)], outline=(0, 220, 255, 255), width=6)
    draw.rectangle([(98, 110), (158, 166)], fill=(0, 200, 240, 255))
    draw.ellipse([(122, 126), (134, 138)], fill=(24, 32, 54, 255))
    draw.rectangle([(126, 136), (130, 150)], fill=(24, 32, 54, 255))

    img.save("apps/desktop/assets/icon.png")
    img.save("apps/desktop/assets/icon.ico", format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
    print("Application icons generated in apps/desktop/assets/")


if __name__ == "__main__":
    generate_icons()
