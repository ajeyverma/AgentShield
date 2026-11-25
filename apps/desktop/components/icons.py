"""
AgentShield AI — Vector SVG Icon Provider.
Provides crisp, modern vector icons for UI buttons, badges, and headers without relying on emojis.
"""

from __future__ import annotations

from PySide6.QtCore import QByteArray, QSize
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

# SVG Definitions (24x24 viewBox, stroke-based)
SVG_ICONS = {
    "agent": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="11" width="18" height="10" rx="3"/>
        <circle cx="12" cy="5" r="2"/>
        <path d="M12 7v4"/>
        <line x1="8" y1="15" x2="8.01" y2="15" stroke-width="3"/>
        <line x1="16" y1="15" x2="16.01" y2="15" stroke-width="3"/>
        <path d="M9 19h6"/>
    </svg>""",

    "trash": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="3 6 5 6 21 6"/>
        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
        <line x1="10" y1="11" x2="10" y2="17"/>
        <line x1="14" y1="11" x2="14" y2="17"/>
    </svg>""",

    "refresh": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
    </svg>""",

    "check": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="20 6 9 17 4 12"/>
    </svg>""",

    "cross": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <line x1="18" y1="6" x2="6" y2="18"/>
        <line x1="6" y1="6" x2="18" y2="18"/>
    </svg>""",

    "play": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="{color}" stroke="{color}" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
        <polygon points="5 3 19 12 5 21 5 3"/>
    </svg>""",

    "pause": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="{color}" stroke="{color}" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
        <rect x="6" y="4" width="4" height="16"/>
        <rect x="14" y="4" width="4" height="16"/>
    </svg>""",

    "shield": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>""",

    "alert": """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>""",
}


def get_pixmap(name: str, size: int = 24, color: str = "#2563EB") -> QPixmap:
    """Render an SVG vector icon to a transparent QPixmap."""
    svg_template = SVG_ICONS.get(name)
    if not svg_template:
        pix = QPixmap(size, size)
        pix.fill(QColor(0, 0, 0, 0))
        return pix

    svg_content = svg_template.format(color=color)
    renderer = QSvgRenderer(QByteArray(svg_content.encode("utf-8")))

    pix = QPixmap(size, size)
    pix.fill(QColor(0, 0, 0, 0))

    painter = QPainter(pix)
    renderer.render(painter)
    painter.end()
    return pix


def get_icon(name: str, size: int = 20, color: str = "#2563EB") -> QIcon:
    """Return a QIcon for use with QPushButton.setIcon()."""
    pix = get_pixmap(name, size=size, color=color)
    return QIcon(pix)
