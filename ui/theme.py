from __future__ import annotations

import tkinter as tk
from tkinter import ttk


COLORS = {
    "background": "#0B0F17",
    "panel": "#131A26",
    "panel_alt": "#182232",
    "border": "#223047",
    "text": "#E7EDF5",
    "muted": "#91A0B4",
    "emerald": "#10B981",
    "emerald_dark": "#0B7657",
    "amber": "#E79E29",
    "crimson": "#EF4444",
    "blue": "#4389F5",
    "white": "#FFFFFF",
}


def configure_ttk(root: tk.Misc) -> None:
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    style.configure(
        "AI.Treeview",
        background=COLORS["panel"],
        foreground=COLORS["text"],
        fieldbackground=COLORS["panel"],
        bordercolor=COLORS["border"],
        rowheight=36,
        font=("Segoe UI", 9),
    )
    style.configure(
        "AI.Treeview.Heading",
        background=COLORS["panel_alt"],
        foreground=COLORS["muted"],
        bordercolor=COLORS["border"],
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padding=(9, 8),
    )
    style.map(
        "AI.Treeview",
        background=[("selected", "#164A3A")],
        foreground=[("selected", COLORS["white"])],
    )
    style.configure(
        "AI.Vertical.TScrollbar",
        background=COLORS["panel_alt"],
        troughcolor=COLORS["background"],
        bordercolor=COLORS["background"],
        arrowcolor=COLORS["muted"],
    )


def card(parent: tk.Misc, *, padding: int = 16, background: str | None = None) -> tk.Frame:
    color = background or COLORS["panel"]
    return tk.Frame(
        parent,
        bg=color,
        padx=padding,
        pady=padding,
        highlightbackground=COLORS["border"],
        highlightthickness=1,
        bd=0,
    )


class ShieldEmblem(tk.Canvas):
    def __init__(
        self,
        parent: tk.Misc,
        size: int = 52,
        *,
        background: str = COLORS["background"],
        accent: str = COLORS["emerald"],
    ) -> None:
        super().__init__(
            parent,
            width=size,
            height=size,
            bg=background,
            highlightthickness=0,
            bd=0,
        )
        self.size = size
        self.accent = accent
        self._draw()

    def _draw(self) -> None:
        size = self.size
        self.create_polygon(
            size * .5, size * .07,
            size * .87, size * .2,
            size * .83, size * .57,
            size * .68, size * .79,
            size * .5, size * .93,
            size * .32, size * .79,
            size * .17, size * .57,
            size * .13, size * .2,
            fill="#10271F",
            outline=self.accent,
            width=max(2, round(size / 25)),
            smooth=True,
        )
        self.create_line(
            size * .31, size * .5,
            size * .45, size * .64,
            size * .7, size * .37,
            fill=self.accent,
            width=max(2, round(size / 18)),
            capstyle=tk.ROUND,
            joinstyle=tk.ROUND,
        )
