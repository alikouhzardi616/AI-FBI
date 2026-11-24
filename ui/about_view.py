from __future__ import annotations

import json
from pathlib import Path

from core.paths import resource_path
from ui.localization import Translator


_CAPABILITY_GROUPS = (
    ("category_monitoring", ("capability_monitor", "capability_network", "capability_files")),
    ("category_scanning", ("capability_scanner",)),
    ("category_response", ("capability_quarantine", "capability_logs", "capability_reports")),
    ("category_integrity", ("capability_self",)),
)


def donate_details(config_path: Path | None = None) -> dict[str, str]:
    path = config_path or resource_path("config/donate.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Donation configuration must be a JSON object")
    network = data.get("network")
    address = data.get("wallet_address")
    if not isinstance(network, str) or not network.strip() or not isinstance(address, str) or not address.strip():
        raise ValueError(f"Donation configuration is incomplete: {path}")
    return {"network": network.strip(), "wallet_address": address.strip()}


def about_content(translator: Translator, metadata_path: Path | None = None) -> dict[str, object]:
    path = metadata_path or resource_path("app_metadata.json")
    metadata = json.loads(path.read_text(encoding="utf-8"))
    return {
        "name": metadata["name"],
        "version_label": translator.text("version"),
        "version": metadata["version"],
        "developer_label": translator.text("developer"),
        "developer": metadata["developer"],
        "capabilities_title": translator.text("capabilities_title"),
        "capabilities": [translator.text(key) for key in translator.capability_keys()],
        "disclaimer": translator.text("about_disclaimer"),
    }


def build_about(parent: tk.Misc, translator: Translator) -> tk.Frame:
    import tkinter as tk
    from ui.theme import COLORS, ShieldEmblem, card

    content = about_content(translator)
    rtl = translator.is_rtl
    anchor = "e" if rtl else "w"
    justify = "right" if rtl else "left"
    frame = tk.Frame(parent, bg=COLORS["background"], padx=20, pady=18)

    hero = card(frame, padding=18)
    hero.pack(fill="x", pady=(0, 16))
    hero.columnconfigure(1, weight=1)
    mark = ShieldEmblem(hero, size=72, background=COLORS["panel"])
    mark.grid(row=0, column=0 if not rtl else 2, rowspan=2, padx=(0, 16) if not rtl else (16, 0), sticky="n")
    title = tk.Label(
        hero,
        text=f"{content['name']}  ·  {content['version']}",
        bg=COLORS["panel"],
        fg=COLORS["text"],
        font=("Segoe UI", 22, "bold"),
        anchor=anchor,
    )
    title.grid(row=0, column=1, sticky="ew")
    tk.Label(
        hero,
        text=translator.text("about_tagline"),
        bg=COLORS["panel"],
        fg=COLORS["muted"],
        font=("Segoe UI", 10),
        anchor=anchor,
        justify=justify,
        wraplength=680,
    ).grid(row=1, column=1, sticky="ew", pady=(5, 12))

    identity = tk.Frame(hero, bg=COLORS["panel"])
    identity.grid(row=2, column=1, sticky="ew")
    tk.Label(
        identity,
        text=f"{content['developer_label']}  ·  {content['developer']}",
        bg=COLORS["panel_alt"],
        fg=COLORS["emerald"],
        font=("Segoe UI", 10, "bold"),
        padx=11,
        pady=7,
    ).pack(side="right" if rtl else "left")
    tk.Label(
        identity,
        text=f"{content['version_label']}  {content['version']}",
        bg=COLORS["panel_alt"],
        fg=COLORS["muted"],
        font=("Segoe UI", 9),
        padx=11,
        pady=7,
    ).pack(side="right" if rtl else "left", padx=(0, 8) if rtl else (8, 0))

    section_head = tk.Frame(frame, bg=COLORS["background"])
    section_head.pack(fill="x", pady=(0, 10))
    tk.Label(
        section_head,
        text=str(content["capabilities_title"]),
        bg=COLORS["background"],
        fg=COLORS["text"],
        font=("Segoe UI", 14, "bold"),
        anchor=anchor,
    ).pack(side="right" if rtl else "left")
    tk.Button(
        section_head,
        text=translator.text("donate_button"),
        command=lambda: _show_donate_dialog(frame, translator),
        bg="#173B31",
        fg=COLORS["emerald"],
        activebackground="#205441",
        activeforeground=COLORS["white"],
        relief="flat",
        bd=0,
        padx=12,
        pady=6,
        font=("Segoe UI", 9, "bold"),
        cursor="hand2",
        highlightthickness=0,
    ).pack(side="left" if rtl else "right")

    grid = tk.Frame(frame, bg=COLORS["background"])
    grid.pack(fill="both", expand=True)
    grid.columnconfigure(0, weight=1, uniform="capability")
    grid.columnconfigure(1, weight=1, uniform="capability")
    accent_colors = (COLORS["emerald"], COLORS["blue"], COLORS["amber"], COLORS["emerald"])
    for index, (category, keys) in enumerate(_CAPABILITY_GROUPS):
        tile = card(grid, padding=14)
        row, column = divmod(index, 2)
        tile.grid(row=row, column=column, sticky="nsew", padx=(0, 8) if column == 0 else (8, 0), pady=6)
        tk.Frame(tile, bg=accent_colors[index], height=3).pack(fill="x", pady=(0, 10))
        tk.Label(
            tile,
            text=translator.text(category),
            bg=COLORS["panel"],
            fg=accent_colors[index],
            font=("Segoe UI", 10, "bold"),
            anchor=anchor,
        ).pack(fill="x", pady=(0, 5))
        for key in keys:
            tk.Label(
                tile,
                text=f"•  {translator.text(key)}",
                bg=COLORS["panel"],
                fg=COLORS["muted"],
                font=("Segoe UI", 9),
                anchor=anchor,
                justify=justify,
                wraplength=440,
            ).pack(fill="x", pady=3)

    tk.Label(
        frame,
        text=str(content["disclaimer"]),
        bg=COLORS["background"],
        fg=COLORS["muted"],
        font=("Segoe UI", 8),
        anchor=anchor,
        justify=justify,
        wraplength=960,
    ).pack(fill="x", pady=(10, 0))
    frame.pack(fill="both", expand=True)
    return frame


def _show_donate_dialog(parent: tk.Misc, translator: Translator) -> None:
    import tkinter as tk
    from tkinter import messagebox

    from ui.theme import COLORS, card

    details = donate_details()
    dialog = tk.Toplevel(parent.winfo_toplevel())
    dialog.title(translator.text("donate_dialog_title"))
    dialog.configure(bg=COLORS["background"])
    dialog.geometry("440x660")
    dialog.resizable(False, False)
    dialog.transient(parent.winfo_toplevel())
    dialog.grab_set()

    rtl = translator.is_rtl
    anchor = "e" if rtl else "w"
    justify = "right" if rtl else "left"
    body = tk.Frame(dialog, bg=COLORS["background"], padx=18, pady=16)
    body.pack(fill="both", expand=True)
    tk.Label(
        body,
        text=translator.text("donate_dialog_title"),
        bg=COLORS["background"],
        fg=COLORS["text"],
        font=("Segoe UI", 17, "bold"),
        anchor=anchor,
    ).pack(fill="x", pady=(0, 12))

    detail_card = card(body, padding=12)
    detail_card.pack(fill="x", pady=(0, 10))
    tk.Label(
        detail_card,
        text=f"{translator.text('donate_network_label')}: {details['network']}",
        bg=COLORS["panel"],
        fg=COLORS["emerald"],
        font=("Segoe UI", 10, "bold"),
        anchor=anchor,
    ).pack(fill="x", pady=(0, 8))
    tk.Label(
        detail_card,
        text=translator.text("donate_wallet_label"),
        bg=COLORS["panel"],
        fg=COLORS["muted"],
        font=("Segoe UI", 8, "bold"),
        anchor=anchor,
    ).pack(fill="x")
    tk.Label(
        detail_card,
        text=details["wallet_address"],
        bg=COLORS["panel_alt"],
        fg=COLORS["text"],
        font=("Consolas", 9),
        justify=justify,
        anchor=anchor,
        wraplength=370,
        padx=8,
        pady=8,
    ).pack(fill="x", pady=(4, 8))

    copy_button = tk.Button(
        detail_card,
        text=translator.text("donate_copy_button"),
        bg="#173B31",
        fg=COLORS["emerald"],
        activebackground="#205441",
        activeforeground=COLORS["white"],
        relief="flat",
        bd=0,
        padx=12,
        pady=7,
        font=("Segoe UI", 9, "bold"),
        cursor="hand2",
        highlightthickness=0,
    )
    copy_button.pack(anchor="e" if not rtl else "w")

    def copy_address() -> None:
        try:
            dialog.clipboard_clear()
            dialog.clipboard_append(details["wallet_address"])
            dialog.update_idletasks()
        except tk.TclError:
            messagebox.showerror(
                translator.text("donate_dialog_title"),
                translator.text("donate_copy_failed"),
                parent=dialog,
            )
            return
        copy_button.configure(text=translator.text("donate_copy_success"))
        dialog.after(1800, lambda: copy_button.configure(text=translator.text("donate_copy_button")))

    copy_button.configure(command=copy_address)

    qr_card = card(body, padding=10)
    qr_card.pack(fill="x", pady=(0, 10))
    qr_path = resource_path("assets/solana_donate_qr.png")
    if qr_path.is_file():
        try:
            qr_image = tk.PhotoImage(file=str(qr_path)).subsample(2, 2)
        except tk.TclError:
            qr_image = None
    else:
        qr_image = None
    if qr_image is not None:
        qr_label = tk.Label(qr_card, image=qr_image, bg=COLORS["panel"])
        qr_label.image = qr_image
        qr_label.pack(pady=(0, 5))
        qr_note = translator.text("donate_qr_note")
    else:
        qr_note = translator.text("donate_qr_unavailable")
    tk.Label(
        qr_card,
        text=qr_note,
        bg=COLORS["panel"],
        fg=COLORS["muted"],
        font=("Segoe UI", 8),
        anchor="center",
        justify="center",
        wraplength=370,
    ).pack(fill="x")

    warning_card = card(body, padding=11)
    warning_card.pack(fill="x", pady=(0, 8))
    for key in ("donate_optional_note", "donate_network_warning"):
        tk.Label(
            warning_card,
            text=translator.text(key),
            bg=COLORS["panel"],
            fg=COLORS["amber"] if key == "donate_network_warning" else COLORS["text"],
            font=("Segoe UI", 9, "bold" if key == "donate_network_warning" else "normal"),
            anchor=anchor,
            justify=justify,
            wraplength=380,
        ).pack(fill="x", pady=3)
