from __future__ import annotations

import hashlib
import json
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    DND_FILES = None
    _TkBase = tk.Tk
else:
    _TkBase = TkinterDnD.Tk

from core.file_guard import FileGuard
from core.licensing import LicenseManager
from core.network_guard import NetworkGuard
from core.paths import ensure_data_directories, resource_path
from core.policy_engine import PolicyEngine
from core.process_monitor import ProcessMonitor
from core.quarantine import Quarantine
from core.report_exporter import SecurityReportExporter
from core.scanner import PROFILE_LABEL_KEYS, Finding, Scanner
from core.scheduled_scanner import ScheduledScanner
from core.self_protection import SelfProtection
from ui.about_view import build_about
from ui.localization import LANGUAGES, Translator
from ui.theme import COLORS, ShieldEmblem, card, configure_ttk


_NAV_ITEMS = ("dashboard", "scanner", "nav_threat_logs", "nav_quarantine", "about")
_PAGE_BY_NAV = {
    "dashboard": "dashboard",
    "scanner": "scanner",
    "nav_threat_logs": "threat_logs",
    "nav_quarantine": "quarantine",
    "about": "about",
}


class AIFBIApp(_TkBase):
    def __init__(self) -> None:
        super().__init__()
        self.data_dirs = ensure_data_directories()
        self.policy = PolicyEngine(self.data_dirs["root"])
        settings = self.policy.get_settings()
        self.translator = Translator(str(settings.get("language", "en-US")))
        self.quarantine = Quarantine(self.data_dirs["quarantine"], self.policy)
        self.license_manager = LicenseManager(self.data_dirs["root"], self.policy)
        self.report_exporter = SecurityReportExporter(
            self.policy,
            self.quarantine,
            self.license_manager.status(),
        )
        self.scheduled_scanner = ScheduledScanner(self.policy)
        self.scanner = Scanner(self.policy.get_custom_rules())
        if self.policy.get_security_profile() == "strict_lockdown" and not self.license_manager.is_pro():
            self.policy.set_security_profile("balanced_guard")
            self.policy.audit("security_profile_downgraded", reason="pro_license_required")
        self.process_monitor = ProcessMonitor(self.policy, self._monitor_callback)
        self.network_guard = NetworkGuard(self.policy, self._monitor_callback)
        self.file_guard = FileGuard(self.policy)
        self.self_protection = SelfProtection(self.data_dirs["root"], self.policy)
        for warning in self.self_protection.verify_startup():
            self.policy.audit("self_protection_warning", warning=warning)

        self.title("AI FBI")
        if sys.platform == "win32":
            try:
                self.iconbitmap(str(resource_path("assets/ai_fbi.ico")))
            except tk.TclError as exc:
                self.policy.audit("window_icon_unavailable", error=str(exc))
        self.geometry("1280x820")
        self.minsize(1000, 680)
        self.configure(bg=COLORS["background"])
        self.protocol("WM_DELETE_WINDOW", self._close)
        self._dnd_available = False
        if DND_FILES:
            try:
                self.drop_target_register(DND_FILES)
                self.dnd_bind("<<Drop>>", self._handle_drop)
                self._dnd_available = True
            except tk.TclError as exc:
                self.policy.audit("drag_drop_unavailable", error=str(exc))
        self.tray_icon: Any = None
        self.findings: list[Finding] = []
        self._finding_identities: list[str] = []
        self._selected_finding: Finding | None = None
        self._selected_identity: str | None = None
        self._scan_mode = "file"
        self._scan_running = False
        self._scan_source: Path | None = None
        self._scan_after_id: str | None = None
        self._metric_after_id: str | None = None
        self._pending_scan_results: tuple[list[Finding], str | None, str, str | None] | None = None
        self._closed = False
        self.current_page = "dashboard"
        configure_ttk(self)
        self._build_shell()
        self._start_tray()
        self._apply_mode(str(settings.get("shield_mode", "active")))
        scheduled = settings.get("scheduled_scan", {})
        if isinstance(scheduled, dict) and scheduled.get("enabled") and self.license_manager.is_pro():
            try:
                self.scheduled_scanner.start(scheduled.get("target", ""), int(scheduled.get("interval_hours", 24)))
            except (OSError, ValueError, TypeError) as exc:
                self.policy.audit("scheduled_scan_failed_to_start", error=str(exc))

    def _build_shell(self) -> None:
        self.header = tk.Frame(self, bg=COLORS["panel"], height=68, highlightbackground=COLORS["border"], highlightthickness=1)
        self.header.pack(fill="x")
        self.header.pack_propagate(False)
        self.header_title = tk.Label(
            self.header,
            text="AI FBI",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=("Segoe UI", 13, "bold"),
        )
        self.header_title.pack(side="left", padx=(22, 8))
        self.header_subtitle = tk.Label(
            self.header,
            text=self.translator.text("product_subtitle"),
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=("Segoe UI", 8, "bold"),
        )
        self.header_subtitle.pack(side="left", padx=(0, 12))

        self.language_var = tk.StringVar(value=self.translator.language_label(self.translator.language))
        self.language_menu = tk.OptionMenu(
            self.header,
            self.language_var,
            *[self.translator.language_label(code) for code in LANGUAGES],
            command=self._language_changed,
        )
        self.language_menu.configure(
            bg="#173B31",
            fg=COLORS["emerald"],
            activebackground="#205441",
            activeforeground=COLORS["white"],
            highlightthickness=0,
            relief="flat",
            bd=0,
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=6,
            cursor="hand2",
        )
        self.language_menu["menu"].configure(
            bg=COLORS["panel"],
            fg=COLORS["text"],
            activebackground="#173B31",
            activeforeground=COLORS["emerald"],
            font=("Segoe UI", 9),
            bd=0,
        )
        self.language_menu.pack(side="right", padx=22, pady=12)
        self.language_caption = tk.Label(
            self.header,
            text=self.translator.text("language").upper(),
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=("Segoe UI", 8, "bold"),
        )
        self.language_caption.pack(side="right", padx=(0, 10))
        self.body = tk.Frame(self, bg=COLORS["background"])
        self.body.pack(fill="both", expand=True)
        self._render_navigation()

    def _render_navigation(self) -> None:
        for name in ("sidebar", "page_host"):
            previous = getattr(self, name, None)
            if previous is not None and previous.winfo_exists():
                previous.destroy()
        rtl = self.translator.is_rtl
        side = "right" if rtl else "left"
        self.sidebar = tk.Frame(
            self.body,
            bg=COLORS["panel"],
            width=224,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        self.sidebar.pack(side=side, fill="y")
        self.sidebar.pack_propagate(False)
        emblem_row = tk.Frame(self.sidebar, bg=COLORS["panel"], padx=17, pady=22)
        emblem_row.pack(fill="x")
        ShieldEmblem(emblem_row, size=48, background=COLORS["panel"]).pack(side=side)
        name_col = tk.Frame(emblem_row, bg=COLORS["panel"])
        name_col.pack(side=side, padx=10, fill="x", expand=True)
        tk.Label(name_col, text="AI FBI", bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 13, "bold"), anchor="e" if rtl else "w").pack(fill="x")
        tk.Label(name_col, text=self.translator.text("brand_caption"), bg=COLORS["panel"], fg=COLORS["emerald"], font=("Segoe UI", 7, "bold"), anchor="e" if rtl else "w").pack(fill="x", pady=(3, 0))

        tk.Frame(self.sidebar, bg=COLORS["border"], height=1).pack(fill="x", padx=14, pady=(0, 14))
        self.nav_buttons: dict[str, tk.Button] = {}
        anchor = "e" if rtl else "w"
        for key in _NAV_ITEMS:
            page = _PAGE_BY_NAV[key]
            active = page == self.current_page
            button = tk.Button(
                self.sidebar,
                text=f"  {self.translator.text(key)}",
                command=lambda selected=page: self._show_page(selected),
                anchor=anchor,
                justify="right" if rtl else "left",
                bg="#173B31" if active else COLORS["panel"],
                fg=COLORS["emerald"] if active else COLORS["muted"],
                activebackground="#173B31",
                activeforeground=COLORS["emerald"],
                relief="flat",
                bd=0,
                padx=13,
                pady=12,
                font=("Segoe UI", 10, "bold" if active else "normal"),
                cursor="hand2",
                highlightthickness=0,
            )
            button.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[page] = button

        self.sidebar_status = tk.Frame(self.sidebar, bg="#10271F", padx=12, pady=12)
        self.sidebar_status.pack(side="bottom", fill="x", padx=12, pady=14)
        self.sidebar_dot = tk.Label(self.sidebar_status, text="●", bg="#10271F", fg=COLORS["emerald"], font=("Segoe UI", 9))
        self.sidebar_dot.pack(side=side)
        self.sidebar_status_label = tk.Label(
            self.sidebar_status,
            text="",
            bg="#10271F",
            fg=COLORS["emerald"],
            font=("Segoe UI", 9, "bold"),
            anchor=anchor,
        )
        self.sidebar_status_label.pack(side=side, padx=7)
        self._update_sidebar_status()
        self.page_host = tk.Frame(self.body, bg=COLORS["background"])
        self.page_host.pack(side="left" if rtl else "right", fill="both", expand=True)
        self._show_page(self.current_page, update_navigation=False)

    def _show_page(self, page: str, *, update_navigation: bool = True) -> None:
        self.current_page = page
        if self._scan_after_id and page != "scanner":
            self.after_cancel(self._scan_after_id)
            self._scan_after_id = None
        if self._metric_after_id:
            self.after_cancel(self._metric_after_id)
            self._metric_after_id = None
        if update_navigation and hasattr(self, "nav_buttons"):
            for name, button in self.nav_buttons.items():
                active = name == page
                button.configure(
                    bg="#173B31" if active else COLORS["panel"],
                    fg=COLORS["emerald"] if active else COLORS["muted"],
                    font=("Segoe UI", 10, "bold" if active else "normal"),
                )
        for child in self.page_host.winfo_children():
            child.destroy()
        builders: dict[str, Callable[[], None]] = {
            "dashboard": self._render_dashboard,
            "scanner": self._render_scanner,
            "threat_logs": self._render_threat_logs,
            "quarantine": self._render_quarantine,
            "about": self._render_about,
        }
        builders.get(page, self._render_dashboard)()

    def _language_changed(self, label: str) -> None:
        self.translator.set_language(self.translator.language_code(label))
        self.policy.update_setting("language", self.translator.language)
        if self._metric_after_id:
            self.after_cancel(self._metric_after_id)
            self._metric_after_id = None
        self.header_subtitle.configure(text=self.translator.text("product_subtitle"))
        self.language_caption.configure(text=self.translator.text("language").upper())
        self._render_navigation()
        self._update_tray_menu()

    def _handle_drop(self, event: Any) -> str:
        if self._scan_running:
            return "break"
        try:
            dropped = self.tk.splitlist(event.data)
        except tk.TclError:
            dropped = ()
        if not dropped:
            messagebox.showinfo(self.translator.text("scanner"), self.translator.text("drop_invalid"))
            return "break"
        candidate = Path(dropped[0]).expanduser()
        if not candidate.is_file() and not candidate.is_dir():
            messagebox.showinfo(self.translator.text("scanner"), self.translator.text("drop_invalid"))
            return "break"
        self._scan_mode = "folder" if candidate.is_dir() else "file"
        self._scan_source = candidate
        self._show_page("scanner")
        self.scan_source_label.configure(text=str(candidate), fg=COLORS["emerald"])
        self.scan_status.configure(text=self.translator.text("drop_ready"), fg=COLORS["emerald"])
        return "break"

    def _page_frame(self) -> tk.Frame:
        return tk.Frame(self.page_host, bg=COLORS["background"], padx=24, pady=22)

    def _page_heading(self, parent: tk.Misc, title: str, subtitle: str | None = None) -> None:
        anchor = "e" if self.translator.is_rtl else "w"
        tk.Label(parent, text=title, bg=COLORS["background"], fg=COLORS["text"], font=("Segoe UI", 20, "bold"), anchor=anchor).pack(fill="x")
        if subtitle:
            tk.Label(
                parent,
                text=subtitle,
                bg=COLORS["background"],
                fg=COLORS["muted"],
                font=("Segoe UI", 9),
                anchor=anchor,
                justify="right" if self.translator.is_rtl else "left",
                wraplength=900,
            ).pack(fill="x", pady=(5, 16))
        else:
            tk.Frame(parent, bg=COLORS["background"], height=16).pack()

    def _button(self, parent: tk.Misc, text: str, command: Callable[[], None], kind: str = "secondary") -> tk.Button:
        colors = {
            "primary": (COLORS["emerald"], "#04271D", "#34D399"),
            "danger": ("#4A2026", "#FFB4B4", "#67252C"),
            "warning": ("#3B2E19", "#F5C466", "#51401F"),
            "secondary": (COLORS["panel_alt"], COLORS["text"], "#223148"),
        }
        background, foreground, hover = colors[kind]
        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=background,
            fg=foreground,
            activebackground=hover,
            activeforeground=foreground,
            relief="flat",
            bd=0,
            padx=14,
            pady=9,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
            highlightthickness=0,
        )
        button.bind("<Enter>", lambda _event: button.configure(bg=hover))
        button.bind("<Leave>", lambda _event: button.configure(bg=background))
        return button

    def _apply_mode(self, mode: str) -> None:
        if mode not in {"active", "strict", "paused"}:
            mode = "active"
        self.mode_var.set(mode) if hasattr(self, "mode_var") else None
        self.policy.update_setting("shield_mode", mode)
        if mode == "paused":
            self.process_monitor.stop()
            self.network_guard.stop()
            self.file_guard.stop()
        else:
            self.process_monitor.start()
            self.network_guard.start()
            folders = self.policy.get_settings().get("protected_folders", [])
            self.file_guard.stop()
            self.file_guard.start(folders if isinstance(folders, list) else [])
        self.policy.audit("shield_mode_changed", mode=mode)
        if hasattr(self, "sidebar_status_label"):
            self._update_sidebar_status()
        if self.current_page == "dashboard" and hasattr(self, "page_host") and self.page_host.winfo_children():
            if hasattr(self, "protection_status"):
                self.protection_status.configure(text=self._status_text(mode), fg=self._mode_color(mode))
                self._style_mode_buttons()

    def _status_text(self, mode: str) -> str:
        key = {"active": "active_status", "strict": "strict_status", "paused": "paused_status"}.get(mode, "ready")
        return self.translator.text(key)

    def _mode_color(self, mode: str) -> str:
        return COLORS["muted"] if mode == "paused" else COLORS["amber"] if mode == "strict" else COLORS["emerald"]

    def _update_sidebar_status(self) -> None:
        mode = str(self.policy.get_settings().get("shield_mode", "active"))
        self.sidebar_status_label.configure(text=self._status_text(mode), fg=self._mode_color(mode))
        self.sidebar_dot.configure(fg=self._mode_color(mode))

    def _render_dashboard(self) -> None:
        t = self.translator.text
        rtl = self.translator.is_rtl
        anchor = "e" if rtl else "w"
        page = self._page_frame()
        page.pack(fill="both", expand=True)
        self._page_heading(page, t("dashboard"), t("system_overview"))
        self.metric_values = {}

        banner = card(page, padding=18)
        banner.pack(fill="x", pady=(0, 14))
        banner.configure(highlightbackground="#1D4D3D")
        side = "right" if rtl else "left"
        ShieldEmblem(banner, size=62, background=COLORS["panel"]).pack(side=side, padx=(0, 15) if not rtl else (15, 0))
        banner_copy = tk.Frame(banner, bg=COLORS["panel"])
        banner_copy.pack(side=side, fill="x", expand=True)
        tk.Label(banner_copy, text=t("live_protection"), bg=COLORS["panel"], fg=COLORS["emerald"], font=("Segoe UI", 9, "bold"), anchor=anchor).pack(fill="x")
        self.protection_status = tk.Label(
            banner_copy,
            text=self._status_text(str(self.policy.get_settings().get("shield_mode", "active"))),
            bg=COLORS["panel"],
            fg=self._mode_color(str(self.policy.get_settings().get("shield_mode", "active"))),
            font=("Segoe UI", 14, "bold"),
            anchor=anchor,
        )
        self.protection_status.pack(fill="x", pady=(4, 2))
        tk.Label(banner_copy, text=t("protection_desc"), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 9), anchor=anchor).pack(fill="x")
        controls = tk.Frame(banner, bg=COLORS["panel"])
        controls.pack(side="left" if rtl else "right", padx=(14, 0) if not rtl else (0, 14))
        self.mode_var = tk.StringVar(value=self.policy.get_settings().get("shield_mode", "active"))
        self.mode_buttons: dict[str, tk.Button] = {}
        for mode, key in (("active", "active"), ("strict", "strict_lockdown"), ("paused", "paused")):
            button = tk.Button(
                controls,
                text=t(key),
                command=lambda selected=mode: self._apply_mode(selected),
                relief="flat",
                bd=0,
                padx=11,
                pady=9,
                cursor="hand2",
                font=("Segoe UI", 8, "bold"),
                highlightthickness=0,
            )
            button.pack(side="left", padx=2)
            self.mode_buttons[mode] = button
        self._style_mode_buttons()

        metrics = tk.Frame(page, bg=COLORS["background"])
        metrics.pack(fill="x", pady=(0, 14))
        for index in range(4):
            metrics.columnconfigure(index, weight=1, uniform="metric")
        self.metric_values: dict[str, tk.Label] = {}
        metric_keys = (
            ("metric_processes", "processes", COLORS["emerald"]),
            ("metric_paths", "paths", COLORS["blue"]),
            ("metric_blocked", "blocked", COLORS["amber"]),
            ("metric_quarantine", "quarantine", COLORS["crimson"]),
        )
        for index, (label_key, metric, accent) in enumerate(metric_keys):
            tile = card(metrics, padding=14)
            tile.grid(row=0, column=index, sticky="nsew", padx=(0, 8) if index < 3 else (0, 0))
            tk.Frame(tile, bg=accent, height=3).pack(fill="x", pady=(0, 12))
            tk.Label(tile, text=t(label_key), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8, "bold"), anchor=anchor).pack(fill="x")
            value = tk.Label(tile, text="—", bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 23, "bold"), anchor=anchor)
            value.pack(fill="x", pady=(5, 0))
            self.metric_values[metric] = value
        self._refresh_dashboard_metrics(schedule=False)

        status_row = tk.Frame(page, bg=COLORS["background"])
        status_row.pack(fill="x", pady=(0, 14))
        sensor_card = card(status_row, padding=15)
        sensor_card.pack(side="left" if not rtl else "right", fill="both", expand=True, padx=(0, 7) if not rtl else (7, 0))
        tk.Label(sensor_card, text=t("sensor_status"), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8, "bold"), anchor=anchor).pack(fill="x", pady=(0, 8))
        self._sensor_row(sensor_card, t("monitor_processes"), self.process_monitor.available, anchor)
        self._sensor_row(sensor_card, t("monitor_network"), self.network_guard.available, anchor)
        self._sensor_row(sensor_card, t("monitor_files"), self.file_guard.available, anchor)
        settings_card = card(status_row, padding=15)
        settings_card.pack(side="right" if not rtl else "left", fill="both", expand=True, padx=(7, 0) if not rtl else (0, 7))
        tk.Label(settings_card, text=t("settings_title"), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8, "bold"), anchor=anchor).pack(fill="x", pady=(0, 8))
        self._render_settings(settings_card)

        if self._scan_after_id:
            self.after_cancel(self._scan_after_id)
        if self._pending_scan_results:
            pending = self._pending_scan_results
            self._pending_scan_results = None
            self.after(10, lambda: self._finish_scan(*pending))
        self._metric_after_id = self.after(10000, self._refresh_dashboard_metrics)

    def _sensor_row(self, parent: tk.Misc, label: str, available: bool, anchor: str) -> None:
        row = tk.Frame(parent, bg=COLORS["panel"])
        row.pack(fill="x", pady=4)
        status = self.translator.text("active") if available else self.translator.text("not_available")
        color = COLORS["emerald"] if available else COLORS["amber"]
        side = "right" if self.translator.is_rtl else "left"
        tk.Label(row, text="●", bg=COLORS["panel"], fg=color, font=("Segoe UI", 8)).pack(side=side, padx=(0, 7))
        tk.Label(row, text=label, bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 9), anchor=anchor).pack(side=side)
        tk.Label(row, text=status, bg=COLORS["panel"], fg=color, font=("Segoe UI", 8), anchor=anchor).pack(side="left" if side == "right" else "right")

    def _style_mode_buttons(self) -> None:
        if not hasattr(self, "mode_buttons"):
            return
        selected_mode = self.mode_var.get()
        for mode, button in self.mode_buttons.items():
            selected = mode == selected_mode
            foreground = self._mode_color(mode)
            button.configure(
                bg="#173B31" if selected and mode == "active" else "#3A2D18" if selected and mode == "strict" else "#272F3C" if selected else COLORS["panel_alt"],
                fg=foreground if selected else COLORS["muted"],
                activebackground="#173B31" if mode == "active" else "#3A2D18" if mode == "strict" else "#272F3C",
                activeforeground=foreground,
            )

    def _refresh_dashboard_metrics(self, *, schedule: bool = True) -> None:
        if not hasattr(self, "metric_values") or self._closed or self.current_page != "dashboard":
            return
        process_count: int | str = len(self.process_monitor.snapshot()) if self.process_monitor.available else "—"
        settings = self.policy.get_settings()
        folders = settings.get("protected_folders", [])
        blocked_count = sum(1 for event in self.policy.read_audit(1000) if event.get("event") == "quarantine")
        quarantined_count = len(self.quarantine.list_items())
        values = {
            "processes": process_count,
            "paths": len(folders) if isinstance(folders, list) else 0,
            "blocked": blocked_count,
            "quarantine": quarantined_count,
        }
        for key, value in values.items():
            self.metric_values[key].configure(text=str(value))
        if schedule and self.current_page == "dashboard":
            self._metric_after_id = self.after(10000, self._refresh_dashboard_metrics)

    def _render_settings(self, parent: tk.Misc) -> None:
        t = self.translator.text
        settings = self.policy.get_settings()
        rtl = self.translator.is_rtl
        anchor = "e" if rtl else "w"
        allow_box = tk.Frame(parent, bg=COLORS["panel"])
        allow_box.pack(fill="x", pady=(0, 8))
        tk.Label(allow_box, text=t("allowlist"), bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 9, "bold"), anchor=anchor).pack(fill="x")
        tk.Label(allow_box, text=t("allowlist_help"), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8), anchor=anchor).pack(fill="x", pady=(2, 4))
        self.allowlist_text = tk.Text(
            allow_box, height=2, wrap="none", bg=COLORS["background"], fg=COLORS["text"],
            insertbackground=COLORS["text"], relief="flat", font=("Consolas", 9),
            highlightbackground=COLORS["border"], highlightthickness=1,
        )
        self.allowlist_text.pack(fill="x")
        self.allowlist_text.insert("1.0", "\n".join(str(item) for item in settings.get("allowlist", [])))
        self._button(allow_box, t("save_allowlist"), self._save_allowlist, "secondary").pack(anchor="e" if not rtl else "w", pady=(5, 0))

        folder_box = tk.Frame(parent, bg=COLORS["panel"])
        folder_box.pack(fill="x")
        tk.Label(folder_box, text=t("protected_folders"), bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 9, "bold"), anchor=anchor).pack(fill="x")
        self.folders_text = tk.Text(
            folder_box, height=2, wrap="none", bg=COLORS["background"], fg=COLORS["text"],
            insertbackground=COLORS["text"], relief="flat", font=("Consolas", 9),
            highlightbackground=COLORS["border"], highlightthickness=1,
        )
        self.folders_text.pack(fill="x", pady=(4, 0))
        self.folders_text.insert("1.0", "\n".join(str(item) for item in settings.get("protected_folders", [])))
        self._button(folder_box, t("save_folders"), self._save_folders, "secondary").pack(anchor="e" if not rtl else "w", pady=(5, 0))
        self._button(parent, t("product_controls"), self._show_product_controls, "secondary").pack(
            anchor="e" if not rtl else "w", pady=(10, 0)
        )

    def _show_product_controls(self) -> None:
        t = self.translator.text
        rtl = self.translator.is_rtl
        anchor = "e" if rtl else "w"
        dialog = tk.Toplevel(self)
        dialog.title(t("product_controls"))
        dialog.configure(bg=COLORS["background"])
        dialog.geometry("780x760")
        dialog.minsize(700, 680)
        dialog.transient(self)
        dialog.grab_set()
        content = tk.Frame(dialog, bg=COLORS["background"], padx=20, pady=16)
        content.pack(fill="both", expand=True)
        self._page_heading(content, t("product_controls"), t("demo_warning"))

        profile_card = card(content, padding=12)
        profile_card.pack(fill="x", pady=(0, 9))
        tk.Label(profile_card, text=t("security_profile"), bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 9, "bold"), anchor=anchor).pack(fill="x")
        profile_ids = ("developer_safe", "balanced_guard")
        if self.license_manager.is_pro():
            profile_ids += ("strict_lockdown",)
        label_to_profile = {t(PROFILE_LABEL_KEYS[profile_id]): profile_id for profile_id in profile_ids}
        profile_var = tk.StringVar(value=t(PROFILE_LABEL_KEYS[self.policy.get_security_profile()]))
        profile_row = tk.Frame(profile_card, bg=COLORS["panel"])
        profile_row.pack(fill="x", pady=(6, 0))
        profile_box = ttk.Combobox(
            profile_row,
            textvariable=profile_var,
            values=list(label_to_profile),
            state="readonly",
            width=38,
        )
        profile_box.pack(side="right" if rtl else "left", fill="x", expand=True)

        def save_profile() -> None:
            profile = label_to_profile.get(profile_var.get())
            if profile is None:
                return
            self.policy.set_security_profile(profile)
            self.scanner = Scanner(self.policy.get_custom_rules())
            self.policy.audit("security_profile_changed", profile=profile)
            messagebox.showinfo(t("security_profile"), t("profile_saved"), parent=dialog)

        self._button(profile_row, t("profile_saved"), save_profile, "secondary").pack(side="left" if rtl else "right", padx=(8, 0))

        license_card = card(content, padding=12)
        license_card.pack(fill="x", pady=(0, 9))
        license_heading = tk.Label(license_card, bg=COLORS["panel"], fg=COLORS["emerald"], font=("Segoe UI", 9, "bold"), anchor=anchor)
        license_heading.pack(fill="x")
        tk.Label(license_card, text=t("demo_warning"), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8), anchor=anchor, wraplength=680, justify="right" if rtl else "left").pack(fill="x", pady=(3, 5))
        license_entry = tk.Entry(
            license_card, bg=COLORS["background"], fg=COLORS["text"], insertbackground=COLORS["text"],
            relief="flat", font=("Consolas", 9), highlightbackground=COLORS["border"], highlightthickness=1,
        )
        license_entry.pack(fill="x", pady=(0, 6))
        license_entry.insert(0, "")
        license_actions = tk.Frame(license_card, bg=COLORS["panel"])
        license_actions.pack(fill="x")
        demo_button = self._button(license_actions, "", lambda: None, "secondary")
        demo_button.pack(side="left" if rtl else "right", padx=(0, 6))

        def update_license_controls() -> None:
            status = self.license_manager.status()
            label = t("edition_pro") if status["edition"] == "pro" else t("edition_community")
            license_heading.configure(text=f"{t('edition_status')}: {label}")
            if status["license_type"] == "demo":
                demo_button.configure(text=t("disable_demo"), command=toggle_demo, state="normal")
            elif status["edition"] == "pro":
                demo_button.configure(text=t("edition_pro"), command=lambda: None, state="disabled")
            else:
                demo_button.configure(text=t("enable_demo"), command=toggle_demo, state="normal")
            available_profiles = ("developer_safe", "balanced_guard", "strict_lockdown") if self.license_manager.is_pro() else ("developer_safe", "balanced_guard")
            label_to_profile.clear()
            label_to_profile.update({t(PROFILE_LABEL_KEYS[key]): key for key in available_profiles})
            profile_box.configure(values=list(label_to_profile))
            if self.policy.get_security_profile() not in available_profiles:
                self.policy.set_security_profile("balanced_guard")
                profile_var.set(t(PROFILE_LABEL_KEYS["balanced_guard"]))

        def activate_license() -> None:
            try:
                self.license_manager.activate(license_entry.get().strip())
            except (OSError, ValueError):
                messagebox.showerror(t("edition_status"), t("activation_failed"), parent=dialog)
                return
            self.report_exporter.license_status = self.license_manager.status()
            update_license_controls()
            messagebox.showinfo(t("edition_status"), t("license_activated"), parent=dialog)

        def toggle_demo() -> None:
            try:
                self.license_manager.set_demo_mode(self.license_manager.status()["license_type"] != "demo")
            except OSError as exc:
                messagebox.showerror(t("edition_status"), str(exc), parent=dialog)
                return
            self.report_exporter.license_status = self.license_manager.status()
            update_license_controls()

        self._button(license_actions, t("activate_license"), activate_license, "primary").pack(side="left" if rtl else "right", padx=(0, 6))
        update_license_controls()

        report_card = card(content, padding=12)
        report_card.pack(fill="x", pady=(0, 9))
        tk.Label(report_card, text=t("report_title"), bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 9, "bold"), anchor=anchor).pack(fill="x")
        report_actions = tk.Frame(report_card, bg=COLORS["panel"])
        report_actions.pack(fill="x", pady=(6, 0))

        def export_report(kind: str) -> None:
            if not self._require_pro(dialog):
                return
            extension = ".json" if kind == "json" else ".html"
            destination = filedialog.asksaveasfilename(
                parent=dialog,
                title=t("report_title"),
                defaultextension=extension,
                filetypes=[("JSON report", "*.json")] if kind == "json" else [("HTML report", "*.html")],
            )
            if not destination:
                return
            try:
                finding_data = [finding.to_dict() for finding in self.findings]
                if kind == "json":
                    self.report_exporter.export_json(destination, finding_data)
                else:
                    self.report_exporter.export_html(destination, finding_data, self.translator.language)
            except (OSError, ValueError, KeyError) as exc:
                messagebox.showerror(t("error"), str(exc), parent=dialog)
                return
            messagebox.showinfo(t("report_title"), t("report_export_success"), parent=dialog)

        self._button(report_actions, t("export_json_report"), lambda: export_report("json"), "secondary").pack(side="left" if rtl else "right", padx=(0, 6))
        self._button(report_actions, t("export_html_report"), lambda: export_report("html"), "secondary").pack(side="left" if rtl else "right")

        rules_card = card(content, padding=12)
        rules_card.pack(fill="x", pady=(0, 9))
        tk.Label(rules_card, text=t("custom_rules_title"), bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 9, "bold"), anchor=anchor).pack(fill="x")
        tk.Label(rules_card, text=t("custom_rules_help"), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8), anchor=anchor).pack(fill="x", pady=(2, 4))
        rules_input = tk.Text(rules_card, height=3, wrap="word", bg=COLORS["background"], fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat", font=("Consolas", 9), highlightbackground=COLORS["border"], highlightthickness=1)
        rules_input.pack(fill="x")
        rules_input.insert("1.0", "\n".join(self.policy.get_custom_rules()))

        def save_custom_rules() -> None:
            if not self._require_pro(dialog):
                return
            try:
                self.policy.set_custom_rules(rules_input.get("1.0", "end").splitlines())
            except ValueError as exc:
                messagebox.showerror(t("custom_rules_title"), str(exc), parent=dialog)
                return
            self.scanner = Scanner(self.policy.get_custom_rules())
            self.policy.audit("custom_rules_updated", count=len(self.policy.get_custom_rules()))
            messagebox.showinfo(t("custom_rules_title"), t("settings_saved"), parent=dialog)

        self._button(rules_card, t("save_custom_rules"), save_custom_rules, "secondary").pack(anchor="e" if not rtl else "w", pady=(5, 0))

        schedule_card = card(content, padding=12)
        schedule_card.pack(fill="x")
        tk.Label(schedule_card, text=t("scheduled_scan_title"), bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 9, "bold"), anchor=anchor).pack(fill="x")
        tk.Label(schedule_card, text=t("scheduled_scan_help"), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8), anchor=anchor).pack(fill="x", pady=(2, 5))
        schedule_state = self.policy.get_settings().get("scheduled_scan", {})
        schedule_state = schedule_state if isinstance(schedule_state, dict) else {}
        schedule_path_var = tk.StringVar(value=str(schedule_state.get("target", "")))
        schedule_path_row = tk.Frame(schedule_card, bg=COLORS["panel"])
        schedule_path_row.pack(fill="x")
        schedule_path_entry = tk.Entry(schedule_path_row, textvariable=schedule_path_var, bg=COLORS["background"], fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat", font=("Segoe UI", 9), highlightbackground=COLORS["border"], highlightthickness=1)
        schedule_path_entry.pack(side="left", fill="x", expand=True)

        def browse_schedule_path() -> None:
            selected = filedialog.askdirectory(parent=dialog, title=t("scheduled_target"))
            if selected:
                schedule_path_var.set(selected)

        self._button(schedule_path_row, t("browse_folder"), browse_schedule_path, "secondary").pack(side="right" if not rtl else "left", padx=(6, 0))
        schedule_options = tk.Frame(schedule_card, bg=COLORS["panel"])
        schedule_options.pack(fill="x", pady=(6, 0))
        tk.Label(schedule_options, text=t("interval_hours"), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8), anchor=anchor).pack(side="left" if not rtl else "right")
        interval = tk.Spinbox(schedule_options, from_=1, to=168, width=5, bg=COLORS["background"], fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat")
        interval.pack(side="left" if not rtl else "right", padx=8)
        interval.delete(0, "end")
        interval.insert(0, str(schedule_state.get("interval_hours", 24)))

        def start_schedule() -> None:
            if not self._require_pro(dialog):
                return
            target = schedule_path_var.get().strip()
            if not target:
                messagebox.showerror(t("scheduled_scan_title"), t("scheduled_path_required"), parent=dialog)
                return
            try:
                hours = int(interval.get())
                self.scheduled_scanner.start(target, hours)
            except (OSError, ValueError) as exc:
                messagebox.showerror(t("scheduled_scan_title"), str(exc), parent=dialog)
                return
            self.policy.update_setting("scheduled_scan", {"enabled": True, "target": target, "interval_hours": hours})
            messagebox.showinfo(t("scheduled_scan_title"), t("scheduled_scan_started"), parent=dialog)

        def stop_schedule() -> None:
            self.scheduled_scanner.stop()
            try:
                hours = int(interval.get())
            except ValueError:
                hours = int(schedule_state.get("interval_hours", 24))
            self.policy.update_setting("scheduled_scan", {"enabled": False, "target": schedule_path_var.get().strip(), "interval_hours": hours})
            messagebox.showinfo(t("scheduled_scan_title"), t("scheduled_scan_stopped"), parent=dialog)

        schedule_actions = tk.Frame(schedule_card, bg=COLORS["panel"])
        schedule_actions.pack(fill="x", pady=(7, 0))
        self._button(schedule_actions, t("start_scheduled_scan"), start_schedule, "primary").pack(side="left" if rtl else "right")
        self._button(schedule_actions, t("stop_scheduled_scan"), stop_schedule, "secondary").pack(side="left" if rtl else "right", padx=(0, 6))

    def _require_pro(self, parent: tk.Misc | None = None) -> bool:
        if self.license_manager.is_pro():
            return True
        messagebox.showinfo(self.translator.text("edition_status"), self.translator.text("pro_required"), parent=parent)
        return False

    def _render_scanner(self) -> None:
        t = self.translator.text
        rtl = self.translator.is_rtl
        anchor = "e" if rtl else "w"
        page = self._page_frame()
        page.pack(fill="both", expand=True)
        self._page_heading(page, t("scanner"), t("scan_tab_hint"))

        tab_row = tk.Frame(page, bg=COLORS["background"])
        tab_row.pack(fill="x", pady=(0, 12))
        self.scan_mode_buttons: dict[str, tk.Button] = {}
        for mode, key in (("file", "scan_file_tab"), ("folder", "scan_folder_tab"), ("text", "scan_text_tab")):
            button = self._button(tab_row, t(key), lambda selected=mode: self._set_scan_mode(selected))
            button.pack(side="right" if rtl else "left", padx=(0, 7))
            if self._scan_running:
                button.configure(state="disabled")
            self.scan_mode_buttons[mode] = button
        self._style_scan_mode_buttons()

        self.scan_source_host = tk.Frame(page, bg=COLORS["background"])
        self.scan_source_host.pack(fill="x", pady=(0, 12))
        self._render_scan_source()

        result_card = card(page, padding=14)
        result_card.pack(fill="both", expand=True)
        top = tk.Frame(result_card, bg=COLORS["panel"])
        top.pack(fill="x")
        tk.Label(top, text=t("scan_results"), bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 11, "bold"), anchor=anchor).pack(side="left" if not rtl else "right")
        self.scan_status = tk.Label(top, text=t("ready"), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8), anchor=anchor)
        self.scan_status.pack(side="right" if not rtl else "left")
        progress_row = tk.Frame(result_card, bg=COLORS["panel"])
        progress_row.pack(fill="x", pady=(10, 0))
        self.progress_label = tk.Label(
            progress_row,
            text=t("scan_progress"),
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=("Segoe UI", 7, "bold"),
        )
        self.progress_label.pack(anchor=anchor)
        self.progress_canvas = tk.Canvas(progress_row, height=5, bg=COLORS["panel_alt"], highlightthickness=0)
        self.progress_canvas.pack(fill="x", pady=(5, 0))
        self.progress_canvas.bind("<Configure>", lambda _event: self._draw_scan_progress(getattr(self, "_scan_progress", 0)))

        meter_row = tk.Frame(result_card, bg=COLORS["panel"])
        meter_row.pack(fill="x", pady=(12, 12))
        meter_info = tk.Frame(meter_row, bg=COLORS["panel"])
        meter_info.pack(fill="x")
        tk.Label(meter_info, text=t("risk_meter"), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8, "bold")).pack(side="left")
        self.risk_value = tk.Label(meter_info, text="0 / 100", bg=COLORS["panel"], fg=COLORS["emerald"], font=("Segoe UI", 9, "bold"))
        self.risk_value.pack(side="right")
        self.risk_badge = tk.Label(
            meter_info,
            text=t("clear").upper(),
            bg="#10271F",
            fg=COLORS["emerald"],
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=3,
        )
        self.risk_badge.pack(side="right", padx=9)
        self.risk_canvas = tk.Canvas(meter_row, height=10, bg=COLORS["panel_alt"], highlightthickness=0)
        self.risk_canvas.pack(fill="x", pady=(8, 0))
        self.risk_canvas.bind("<Configure>", lambda _event: self._draw_risk_meter(getattr(self, "_risk_score", 0)))

        columns = ("target", "risk", "severity", "confidence", "rules", "action")
        self.results = ttk.Treeview(result_card, columns=columns, show="headings", height=9, style="AI.Treeview")
        definitions = (
            ("target", "target", 190), ("risk", "risk_score", 72), ("severity", "severity", 80),
            ("confidence", "accuracy_confidence", 94),
            ("rules", "matched_rules", 270), ("action", "recommended_action", 120),
        )
        for column, key, width in definitions:
            self.results.heading(column, text=t(key).upper())
            self.results.column(column, width=width, stretch=column in {"target", "rules"})
        self.results.tag_configure("clear", foreground=COLORS["emerald"])
        self.results.tag_configure("low", foreground=COLORS["emerald"])
        self.results.tag_configure("medium", foreground=COLORS["amber"])
        self.results.tag_configure("high", foreground=COLORS["crimson"])
        self.results.pack(fill="both", expand=True, pady=(0, 10))
        self.results.bind("<<TreeviewSelect>>", self._select_finding)

        actions = tk.Frame(result_card, bg=COLORS["panel"])
        actions.pack(fill="x")
        self._button(actions, t("quarantine"), self._quarantine_selected, "danger").pack(side="left", padx=(0, 7))
        self._button(actions, t("action_allowlist"), self._allowlist_selected, "warning").pack(side="left", padx=7)
        self._button(actions, t("action_clear"), self._clear_scan, "secondary").pack(side="right")

    def _set_scan_mode(self, mode: str) -> None:
        if mode not in {"file", "folder", "text"}:
            return
        self._scan_mode = mode
        self._scan_source = None
        self._render_scanner()

    def _style_scan_mode_buttons(self) -> None:
        for mode, button in getattr(self, "scan_mode_buttons", {}).items():
            selected = mode == self._scan_mode
            button.configure(
                bg="#173B31" if selected else COLORS["panel_alt"],
                fg=COLORS["emerald"] if selected else COLORS["muted"],
                activebackground="#173B31" if selected else "#223148",
                activeforeground=COLORS["emerald"] if selected else COLORS["text"],
            )

    def _render_scan_source(self) -> None:
        for child in self.scan_source_host.winfo_children():
            child.destroy()
        t = self.translator.text
        rtl = self.translator.is_rtl
        anchor = "e" if rtl else "w"
        if self._scan_mode == "text":
            source = card(self.scan_source_host, padding=14)
            source.pack(fill="x")
            tk.Label(source, text=t("scan_input"), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 9, "bold"), anchor=anchor).pack(fill="x", pady=(0, 7))
            self.scan_text_box = tk.Text(
                source, height=5, wrap="word", bg=COLORS["background"], fg=COLORS["text"],
                insertbackground=COLORS["text"], relief="flat", font=("Segoe UI", 10),
                highlightbackground=COLORS["border"], highlightthickness=1,
            )
            self.scan_text_box.pack(fill="x")
            if rtl:
                self.scan_text_box.tag_configure("rtl", justify="right")
                self.scan_text_box.tag_add("rtl", "1.0", "end")
            controls = tk.Frame(source, bg=COLORS["panel"])
            controls.pack(fill="x", pady=(9, 0))
            self._button(controls, t("scan_now"), self._scan_pasted_text, "primary").pack(side="right" if rtl else "left")
            return

        kind = "file" if self._scan_mode == "file" else "folder"
        title = t("scan_drop_title") if kind == "file" else t("choose_folder")
        browse_text = t("browse_file") if kind == "file" else t("browse_folder")
        browse = self._scan_file if kind == "file" else self._scan_folder
        source = card(self.scan_source_host, padding=16)
        source.pack(fill="x")
        source.configure(highlightbackground="#2D425C")
        text_col = tk.Frame(source, bg=COLORS["panel"])
        text_col.pack(side="right" if rtl else "left", fill="x", expand=True)
        tk.Label(text_col, text=title, bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 11, "bold"), anchor=anchor).pack(fill="x")
        tk.Label(text_col, text=t("scan_drop_hint"), bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 9), anchor=anchor).pack(fill="x", pady=(4, 4))
        self.scan_source_label = tk.Label(
            text_col,
            text=str(self._scan_source) if self._scan_source else t("no_selection"),
            bg=COLORS["panel"],
            fg=COLORS["emerald"] if self._scan_source else COLORS["muted"],
            font=("Segoe UI", 8),
            anchor=anchor,
        )
        self.scan_source_label.pack(fill="x")
        buttons = tk.Frame(source, bg=COLORS["panel"])
        buttons.pack(side="left" if rtl else "right", padx=(12, 0) if not rtl else (0, 12))
        self._button(buttons, browse_text, browse, "secondary").pack(side="left" if not rtl else "right", padx=(0, 6))
        self._button(buttons, t("scan_now"), self._scan_selected_path, "primary").pack(side="left" if not rtl else "right")

    def _scan_file(self) -> None:
        path = filedialog.askopenfilename(title=self.translator.text("choose_file"))
        if path:
            self._scan_source = Path(path)
            if hasattr(self, "scan_source_label"):
                self.scan_source_label.configure(text=path, fg=COLORS["emerald"])

    def _scan_folder(self) -> None:
        path = filedialog.askdirectory(title=self.translator.text("choose_folder"))
        if path:
            self._scan_source = Path(path)
            if hasattr(self, "scan_source_label"):
                self.scan_source_label.configure(text=path, fg=COLORS["emerald"])

    def _scan_selected_path(self) -> None:
        if self._scan_source is None:
            self._scan_file() if self._scan_mode == "file" else self._scan_folder()
        if self._scan_source is not None:
            source = self._scan_source
            profile = self.policy.get_security_profile()
            self._start_scan(lambda: self.scanner.scan_path(source, profile), "path", str(source))

    def _scan_pasted_text(self) -> None:
        content = self.scan_text_box.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showinfo(self.translator.text("scanner"), self.translator.text("scan_input_empty"))
            return
        identity = "scan:text:" + hashlib.sha256(content.encode("utf-8")).hexdigest()
        profile = self.policy.get_security_profile()
        self._start_scan(lambda: [self.scanner.scan_text(content, self.translator.text("scan_input"), profile)], identity)

    def _start_scan(self, work: Callable[[], list[Finding]], identity: str, audit_target: str | None = None) -> None:
        self._scan_running = True
        self._scan_progress = 0
        self._draw_scan_progress(0)
        self.scan_status.configure(text=self.translator.text("scanning"), fg=COLORS["amber"])
        for button in getattr(self, "scan_mode_buttons", {}).values():
            button.configure(state="disabled")
        self._animate_scan_progress()

        def run_scan() -> None:
            try:
                result = work()
                error = None
            except (OSError, ValueError) as exc:
                result = []
                error = str(exc)
            if not self._closed:
                try:
                    self.after(0, lambda: self._finish_scan(result, error, identity, audit_target))
                except RuntimeError:
                    return

        threading.Thread(target=run_scan, daemon=True, name="ai-fbi-scan").start()

    def _animate_scan_progress(self) -> None:
        if not hasattr(self, "scan_status") or not self.scan_status.winfo_exists():
            return
        self._scan_progress = min(90, self._scan_progress + 7)
        self.progress_label.configure(text=f"{self.translator.text('scan_progress')}  {self._scan_progress}%")
        self._draw_scan_progress(self._scan_progress)
        if self._scan_progress < 90:
            self._scan_after_id = self.after(100, self._animate_scan_progress)

    def _finish_scan(self, findings: list[Finding], error: str | None, identity: str, audit_target: str | None = None) -> None:
        if self.current_page != "scanner" or not hasattr(self, "scan_status") or not self.scan_status.winfo_exists():
            self._pending_scan_results = (findings, error, identity, audit_target)
            return
        if self._scan_after_id:
            self.after_cancel(self._scan_after_id)
            self._scan_after_id = None
        if error:
            self._scan_running = False
            for button in getattr(self, "scan_mode_buttons", {}).values():
                button.configure(state="normal")
            self.scan_status.configure(text=self.translator.text("scan_failed"), fg=COLORS["crimson"])
            messagebox.showerror(self.translator.text("scan_failed"), error)
            return
        self._scan_progress = 100
        self._scan_running = False
        self.progress_label.configure(text=f"{self.translator.text('scan_progress')}  100%")
        self._draw_scan_progress(100)
        for button in getattr(self, "scan_mode_buttons", {}).values():
            button.configure(state="normal")
        if identity == "path":
            self._finding_identities = [self._path_identity(item.target) for item in findings]
            target = audit_target or (str(self._scan_source) if self._scan_source else "")
            self.policy.audit("scan_path", target=target, result_count=len(findings))
        else:
            self._finding_identities = [identity] * len(findings)
            self.policy.audit("scan_text", risk_score=max((item.risk_score for item in findings), default=0))
        allowed = set(str(item) for item in self.policy.get_settings().get("allowlist", []))
        self.findings = [
            Finding(item.target, 0, "clear", ["allowlisted"], "allow") if identity_key in allowed else item
            for item, identity_key in zip(findings, self._finding_identities)
        ]
        self._populate_findings()
        self.scan_status.configure(text=self.translator.text("scan_done"), fg=COLORS["emerald"])

    @staticmethod
    def _path_identity(target: str) -> str:
        return "scan:path:" + str(Path(target).expanduser().resolve())

    def _populate_findings(self) -> None:
        self.results.delete(*self.results.get_children())
        for index, finding in enumerate(self.findings):
            rules = ", ".join(self.translator.text(f"rule_{rule}") if rule != "allowlisted" else self.translator.text("allow") for rule in finding.matched_rules)
            severity_key = "critical" if finding.risk_score >= 70 else "medium" if finding.risk_score >= 40 else "low" if finding.risk_score else "clear"
            self.results.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    finding.target,
                    finding.risk_score,
                    self.translator.text(severity_key).upper(),
                    f"{finding.confidence}%" if finding.risk_score else "—",
                    rules or self.translator.text("no_findings"),
                    self.translator.text(finding.recommended_action),
                ),
                tags=(finding.severity,),
            )
        if self.findings:
            highest = max(range(len(self.findings)), key=lambda index: self.findings[index].risk_score)
            self.results.selection_set(str(highest))
            self._select_finding()
        else:
            self._selected_finding = None
            self._selected_identity = None
            self._update_risk_meter(0)
            self.scan_status.configure(text=self.translator.text("scan_safe"), fg=COLORS["emerald"])

    def _select_finding(self, _event: object = None) -> None:
        selected = self.results.selection()
        if not selected:
            self._selected_finding = None
            self._selected_identity = None
            self._update_risk_meter(0)
            return
        index = int(selected[0])
        self._selected_finding = self.findings[index]
        self._selected_identity = self._finding_identities[index] if index < len(self._finding_identities) else None
        self._update_risk_meter(self._selected_finding.risk_score)

    def _update_risk_meter(self, score: int) -> None:
        self._risk_score = score
        if hasattr(self, "risk_value"):
            self.risk_value.configure(text=f"{score} / 100")
            if score >= 70:
                color, label, badge_bg = COLORS["crimson"], self.translator.text("critical"), "#3C1D25"
            elif score >= 40:
                color, label, badge_bg = COLORS["amber"], self.translator.text("medium"), "#3B2E19"
            elif score > 0:
                color, label, badge_bg = COLORS["emerald"], self.translator.text("low"), "#10271F"
            else:
                color, label, badge_bg = COLORS["emerald"], self.translator.text("clear"), "#10271F"
            self.risk_value.configure(fg=color)
            self.risk_badge.configure(text=label.upper(), fg=color, bg=badge_bg)
            self._draw_risk_meter(score)

    def _draw_risk_meter(self, score: int) -> None:
        if not hasattr(self, "risk_canvas") or not self.risk_canvas.winfo_exists():
            return
        width = self.risk_canvas.winfo_width()
        if width < 4:
            return
        self.risk_canvas.delete("all")
        color = COLORS["crimson"] if score >= 70 else COLORS["amber"] if score >= 40 else COLORS["emerald"]
        self.risk_canvas.create_rectangle(0, 0, width * max(0, min(100, score)) / 100, 10, fill=color, outline="")

    def _draw_scan_progress(self, progress: int) -> None:
        if not hasattr(self, "progress_canvas") or not self.progress_canvas.winfo_exists():
            return
        width = self.progress_canvas.winfo_width()
        if width < 4:
            return
        self.progress_canvas.delete("all")
        self.progress_canvas.create_rectangle(
            0, 0, width * max(0, min(100, progress)) / 100, 5,
            fill=COLORS["emerald"] if progress >= 100 else COLORS["blue"],
            outline="",
        )

    def _quarantine_selected(self) -> None:
        finding = self._selected_finding
        if finding is None or finding.target == self.translator.text("scan_input"):
            messagebox.showinfo(self.translator.text("scanner"), self.translator.text("scan_path_first"))
            return
        try:
            self.quarantine.quarantine_path(finding.target, finding.to_dict())
            self.policy.audit("quarantine_from_scanner", target=finding.target)
            self.scan_status.configure(text=self.translator.text("quarantined_success"), fg=COLORS["emerald"])
            self._refresh_dashboard_metrics()
        except (OSError, ValueError) as exc:
            messagebox.showerror(self.translator.text("error"), str(exc))

    def _allowlist_selected(self) -> None:
        if not self._selected_identity:
            messagebox.showinfo(self.translator.text("scanner"), self.translator.text("scan_path_first"))
            return
        self.policy.add_allowlist(self._selected_identity)
        self.policy.audit("scan_target_allowlisted", target=self._selected_identity)
        self.scan_status.configure(text=self.translator.text("target_allowlisted"), fg=COLORS["emerald"])

    def _clear_scan(self) -> None:
        self.findings = []
        self._finding_identities = []
        self._selected_finding = None
        self._selected_identity = None
        if hasattr(self, "results") and self.results.winfo_exists():
            self.results.delete(*self.results.get_children())
        if self._scan_mode == "text" and hasattr(self, "scan_text_box"):
            self.scan_text_box.delete("1.0", "end")
        self._update_risk_meter(0)
        self._scan_progress = 0
        self.progress_label.configure(text=self.translator.text("scan_progress"))
        self._draw_scan_progress(0)
        self.scan_status.configure(text=self.translator.text("ready"), fg=COLORS["muted"])

    def _render_threat_logs(self) -> None:
        page = self._page_frame()
        page.pack(fill="both", expand=True)
        self._page_heading(page, self.translator.text("nav_threat_logs"), self.translator.text("activity_title"))
        container = card(page, padding=13)
        container.pack(fill="both", expand=True)
        toolbar = tk.Frame(container, bg=COLORS["panel"])
        toolbar.pack(fill="x", pady=(0, 10))
        tk.Label(toolbar, text=self.translator.text("audit_events"), bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 11, "bold")).pack(side="left")
        self._button(toolbar, self.translator.text("refresh"), self._refresh_logs, "secondary").pack(side="right")
        columns = ("time", "event", "severity", "details")
        self.audit_view = ttk.Treeview(container, columns=columns, show="headings", style="AI.Treeview")
        for column, key, width in (
            ("time", "table_time", 175), ("event", "table_event", 190),
            ("severity", "table_severity", 100), ("details", "table_details", 500),
        ):
            self.audit_view.heading(column, text=self.translator.text(key))
            self.audit_view.column(column, width=width, stretch=column == "details")
        self.audit_view.tag_configure("critical", foreground=COLORS["crimson"])
        self.audit_view.tag_configure("warning", foreground=COLORS["amber"])
        self.audit_view.tag_configure("safe", foreground=COLORS["emerald"])
        self.audit_view.pack(fill="both", expand=True)
        self._refresh_logs()

    def _event_label(self, event: str) -> str:
        key_map = {
            "quarantine": "nav_quarantine",
            "quarantine_from_scanner": "nav_quarantine",
            "quarantine_restore": "restore",
            "quarantine_restore_from_ui": "restore",
            "quarantine_delete": "permanently_delete",
            "scan_path": "scan_folder",
            "scan_text": "scan_text_tab",
            "process_risk": "alert_process_risk",
            "process_alert": "alert_process_risk",
            "process_action": "monitor_processes",
            "process_action_failed": "error",
            "process_allowlisted": "allowlist",
            "network_connection": "alert_network_connection",
            "file_change": "monitor_files",
            "shield_mode_changed": "shield_mode",
            "scan_target_allowlisted": "allowlist",
            "allowlist_updated": "allowlist",
            "protected_folders_updated": "protected_folders",
            "self_protection_tamper_indicator": "category_integrity",
            "self_protection_integrity_error": "category_integrity",
            "self_protection_warning": "category_integrity",
            "monitor_notification": "monitoring",
        }
        return self.translator.text(key_map[event]) if event in key_map else event.replace("_", " ").title()

    def _refresh_logs(self) -> None:
        if not hasattr(self, "audit_view") or not self.audit_view.winfo_exists():
            return
        self.audit_view.delete(*self.audit_view.get_children())
        records = reversed(self.policy.read_audit(500))
        for index, record in enumerate(records):
            event = str(record.get("event", "event"))
            risk = int(record.get("risk_score", 0) or 0)
            severity = "critical" if risk >= 70 or event in {"process_risk", "self_protection_tamper_indicator"} else "warning" if risk >= 30 or event in {"network_connection", "file_change"} else "safe"
            details = {key: value for key, value in record.items() if key not in {"timestamp", "event"}}
            self.audit_view.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    str(record.get("timestamp", "")).replace("T", " ")[:19],
                    self._event_label(event),
                    self.translator.text(severity if severity != "critical" else "high").upper(),
                    json.dumps(details, ensure_ascii=False, default=str)[:800],
                ),
                tags=(severity,),
            )

    def _render_quarantine(self) -> None:
        page = self._page_frame()
        page.pack(fill="both", expand=True)
        self._page_heading(page, self.translator.text("nav_quarantine"), self.translator.text("quarantine_items"))
        container = card(page, padding=13)
        container.pack(fill="both", expand=True)
        toolbar = tk.Frame(container, bg=COLORS["panel"])
        toolbar.pack(fill="x", pady=(0, 10))
        tk.Label(toolbar, text=self.translator.text("quarantine_items"), bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 11, "bold")).pack(side="left")
        self._button(toolbar, self.translator.text("refresh"), self._refresh_quarantine, "secondary").pack(side="right")
        columns = ("name", "path", "date", "severity")
        self.quarantine_view = ttk.Treeview(container, columns=columns, show="headings", style="AI.Treeview", height=12)
        for column, key, width in (
            ("name", "table_item", 190), ("path", "target", 430),
            ("date", "table_date", 175), ("severity", "table_severity", 100),
        ):
            self.quarantine_view.heading(column, text=self.translator.text(key))
            self.quarantine_view.column(column, width=width, stretch=column == "path")
        self.quarantine_view.tag_configure("critical", foreground=COLORS["crimson"])
        self.quarantine_view.tag_configure("warning", foreground=COLORS["amber"])
        self.quarantine_view.pack(fill="both", expand=True)
        actions = tk.Frame(container, bg=COLORS["panel"])
        actions.pack(fill="x", pady=(10, 0))
        self._button(actions, self.translator.text("inspect"), self._inspect_quarantined, "secondary").pack(side="left")
        self._button(actions, self.translator.text("restore"), self._restore_selected, "primary").pack(side="left", padx=8)
        self._button(actions, self.translator.text("permanently_delete"), self._delete_selected, "danger").pack(side="right")
        self._refresh_quarantine()

    def _refresh_quarantine(self) -> None:
        if not hasattr(self, "quarantine_view") or not self.quarantine_view.winfo_exists():
            return
        self.quarantine_view.delete(*self.quarantine_view.get_children())
        for entry in self.quarantine.list_items():
            finding = entry.get("finding", {})
            score = int(finding.get("risk_score", 0) or 0) if isinstance(finding, dict) else 0
            severity = self.translator.text("critical" if score >= 70 else "medium" if score >= 40 else "low" if score else "clear")
            tag = "critical" if score >= 70 else "warning" if score >= 40 else "safe"
            self.quarantine_view.insert(
                "",
                "end",
                iid=entry["id"],
                values=(
                    Path(entry.get("original_path", "")).name,
                    entry.get("original_path", ""),
                    str(entry.get("quarantined_at", "")).replace("T", " ")[:19],
                    severity.upper(),
                ),
                tags=(tag,),
            )
        self._refresh_dashboard_metrics()

    def _selected_quarantine_item(self) -> dict[str, Any] | None:
        selected = self.quarantine_view.selection()
        if not selected:
            messagebox.showinfo(self.translator.text("nav_quarantine"), self.translator.text("no_selection"))
            return None
        return next((item for item in self.quarantine.list_items() if item.get("id") == selected[0]), None)

    def _inspect_quarantined(self) -> None:
        item = self._selected_quarantine_item()
        if item is None:
            return
        finding = item.get("finding", {})
        rules = finding.get("matched_rules", []) if isinstance(finding, dict) else []
        details = (
            f"{self.translator.text('target')}: {item.get('original_path', '')}\n"
            f"{self.translator.text('table_date')}: {item.get('quarantined_at', '')}\n"
            f"{self.translator.text('risk_score')}: {finding.get('risk_score', 0) if isinstance(finding, dict) else 0}/100\n"
            f"{self.translator.text('matched_rules')}: {', '.join(self.translator.text(f'rule_{rule}') for rule in rules)}"
        )
        messagebox.showinfo(self.translator.text("inspect"), details)

    def _restore_selected(self) -> None:
        item = self._selected_quarantine_item()
        if item is None:
            return
        try:
            self.quarantine.restore(str(item["id"]))
            self.policy.audit("quarantine_restore_from_ui", item_id=item["id"])
            self._refresh_quarantine()
            messagebox.showinfo(self.translator.text("restore"), self.translator.text("restored_success"))
        except (OSError, KeyError, ValueError) as exc:
            messagebox.showerror(self.translator.text("error"), str(exc))

    def _delete_selected(self) -> None:
        item = self._selected_quarantine_item()
        if item is None or not messagebox.askyesno(self.translator.text("permanently_delete"), self.translator.text("confirm_delete")):
            return
        try:
            self.quarantine.delete(str(item["id"]))
            self._refresh_quarantine()
            messagebox.showinfo(self.translator.text("permanently_delete"), self.translator.text("deleted_success"))
        except (OSError, KeyError, ValueError) as exc:
            messagebox.showerror(self.translator.text("error"), str(exc))

    def _render_about(self) -> None:
        build_about(self.page_host, self.translator)

    def _save_allowlist(self) -> None:
        entries = [line.strip() for line in self.allowlist_text.get("1.0", "end").splitlines() if line.strip()]
        self.policy.update_setting("allowlist", entries)
        self.policy.audit("allowlist_updated", count=len(entries))
        messagebox.showinfo(self.translator.text("allowlist"), self.translator.text("allowlist_saved"))

    def _save_folders(self) -> None:
        entries = [line.strip() for line in self.folders_text.get("1.0", "end").splitlines() if line.strip()]
        self.policy.update_setting("protected_folders", entries)
        self.file_guard.stop()
        if self.policy.get_settings().get("shield_mode") != "paused":
            self.file_guard.start(entries)
        self.policy.audit("protected_folders_updated", folders=entries)
        messagebox.showinfo(self.translator.text("protected_folders"), self.translator.text("folder_saved"))

    def _monitor_callback(self, event: dict[str, Any]) -> None:
        if self._closed:
            return
        try:
            self.after(0, lambda: self._show_monitor_alert(event))
        except RuntimeError:
            return

    def _show_monitor_alert(self, event: dict[str, Any]) -> None:
        self.policy.audit("monitor_notification", details=event)
        self.sidebar_status_label.configure(text=self.translator.text("alert_process_risk" if event.get("finding") else "alert_network_connection"), fg=COLORS["amber"])

    def _start_tray(self) -> None:
        try:
            import pystray
            from PIL import Image, ImageDraw
        except ImportError:
            return
        image = Image.new("RGB", (64, 64), COLORS["panel"])
        draw = ImageDraw.Draw(image)
        draw.polygon([(32, 5), (54, 14), (52, 36), (32, 58), (12, 36), (10, 14)], fill="#10271F", outline=COLORS["emerald"])
        draw.line([(21, 31), (29, 39), (44, 23)], fill=COLORS["emerald"], width=4)
        self.tray_icon = pystray.Icon("ai-fbi", image, "AI FBI", self._make_tray_menu(pystray))
        self.tray_icon.run_detached()

    def _make_tray_menu(self, pystray: Any) -> Any:
        return pystray.Menu(
            pystray.MenuItem(self.translator.text("tray_show"), lambda _icon, _item: self.after(0, self.deiconify)),
            pystray.MenuItem(self.translator.text("tray_quit"), lambda _icon, _item: self.after(0, self._quit_from_tray)),
        )

    def _update_tray_menu(self) -> None:
        if self.tray_icon:
            try:
                import pystray
                self.tray_icon.menu = self._make_tray_menu(pystray)
            except ImportError:
                return

    def _quit_from_tray(self) -> None:
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None
        self._shutdown()

    def _close(self) -> None:
        if self.tray_icon:
            self.withdraw()
            return
        self._shutdown()

    def _shutdown(self) -> None:
        self._closed = True
        if self._scan_after_id:
            self.after_cancel(self._scan_after_id)
            self._scan_after_id = None
        self.process_monitor.stop()
        self.network_guard.stop()
        self.file_guard.stop()
        self.scheduled_scanner.stop()
        if self._metric_after_id:
            self.after_cancel(self._metric_after_id)
            self._metric_after_id = None
        self.destroy()


def run() -> None:
    AIFBIApp().mainloop()
