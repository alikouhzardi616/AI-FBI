# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

hiddenimports = collect_submodules("pystray") + collect_submodules("tkinterdnd2") + [
    "core.file_guard",
    "core.licensing",
    "core.network_guard",
    "core.paths",
    "core.policy_engine",
    "core.process_monitor",
    "core.quarantine",
    "core.report_exporter",
    "core.scanner",
    "core.scheduled_scanner",
    "core.self_protection",
    "ui.about_view",
    "ui.desktop_app",
    "ui.localization",
]

a = Analysis(
    ["main.py"],
    pathex=[SPECPATH],
    binaries=[],
    datas=[
        ("config/donate.json", "config"),
        ("i18n/translations.json", "i18n"),
        ("app_metadata.json", "."),
        ("assets/ai_fbi.png", "assets"),
        ("assets/ai_fbi.ico", "assets"),
        ("assets/solana_donate_qr.png", "assets"),
        ] + collect_data_files("tkinterdnd2"),
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["kivy"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="AI FBI",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon="assets/ai_fbi.ico",
    version="installer/AI_FBI_version.txt",
)
