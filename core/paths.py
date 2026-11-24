from __future__ import annotations

import os
import sys
from pathlib import Path


def application_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resource_path(relative: str) -> Path:
    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        return Path(bundled) / relative
    return application_root() / relative


def user_data_root() -> Path:
    override = os.environ.get("AI_FBI_HOME")
    if override:
        return Path(override).expanduser().resolve()
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "AI FBI"


def ensure_data_directories(root: Path | None = None) -> dict[str, Path]:
    root = (root or user_data_root()).expanduser().resolve()
    paths = {
        "root": root,
        "config": root / "config",
        "logs": root / "logs",
        "quarantine": root / "quarantine",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths
