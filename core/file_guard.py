from __future__ import annotations

import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from core.policy_engine import PolicyEngine

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEventHandler = object  # type: ignore[assignment,misc]
    Observer = None


class FileGuard:
    def __init__(self, policy: PolicyEngine, sensitive_patterns: list[str] | None = None) -> None:
        self.policy = policy
        self.sensitive_patterns = sensitive_patterns or [".env", "*.key", "*.pem", "credentials*"]
        self._observers: list[Any] = []
        self._changes: deque[float] = deque()
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return Observer is not None

    def start(self, folders: list[Path | str]) -> bool:
        if Observer is None:
            return False
        for folder in folders:
            path = Path(folder).expanduser()
            if not path.is_dir():
                continue
            observer = Observer()
            observer.schedule(_ChangeHandler(self), str(path), recursive=True)
            observer.start()
            self._observers.append(observer)
        return bool(self._observers)

    def stop(self) -> None:
        for observer in self._observers:
            observer.stop()
        for observer in self._observers:
            observer.join(timeout=2)
        self._observers.clear()

    def _on_change(self, event: Any) -> None:
        if getattr(event, "is_directory", False):
            return
        path = Path(getattr(event, "src_path", ""))
        matched = any(path.name == pattern or path.match(pattern) for pattern in self.sensitive_patterns)
        now = time.monotonic()
        with self._lock:
            self._changes.append(now)
            while self._changes and now - self._changes[0] > 10:
                self._changes.popleft()
            mass_change = len(self._changes) >= 20
        risk = 65 if matched else 40 if mass_change else 10
        self.policy.audit(
            "file_change",
            path=str(path),
            change=getattr(event, "event_type", "unknown"),
            sensitive=matched,
            mass_change=mass_change,
            risk_score=risk,
        )


class _ChangeHandler(FileSystemEventHandler):
    def __init__(self, guard: FileGuard) -> None:
        self.guard = guard

    def on_any_event(self, event: Any) -> None:
        if getattr(event, "event_type", "") in {"created", "modified", "deleted", "moved"}:
            self.guard._on_change(event)
