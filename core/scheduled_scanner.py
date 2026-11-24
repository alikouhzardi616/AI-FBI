from __future__ import annotations

import threading
from pathlib import Path

from core.policy_engine import PolicyEngine
from core.scanner import Scanner


class ScheduledScanner:
    """Runs configured local scans at an interval while the desktop app is running."""

    def __init__(self, policy: PolicyEngine) -> None:
        self.policy = policy
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, target: Path | str, interval_hours: int) -> None:
        path = Path(target).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)
        if not 1 <= interval_hours <= 168:
            raise ValueError("Scheduled scan interval must be between 1 and 168 hours")
        self.stop()
        if self.running:
            raise ValueError("The previous scheduled scan is still finishing")
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            args=(path, interval_hours * 3600),
            daemon=True,
            name="ai-fbi-scheduled-scan",
        )
        self._thread.start()
        self.policy.audit("scheduled_scan_enabled", target=str(path), interval_hours=interval_hours)

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread:
            if thread.is_alive():
                thread.join(timeout=3)
            if not thread.is_alive():
                self._thread = None
                self.policy.audit("scheduled_scan_disabled")

    def _run(self, target: Path, interval_seconds: int) -> None:
        while not self._stop.wait(interval_seconds):
            try:
                profile = self.policy.get_security_profile()
                scanner = Scanner(self.policy.get_custom_rules())
                findings = scanner.scan_path(target, profile)
            except (OSError, ValueError) as exc:
                self.policy.audit("scheduled_scan_failed", target=str(target), error=str(exc))
                continue
            risks = [item for item in findings if item.risk_score > 0]
            self.policy.audit(
                "scheduled_scan_complete",
                target=str(target),
                scanned_count=len(findings),
                finding_count=len(risks),
                highest_risk=max((item.risk_score for item in risks), default=0),
                matched_rules=sorted({rule for item in risks for rule in item.matched_rules}),
            )
