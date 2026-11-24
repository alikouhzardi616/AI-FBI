from __future__ import annotations

import threading
from typing import Any, Callable

from core.policy_engine import PolicyEngine

try:
    import psutil
except ImportError:  # Android and minimal installs remain usable.
    psutil = None  # type: ignore[assignment]


class ProcessMonitor:
    ACTIONS = {"ALERT", "SUSPEND", "TERMINATE", "ALLOWLIST"}

    def __init__(self, policy: PolicyEngine, callback: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.policy = policy
        self.callback = callback
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._reported: set[tuple[int, str]] = set()

    @property
    def available(self) -> bool:
        return psutil is not None

    def snapshot(self) -> list[dict[str, Any]]:
        if psutil is None:
            return []
        processes = []
        try:
            iterator = psutil.process_iter(["pid", "name", "cmdline", "username"])
            for proc in iterator:
                try:
                    info = proc.info
                    processes.append({
                        "pid": info.get("pid"),
                        "name": info.get("name") or "",
                        "command_line": " ".join(info.get("cmdline") or []),
                        "username": info.get("username") or "",
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.Error, OSError, NotImplementedError):
            return processes
        return processes

    def act(self, pid: int, action: str) -> None:
        action = action.upper()
        if action not in self.ACTIONS:
            raise ValueError(f"Unsupported process action: {action}")
        if action == "ALLOWLIST":
            self.policy.add_allowlist(str(pid))
            self.policy.audit("process_allowlisted", pid=pid)
            return
        if action == "ALERT":
            self.policy.audit("process_alert", pid=pid)
            return
        if psutil is None:
            raise RuntimeError("Process actions require psutil on a supported desktop platform")
        try:
            process = psutil.Process(pid)
            if action == "SUSPEND":
                process.suspend()
            else:
                process.terminate()
            self.policy.audit("process_action", pid=pid, action=action)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            self.policy.audit("process_action_failed", pid=pid, action=action, error=type(exc).__name__)
            raise

    def start(self, interval: float = 5.0) -> None:
        if psutil is None or (self._thread and self._thread.is_alive()):
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, args=(interval,), daemon=True, name="ai-fbi-process-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self, interval: float) -> None:
        while not self._stop.is_set():
            for process in self.snapshot():
                cmdline = process["command_line"]
                pid = process["pid"]
                if not cmdline or pid is None or self.policy.is_allowed(str(pid)):
                    continue
                from core.scanner import Scanner
                finding = Scanner(self.policy.get_custom_rules()).scan_text(
                    cmdline,
                    str(pid),
                    self.policy.get_security_profile(),
                )
                strict = self.policy.get_settings().get("shield_mode") == "strict"
                if finding.risk_score >= (25 if strict else 40):
                    identity = (int(pid), cmdline)
                    if identity in self._reported:
                        continue
                    self._reported.add(identity)
                    summary = {key: process[key] for key in ("pid", "name", "username")}
                    event = {"process": summary, "finding": finding.to_dict()}
                    self.policy.audit("process_risk", **event)
                    if self.callback:
                        self.callback(event)
            self._stop.wait(max(0.5, interval))
