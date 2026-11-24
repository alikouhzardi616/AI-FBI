from __future__ import annotations

import threading
from typing import Any, Callable

from core.policy_engine import PolicyEngine

try:
    import psutil
except ImportError:  # Network monitoring is optional on mobile/minimal builds.
    psutil = None  # type: ignore[assignment]


class NetworkGuard:
    """Reports outbound sockets; it does not silently alter the host firewall."""

    def __init__(self, policy: PolicyEngine, callback: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.policy = policy
        self.callback = callback
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: set[tuple[int | None, str]] = set()

    @property
    def available(self) -> bool:
        return psutil is not None

    def snapshot(self) -> list[dict[str, Any]]:
        if psutil is None:
            return []
        results = []
        try:
            for connection in psutil.net_connections(kind="inet"):
                if not connection.raddr:
                    continue
                remote = f"{connection.raddr.ip}:{connection.raddr.port}"
                results.append({"pid": connection.pid, "remote": remote, "status": connection.status})
        except (psutil.Error, OSError, NotImplementedError):
            return results
        return results

    def start(self, interval: float = 8.0) -> None:
        if psutil is None or (self._thread and self._thread.is_alive()):
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, args=(interval,), daemon=True, name="ai-fbi-network-guard")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self, interval: float) -> None:
        while not self._stop.is_set():
            for connection in self.snapshot():
                identity = (connection["pid"], connection["remote"])
                if identity not in self._seen:
                    self._seen.add(identity)
                    event = {"event": "outbound_connection", **connection}
                    self.policy.audit("network_connection", **connection)
                    if self.callback:
                        self.callback(event)
            self._stop.wait(max(1.0, interval))
