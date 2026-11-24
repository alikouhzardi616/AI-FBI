from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable

from core.policy_engine import PolicyEngine


class SelfProtection:
    """Best-effort integrity checks for local policy/config files; not OS tamper protection."""

    def __init__(self, data_root: Path, policy: PolicyEngine) -> None:
        self.data_root = data_root
        self.policy = policy
        self.baseline_path = data_root / "config" / "integrity.json"

    def verify_startup(self, protected_files: Iterable[Path] | None = None) -> list[str]:
        files = list(protected_files or [self.data_root / "config" / "policies.json"])
        current = {str(path): self._hash(path) for path in files if path.is_file()}
        if not self.baseline_path.exists():
            self._write(current)
            return []
        try:
            baseline = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.policy.audit("self_protection_integrity_error", error=type(exc).__name__)
            return ["integrity_manifest_unreadable"]
        changed = [path for path, digest in current.items() if baseline.get(path) != digest]
        missing = [path for path in baseline if path not in current]
        if changed or missing:
            self.policy.audit("self_protection_tamper_indicator", changed=changed, missing=missing)
        return changed + missing

    def refresh_baseline(self, protected_files: Iterable[Path] | None = None) -> None:
        files = list(protected_files or [self.data_root / "config" / "policies.json"])
        self._write({str(path): self._hash(path) for path in files if path.is_file()})

    @staticmethod
    def _hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as file_obj:
            for chunk in iter(lambda: file_obj.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _write(self, data: dict[str, str]) -> None:
        temp = self.baseline_path.with_suffix(".json.tmp")
        temp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        temp.replace(self.baseline_path)
