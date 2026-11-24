from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class PolicyEngine:
    """Local policy/settings store and append-only structured audit writer."""

    SECURITY_PROFILE_IDS = {"developer_safe", "balanced_guard", "strict_lockdown"}

    def __init__(self, data_root: Path) -> None:
        self.data_root = data_root
        self.config_dir = data_root / "config"
        self.logs_dir = data_root / "logs"
        self.settings_path = self.config_dir / "settings.json"
        self.policy_path = self.config_dir / "policies.json"
        self.audit_path = self.logs_dir / "audit.jsonl"
        self._lock = threading.RLock()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self._settings = self._read_json(
            self.settings_path,
            {
                "language": "en-US",
                "shield_mode": "active",
                "security_profile": "balanced_guard",
                "allowlist": [],
                "protected_folders": [],
            },
        )
        self._policies = self._read_json(
            self.policy_path,
            {
                "sensitive_patterns": [".env", "*.key", "*.pem", "credentials*", "*.p12", "*.pfx"],
                "custom_rules": [],
            },
        )
        self._settings.setdefault("security_profile", "balanced_guard")
        self._policies.setdefault("custom_rules", [])
        self._write_json(self.settings_path, self._settings)
        self._write_json(self.policy_path, self._policies)

    @staticmethod
    def _read_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError(f"Configuration must contain a JSON object: {path}")
            return data
        except FileNotFoundError:
            return default.copy()
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON configuration at {path}: {exc}") from exc

    @staticmethod
    def _write_json(path: Path, value: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(path.suffix + ".tmp")
        temp_path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temp_path.replace(path)

    def get_settings(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._settings))

    def update_setting(self, key: str, value: Any) -> None:
        with self._lock:
            self._settings[key] = value
            self._write_json(self.settings_path, self._settings)

    def get_security_profile(self) -> str:
        profile = self.get_settings().get("security_profile", "balanced_guard")
        return profile if profile in self.SECURITY_PROFILE_IDS else "balanced_guard"

    def set_security_profile(self, profile: str) -> None:
        if profile not in self.SECURITY_PROFILE_IDS:
            raise ValueError(f"Unknown security profile: {profile}")
        self.update_setting("security_profile", profile)

    def get_custom_rules(self) -> list[str]:
        with self._lock:
            rules = self._policies.get("custom_rules", [])
            if not isinstance(rules, list):
                raise ValueError("Configured custom rules must be a list")
            return [item for item in rules if isinstance(item, str) and 2 <= len(item.strip()) <= 120]

    def set_custom_rules(self, rules: list[str]) -> None:
        normalized = [rule.strip() for rule in rules if rule.strip()]
        if any(len(rule) < 2 or len(rule) > 120 for rule in normalized):
            raise ValueError("Custom literal rules must be 2-120 characters")
        with self._lock:
            self._policies["custom_rules"] = normalized[:100]
            self._write_json(self.policy_path, self._policies)

    def is_allowed(self, identifier: str) -> bool:
        with self._lock:
            entries = self._settings.get("allowlist", [])
            return identifier in entries if isinstance(entries, list) else False

    def add_allowlist(self, identifier: str) -> None:
        with self._lock:
            entries = self._settings.setdefault("allowlist", [])
            if not isinstance(entries, list):
                raise ValueError("The configured allowlist is not a list")
            if identifier not in entries:
                entries.append(identifier)
                self._write_json(self.settings_path, self._settings)

    def audit(self, event: str, **details: Any) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **details,
        }
        with self._lock:
            with self.audit_path.open("a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    def read_audit(self, limit: int = 500) -> list[dict[str, Any]]:
        if limit < 1:
            return []
        with self._lock:
            if not self.audit_path.exists():
                return []
            lines = self.audit_path.read_text(encoding="utf-8", errors="replace").splitlines()
        records: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    records.append(item)
            except json.JSONDecodeError:
                continue
        return records
