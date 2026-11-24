from __future__ import annotations

import json
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.policy_engine import PolicyEngine


class Quarantine:
    def __init__(self, directory: Path, policy: PolicyEngine) -> None:
        self.directory = directory
        self.manifest_path = directory / "quarantine_manifest.json"
        self.policy = policy
        self._lock = threading.RLock()
        self.directory.mkdir(parents=True, exist_ok=True)
        if not self.manifest_path.exists():
            self._write_manifest({})

    def list_items(self) -> list[dict[str, Any]]:
        with self._lock:
            manifest = self._read_manifest()
            return list(manifest.values())

    def quarantine_path(self, source: Path | str, finding: dict[str, Any] | None = None) -> str:
        path = Path(source).expanduser().resolve(strict=True)
        if Path(source).expanduser().is_symlink():
            raise ValueError("Symbolic links cannot be quarantined")
        if not path.is_file():
            raise ValueError("Only individual files can be quarantined")
        if path == self.directory.resolve() or self.directory.resolve() in path.parents:
            raise ValueError("The quarantine directory cannot be quarantined")
        item_id = uuid.uuid4().hex
        stored_name = f"{item_id}_{path.name}"
        stored_path = self.directory / stored_name
        with self._lock:
            shutil.move(str(path), str(stored_path))
            try:
                manifest = self._read_manifest()
                manifest[item_id] = {
                    "id": item_id,
                    "original_path": str(path),
                    "stored_name": stored_name,
                    "quarantined_at": datetime.now(timezone.utc).isoformat(),
                    "finding": finding or {},
                }
                self._write_manifest(manifest)
            except (OSError, ValueError):
                shutil.move(str(stored_path), str(path))
                raise
        self.policy.audit("quarantine", item_id=item_id, original_path=str(path), finding=finding or {})
        return item_id

    def restore(self, item_id: str, destination: Path | str | None = None) -> Path:
        with self._lock:
            manifest = self._read_manifest()
            entry = manifest.get(item_id)
            if not entry:
                raise KeyError(item_id)
            source = self._stored_path(entry)
            target = Path(destination).expanduser() if destination else Path(entry["original_path"])
            target = target.resolve()
            if target.exists():
                raise FileExistsError(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(target))
            del manifest[item_id]
            self._write_manifest(manifest)
        self.policy.audit("quarantine_restore", item_id=item_id, destination=str(target))
        return target

    def delete(self, item_id: str) -> None:
        with self._lock:
            manifest = self._read_manifest()
            entry = manifest.get(item_id)
            if not entry:
                raise KeyError(item_id)
            stored = self._stored_path(entry)
            stored.unlink(missing_ok=True)
            del manifest[item_id]
            self._write_manifest(manifest)
        self.policy.audit("quarantine_delete", item_id=item_id)

    def _stored_path(self, entry: dict[str, Any]) -> Path:
        name = entry.get("stored_name")
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError("Invalid quarantine manifest entry")
        path = (self.directory / name).resolve()
        if path.parent != self.directory.resolve():
            raise ValueError("Quarantine manifest path escapes its directory")
        return path

    def _read_manifest(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Quarantine manifest must contain an object")
            return data
        except FileNotFoundError:
            return {}

    def _write_manifest(self, data: dict[str, Any]) -> None:
        temp = self.manifest_path.with_suffix(".json.tmp")
        temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temp.replace(self.manifest_path)
