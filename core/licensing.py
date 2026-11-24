from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from core.policy_engine import PolicyEngine


_KEY_PREFIX = "AIFBI-PRO1-"
_CHECKSUM_CONTEXT = b"AI FBI offline license checksum v1:"


class LicenseManager:
    """Offline edition state with an integrity-check activation format and demo mode.

    The checksum detects malformed keys; it is not a cryptographic signature and
    must not be treated as tamper-resistant commercial entitlement enforcement.
    """

    def __init__(self, data_root: Path, policy: PolicyEngine) -> None:
        self.path = data_root / "config" / "license.json"
        self.policy = policy
        self._lock = threading.RLock()
        self._state: dict[str, Any] = {}
        self._load()

    @staticmethod
    def build_checksummed_activation_key(customer: str, expires: str | None = None) -> str:
        if not customer.strip():
            raise ValueError("A customer identifier is required")
        claims: dict[str, Any] = {"product": "AI FBI", "edition": "pro", "customer": customer.strip()}
        if expires:
            date.fromisoformat(expires)
            claims["expires"] = expires
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        checksum = hashlib.sha256(_CHECKSUM_CONTEXT + payload).hexdigest()
        return f"{_KEY_PREFIX}{encoded}.{checksum}"

    def activate(self, activation_key: str) -> dict[str, Any]:
        if not activation_key.startswith(_KEY_PREFIX):
            raise ValueError("Activation key format is not recognized")
        try:
            encoded, supplied_checksum = activation_key[len(_KEY_PREFIX):].split(".", 1)
            payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            claims = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Activation key payload is malformed") from exc
        expected = hashlib.sha256(_CHECKSUM_CONTEXT + payload).hexdigest()
        if not hmac.compare_digest(supplied_checksum.lower(), expected):
            raise ValueError("Activation key checksum does not match")
        if not isinstance(claims, dict) or claims.get("product") != "AI FBI" or claims.get("edition") != "pro":
            raise ValueError("Activation key is not for AI FBI Pro")
        customer = claims.get("customer")
        if not isinstance(customer, str) or not customer.strip():
            raise ValueError("Activation key does not identify a customer")
        expiry = claims.get("expires")
        if expiry is not None:
            try:
                if date.fromisoformat(str(expiry)) < datetime.now(timezone.utc).date():
                    raise ValueError("Activation key has expired")
            except ValueError as exc:
                if str(exc) == "Activation key has expired":
                    raise
                raise ValueError("Activation key expiry date is invalid") from exc
        with self._lock:
            self._state = {
                "edition": "pro",
                "license_type": "activation",
                "activated_at": datetime.now(timezone.utc).isoformat(),
                "claims": claims,
            }
            self._write()
        self.policy.audit("license_activated", license_type="activation")
        return self.status()

    def set_demo_mode(self, enabled: bool) -> dict[str, Any]:
        with self._lock:
            if enabled:
                self._state = {
                    "edition": "pro",
                    "license_type": "demo",
                    "demo_enabled_at": datetime.now(timezone.utc).isoformat(),
                }
            else:
                self._state = {"edition": "community", "license_type": "community"}
            self._write()
        self.policy.audit("license_demo_changed", enabled=enabled)
        return self.status()

    def is_pro(self) -> bool:
        state = self._snapshot()
        if state.get("edition") != "pro":
            return False
        if state.get("license_type") == "demo":
            return True
        claims = state.get("claims", {})
        expiry = claims.get("expires") if isinstance(claims, dict) else None
        if not expiry:
            return state.get("license_type") == "activation"
        try:
            return date.fromisoformat(str(expiry)) >= datetime.now(timezone.utc).date()
        except ValueError:
            return False

    def status(self) -> dict[str, Any]:
        state = self._snapshot()
        active = self.is_pro()
        claims = state.get("claims", {})
        return {
            "edition": "pro" if active else "community",
            "license_type": state.get("license_type", "community") if active else "community",
            "customer": claims.get("customer", "") if isinstance(claims, dict) else "",
            "expires": claims.get("expires") if isinstance(claims, dict) else None,
        }

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("License state must be a JSON object")
            if data.get("edition") not in {"community", "pro"}:
                raise ValueError("License edition is invalid")
            if data.get("edition") == "pro" and data.get("license_type") == "activation":
                claims = data.get("claims")
                if not isinstance(claims, dict) or claims.get("product") != "AI FBI" or claims.get("edition") != "pro":
                    raise ValueError("Stored activation claims are invalid")
                customer = claims.get("customer")
                if not isinstance(customer, str) or not customer.strip():
                    raise ValueError("Stored activation customer is invalid")
                expiry = claims.get("expires")
                if expiry is not None:
                    date.fromisoformat(str(expiry))
            elif data.get("edition") == "pro" and data.get("license_type") != "demo":
                raise ValueError("Pro license type is invalid")
            self._state = data
        except FileNotFoundError:
            self._state = {"edition": "community", "license_type": "community"}
            self._write()
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            self._state = {"edition": "community", "license_type": "community"}
            self.policy.audit("license_state_invalid", error=type(exc).__name__)

    def _snapshot(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._state))

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(".json.tmp")
        temp.write_text(json.dumps(self._state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temp.replace(self.path)
