from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.paths import resource_path


LANGUAGES = ("en-US", "fa-IR", "ru-RU", "zh-CN")


class Translator:
    def __init__(self, language: str = "en-US", path: Path | None = None) -> None:
        translations_path = path or resource_path("i18n/translations.json")
        self._data: dict[str, dict[str, Any]] = json.loads(translations_path.read_text(encoding="utf-8"))
        missing = [code for code in LANGUAGES if code not in self._data]
        if missing:
            raise ValueError(f"Missing translation languages: {', '.join(missing)}")
        self.language = language if language in LANGUAGES else "en-US"

    def set_language(self, language: str) -> None:
        if language not in LANGUAGES:
            raise ValueError(f"Unsupported language: {language}")
        self.language = language

    @property
    def is_rtl(self) -> bool:
        return self.language == "fa-IR"

    def text(self, key: str) -> str:
        value = self._data[self.language].get(key, self._data["en-US"].get(key, key))
        return str(value)

    def capability_keys(self) -> list[str]:
        return [key for key in self._data[self.language] if key.startswith("capability_")]

    def language_label(self, code: str) -> str:
        key = {"en-US": "lang_en", "fa-IR": "lang_fa", "ru-RU": "lang_ru", "zh-CN": "lang_zh"}.get(code)
        if key is None:
            raise ValueError(f"Unsupported language: {code}")
        return self.text(key)

    def language_code(self, label: str) -> str:
        for code in LANGUAGES:
            if self.language_label(code) == label:
                return code
        raise ValueError(f"Unsupported language label: {label}")
