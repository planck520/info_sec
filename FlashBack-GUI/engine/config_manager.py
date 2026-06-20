# coding: utf-8
"""Configuration persistence layer — reads/writes %APPDATA%/FlashBack/config.json."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any


class ConfigManager:
    """Thread-safe JSON-backed configuration store.

    Config file location: %APPDATA%/FlashBack/config.json
    Atomic writes via temp-file-and-rename.
    """

    DEFAULTS: dict[str, Any] = {
        "ida_path": "",
        "llm_enabled": True,
        "llm_provider": "deepseek",
        "llm_base_url": "https://api.deepseek.com",
        "llm_api_key": "",
        "llm_model": "deepseek-chat",
        "max_parallel": 4,
        "theme": "dark",
        "output_dir": "",
    }

    def __init__(self) -> None:
        appdata = os.environ.get("APPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Roaming"))
        self._config_dir = Path(appdata) / "FlashBack"
        self._config_file = self._config_dir / "config.json"
        self._lock = threading.Lock()
        self._cache: dict[str, Any] = dict(self.DEFAULTS)
        self._load()

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Merge disk state into defaults so newly-added keys survive upgrades."""
        try:
            if self._config_file.exists():
                disk = json.loads(self._config_file.read_text(encoding="utf-8"))
                for k in self.DEFAULTS:
                    if k in disk:
                        self._cache[k] = disk[k]
        except (json.JSONDecodeError, OSError):
            pass  # corrupt file → keep defaults

    def _save(self) -> None:
        """Atomic write: tmp file → rename."""
        self._config_dir.mkdir(parents=True, exist_ok=True)
        tmp = self._config_file.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(self._cache, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        tmp.replace(self._config_file)

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def get_all(self) -> dict[str, Any]:
        """Return a copy of all settings."""
        with self._lock:
            return dict(self._cache)

    def update(self, partial: dict[str, Any]) -> None:
        """Merge *partial* into current config and persist.

        Keys not present in DEFAULTS are silently ignored.
        ``None`` values are treated as "delete" (reset to default).
        """
        with self._lock:
            for k in self.DEFAULTS:
                if k in partial:
                    val = partial[k]
                    if val is None:
                        self._cache[k] = self.DEFAULTS[k]
                    else:
                        self._cache[k] = val
            self._save()

    def get(self, key: str) -> Any:
        """Return a single config value."""
        with self._lock:
            return self._cache.get(key, self.DEFAULTS.get(key))


# ------------------------------------------------------------------
# module-level singleton
# ------------------------------------------------------------------

_instance: ConfigManager | None = None


def get_config() -> ConfigManager:
    global _instance
    if _instance is None:
        _instance = ConfigManager()
    return _instance
