# -*- coding: utf-8 -*-
"""Tiny LFU-ish cache used by backward traversal (with stats)."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


class TinyCache:
    """A tiny frequency-based eviction cache.

    Designed to avoid importing external deps while keeping behavior explicit.
    """

    def __init__(self, max_size: int = 100000) -> None:
        self._store: Dict[Tuple[str, int], Any] = {}
        self._freq: Dict[Tuple[str, int], int] = {}
        self.max_size = max_size
        self.hits = 0
        self.misses = 0

    def get(self, key) -> Optional[Any]:
        if key in self._store:
            self.hits += 1
            self._freq[key] = self._freq.get(key, 0) + 1
            return self._store[key]
        self.misses += 1
        return None

    def set(self, key, value) -> None:
        if key not in self._store and len(self._store) >= self.max_size:
            # Evict least frequently used key
            victim = min(self._freq.items(), key=lambda kv: kv[1])[0]
            self._store.pop(victim, None)
            self._freq.pop(victim, None)
        self._store[key] = value
        self._freq[key] = self._freq.get(key, 0) + 1

    def stats(self) -> dict:
        total = self.hits + self.misses
        rate = (self.hits / total * 100.0) if total else 0.0
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": rate,
            "current_size": len(self._store),
            "max_size": self.max_size,
        }