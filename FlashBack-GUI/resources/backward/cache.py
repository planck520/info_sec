# -*- coding: utf-8 -*-
"""Tiny LRU cache used by backward traversal (with stats).

This optimized version replaces LFU with LRU and reduces eviction overhead from O(n) to O(1).
"""
from __future__ import annotations

from collections import OrderedDict
from typing import Any, Optional


class TinyCache:
    """A tiny LRU (Least Recently Used) eviction cache.

    OrderedDict provides O(1) get/set/evict operations and is cheaper than LFU.
    """

    def __init__(self, max_size: int = 100000) -> None:
        self._store: OrderedDict = OrderedDict()
        self.max_size = max_size
        self.hits = 0
        self.misses = 0

    def get(self, key) -> Optional[Any]:
        if key in self._store:
            self.hits += 1
            # LRU: move to the end to mark recent use
            self._store.move_to_end(key)
            return self._store[key]
        self.misses += 1
        return None

    def set(self, key, value) -> None:
        if key in self._store:
            # Existing key: update the value and move it to the end
            self._store.move_to_end(key)
            self._store[key] = value
        else:
            # New key
            if len(self._store) >= self.max_size:
                # Evict the least recently used item (the first entry) in O(1)
                self._store.popitem(last=False)
            self._store[key] = value

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
