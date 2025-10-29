"""
Very small JSON cache with TTL.
"""
import json, os, time
from typing import Callable, Any

class Cache:
    def __init__(self, path: str, ttl: int = 86400):
        self.path = path
        self.ttl = ttl
        self.data = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except Exception:
                self.data = {}

    def get(self, key: str):
        item = self.data.get(key)
        if not item:
            return None
        if time.time() - item["ts"] > self.ttl:
            del self.data[key]
            return None
        return item["val"]

    def set(self, key: str, val: Any):
        self.data[key] = {"ts": time.time(), "val": val}

    def get_or_set(self, key: str, fn: Callable[[], Any]):
        v = self.get(key)
        if v is not None:
            return v
        v = fn()
        self.set(key, v)
        return v

    def flush(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
