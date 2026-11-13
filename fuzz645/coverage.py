"""Coverage bookkeeping shared by all workers.

Edge ids are assigned once by the worker at startup, so the same id means the
same ``trace-pc-guard`` site in every process of a campaign (same binary).
That makes the global map a plain bitmap and lets the corpus selection decide
"is this input interesting?" with a cheap set difference.
"""
from __future__ import annotations

import threading
from typing import Iterable, Set


class CoverageMap:
    def __init__(self, guard_count: int = 1 << 20):
        self.slots = bytearray(guard_count)
        self.guard_count = guard_count
        self.count = 0
        self.lock = threading.Lock()
        self.history = []          # (timestamp, total_edges) for the UI chart

    def add(self, edges: Iterable[int]) -> bool:
        """Merge edges; return True if at least one was new."""
        new = False
        with self.lock:
            slots = self.slots
            for e in edges:
                if e < self.guard_count and not slots[e]:
                    slots[e] = 1
                    self.count += 1
                    new = True
        return new

    def novel(self, edges: Iterable[int]) -> bool:
        with self.lock:
            return any(not self.slots[e] for e in edges if e < self.guard_count)

    def snapshot(self) -> Set[int]:
        with self.lock:
            return {i for i, v in enumerate(self.slots) if v}

    def seed_from(self, edges: Iterable[int]) -> None:
        self.add(edges)
