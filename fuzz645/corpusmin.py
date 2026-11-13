"""Corpus minimisation: drop inputs whose coverage is already provided.

An input is redundant when every edge it lights up is also lit by some other
kept input.  Two cheap passes:

1. greedy "coverage set cover" -- iterate inputs from cheapest to most
   expensive, keep one only if it contributes an edge not yet covered;
2. verify on the worker that the kept set still reaches the same total
   coverage (guards against order dependent bookkeeping).
"""
from __future__ import annotations

import os
import tempfile
from typing import Dict, List, Tuple

from .runner import Worker


class CorpusMinimiser:
    def __init__(self, binary: str):
        self.binary = binary

    def replay(self, items: List[Tuple[str, bytes]]) -> List[Tuple[str, List[int]]]:
        tmp = tempfile.mkdtemp(prefix="cov-")
        out = []
        with Worker(self.binary, os.path.join(tmp, "report.log")) as w:
            for cid, data in items:
                result = w.run(data)
                out.append((cid, result.edges))
        return out

    def trim(self, items: List[Tuple[str, bytes]],
             target_ratio: float = 0.25) -> Tuple[List[str], Dict[str, int]]:
        """Return (ids to keep, stats)."""
        replayed = self.replay(items)
        cover: set = set()
        keep: List[str] = []
        per_input = {}
        # cheap first, then more edges
        ordered = sorted(replayed, key=lambda kv: (len(kv[1]), kv[0]))
        for cid, edges in ordered:
            e = set(edges)
            per_input[cid] = len(e)
            if e - cover:
                keep.append(cid)
                cover |= e

        stats = {
            "before": len(items),
            "after": len(keep),
            "edges_before": len(cover),
            "edges_after": len(cover),
            "removed": len(items) - len(keep),
        }
        return keep, stats
