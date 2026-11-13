"""Regression: re-run every bucketed reproducer against a rebuilt target.

The fixed build is produced by ``build.sh --fixed``; each bucket keeps its
minimised reproducer, which is replayed on the fixed binary.  A bucket whose
reproducer no longer crashes is marked ``fixed``; one that still crashes keeps
(or returns to) ``open`` with the new signature attached.  If the new crash
maps to a *different* bucket, the original bucket is marked ``fixed`` and the
observation is reported as a separate finding (the fix moved the fault).
"""
from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass
from typing import List, Optional

from . import buckets as bucket_mod
from .runner import Worker
from .store import Store


@dataclass
class RegressionResult:
    bucket_id: str
    label: str
    status: str                 # fixed | still-open | changed
    new_signature: Optional[str] = None
    new_bucket: Optional[str] = None
    detail: str = ""


def run_regression(store: Store, fixed_binary: str,
                   report_dir: Optional[str] = None) -> List[RegressionResult]:
    report_dir = report_dir or tempfile.mkdtemp(prefix="reg-")
    os.makedirs(report_dir, exist_ok=True)
    results: List[RegressionResult] = []
    with Worker(fixed_binary, os.path.join(report_dir, "regression.log")) as w:
        for b in store.buckets():

            repro = os.path.join(store.root, "crashes", b["id"], "minimised")
            # strip stale state from previous regression runs before the replay
            row_path = repro if os.path.exists(repro) else None
            if row_path is None:
                crashes = store.crashes(b["id"])
                if not crashes:
                    results.append(RegressionResult(
                        b["id"], b["label"], "still-open",
                        detail="no reproducer stored"))
                    continue
                data = store.crash_input(crashes[0])
                path_note = crashes[0]["input_path"]
            else:
                with open(repro, "rb") as fh:
                    data = fh.read()
                path_note = os.path.relpath(repro, store.root)

            r = w.run(data)
            if not r.crashed:
                store.set_bucket_status(b["id"], "fixed", {
                    "at": time.time(), "binary": fixed_binary,
                    "reproducer": path_note, "crashes": 0,
                })
                results.append(RegressionResult(b["id"], b["label"], "fixed",
                                                detail=path_note))
                continue

            sig = bucket_mod.classify(r.report)
            if sig.key == b["id"]:
                store.set_bucket_status(b["id"], "open", {
                    "at": time.time(), "binary": fixed_binary,
                    "reproducer": path_note, "crashes": 1,
                })
                results.append(RegressionResult(b["id"], b["label"], "still-open",
                                                new_signature=sig.label,
                                                detail=path_note))
            else:
                # the fault moved: close this bucket, report the new site
                store.set_bucket_status(b["id"], "fixed", {
                    "at": time.time(), "binary": fixed_binary,
                    "reproducer": path_note, "note": "crash moved to %s" % sig.label,
                })
                results.append(RegressionResult(b["id"], b["label"], "changed",
                                                new_signature=sig.label,
                                                new_bucket=sig.key,
                                                detail=path_note))
    store.set_meta("regression_final", True)
    store.set_meta("last_regression", {
        "at": time.time(), "binary": fixed_binary,
        "fixed": sum(1 for r in results if r.status == "fixed"),
        "open": sum(1 for r in results if r.status != "fixed"),
    })
    store.event("regression", "replayed %d reproducers against %s"
                % (len(results), fixed_binary))
    return results
