"""Coverage guided campaign orchestrator.

One coordinator process owns the coverage map and the corpus; N persistent
worker processes execute inputs.  Workers that die (ASan reported a fault)
are restarted automatically and the crash is normalised into a bucket.

Corpus policy
-------------
* every seed is executed once and its coverage merged;
* a mutated input is kept when it lights up at least one edge never seen
  before (AFL style "interesting" rule), or when it crashes;
* each kept input is tagged with its parent and a depth, which the corpus
  minimiser later uses for its "prefer shallow, small, rare" ranking.
"""
from __future__ import annotations

import os
import queue
import random
import signal
import threading
import time
from dataclasses import dataclass
from typing import List, Optional

from . import buckets as bucket_mod
from .coverage import CoverageMap
from .mutate import mutate, mutate_traced
from .runner import Worker
from .store import Store


@dataclass
class CampaignConfig:
    binary: str
    workdir: str
    workers: int = 8
    duration: float = 1800.0
    seed_corpus: str = "corpus"
    max_len: int = 4096
    seed: int = 645
    sample_interval: float = 2.0
    refresh_corpus_every: float = 5.0
    minimize_every: float = 0.0     # 0 = only on demand
    minimize_ratio: float = 0.25    # corpus trim target when auto minimising
    restart_after: int = 1          # restarts before the rate watchdog trips


@dataclass
class WorkerStat:
    worker_id: int
    execs: int = 0
    crashes: int = 0
    restarts: int = 0
    errors: int = 0
    alive: bool = True


class Campaign:
    def __init__(self, cfg: CampaignConfig):
        self.cfg = cfg
        self.store = Store(cfg.workdir)
        self.cov = CoverageMap(1 << 20)
        self.buckets = bucket_mod.BucketRegistry()
        self.stats = [WorkerStat(i) for i in range(cfg.workers)]
        self.execs = 0
        self.crashes = 0
        self.started = 0.0
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self._corpus: List[dict] = []
        self._corpus_lock = threading.Lock()
        self._corpus_version = 0
        self.samples: List[dict] = []
        self._thread: Optional[threading.Thread] = None
        self._monitor: Optional[threading.Thread] = None
        self._last_rate = 0.0
        self._report_dir = os.path.join(cfg.workdir, "reports")
        os.makedirs(self._report_dir, exist_ok=True)
        self.running = False
        self.finished_at: Optional[float] = None
        # instrumentation for the reports page
        self.restart_times: List[float] = []
        self.worker_errors = 0
        # rolling crash-recent rate; the mutator dampens the structural
        # operator that is currently producing the most redundant crashes
        self._recent_ops = []
        self._op_crash_rate: dict = {}
        self._minimise_queue: "queue.Queue" = None

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.started = time.time()
        self.stop_event.clear()
        self.store.set_meta("config", {
            "binary": self.cfg.binary, "workers": self.cfg.workers,
            "duration": self.cfg.duration, "seed": self.cfg.seed,
        })
        self.store.set_meta("started", self.started)
        self._load_seed_corpus()
        self._minimise_queue = queue.Queue()
        self._minimise_thread = threading.Thread(
            target=self._minimise_loop, name="minimise", daemon=True)
        self._minimise_thread.start()
        self._thread = threading.Thread(target=self._run, name="campaign", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def _run(self) -> None:
        threads = [threading.Thread(target=self._worker_loop, args=(i,),
                                    name="fuzz-%d" % i, daemon=True)
                   for i in range(self.cfg.workers)]
        for t in threads:
            t.start()
        monitor = threading.Thread(target=self._monitor_loop, name="monitor", daemon=True)
        monitor.start()
        deadline = self.started + self.cfg.duration
        try:
            while not self.stop_event.is_set():
                if time.time() >= deadline:
                    break
                self.stop_event.wait(0.25)
        finally:
            self.stop_event.set()
            for t in threads:
                t.join(timeout=15)
            # let the minimiser drain: one reproducer per bucket is the
            # deliverable the regression page depends on
            if self._minimise_thread is not None:
                self._minimise_thread.join(timeout=180)
            monitor.join(timeout=15)
            self.running = False
            self.finished_at = time.time()
            self._sample(final=True)
            self.store.set_meta("finished", self.finished_at)
            self.store.event("campaign", "finished after %d execs, %d crashes, %d buckets"
                             % (self.execs, self.crashes, len(self.buckets.buckets)))

    # ------------------------------------------------------------------
    # corpus
    # ------------------------------------------------------------------
    def _load_seed_corpus(self) -> None:
        rows = self.store.corpus(origin="seed")
        if not rows:
            from .seeds import write_corpus
            n = write_corpus(os.path.join(self.cfg.workdir, "seed_corpus"))
            for i in range(n):
                path = os.path.join(self.cfg.workdir, "seed_corpus", "seed-%04d" % i)
                with open(path, "rb") as fh:
                    data = fh.read()
                self.store.write_corpus(data, origin="seed", edges=0, depth=0)
            rows = self.store.corpus()
        with self._corpus_lock:
            self._corpus = [r for r in rows if os.path.exists(self.store.corpus_path(r))]
        self.store.event("corpus", "loaded %d seeds" % len(self._corpus))

    def _note_op(self, op_mix, crashed: bool) -> None:
        """Track crash frequency per structural operator.

        Every crash costs a worker restart (~100 ms) while a benign input is
        ~70 us, so an operator whose mutations almost always crash the same
        easy defect eats the whole budget.  This is a display / tuning signal
        only; the mutator itself does not change its distribution mid-run.
        """
        if not op_mix:
            return
        self._recent_ops.append((op_mix, crashed))
        if len(self._recent_ops) > 4000:
            self._recent_ops = self._recent_ops[-2000:]
        if len(self._recent_ops) % 500:
            return
        agg = {}
        for mix, c in self._recent_ops:
            for op in mix:
                t, n = agg.get(op, (0, 0))
                agg[op] = (t + (1 if c else 0), n + 1)
        self._op_crash_rate = {op: t / max(1, n) for op, (t, n) in agg.items()}

    def op_stats(self) -> dict:
        return dict(self._op_crash_rate)

    def _pick_parent(self, rng: random.Random, corpus: List[dict]) -> dict:
        """Bias parent selection towards inputs that are small and rich.

        A crash costs a worker restart (~100 ms), a benign input ~70 us, so
        time is dominated by time-to-first-crash.  Inputs that already reach
        deep code (many edges) and that are short (fewer bytes to corrupt)
        find new faults faster; pure uniform selection spends most of its
        budget on inputs that only cover the entry paths.
        """
        if len(corpus) <= 2 or rng.random() < 0.15:
            return rng.choice(corpus)
        sample = rng.sample(corpus, min(8, len(corpus)))
        sample.sort(key=lambda r: (r.get("edges") or 0) / (1 + (r.get("size") or 1)),
                    reverse=True)
        return sample[0]

    def _snapshot_corpus(self) -> List[dict]:
        with self._corpus_lock:
            return list(self._corpus)

    def _append_corpus(self, row: dict) -> None:
        with self._corpus_lock:
            self._corpus.append(row)
            self._corpus_version += 1

    def _reload_corpus(self) -> None:
        rows = self.store.corpus()
        live = []
        for r in rows:
            if os.path.exists(self.store.corpus_path(r)):
                live.append(r)
        with self._corpus_lock:
            self._corpus = live
            self._corpus_version += 1

    # ------------------------------------------------------------------
    # worker loops
    # ------------------------------------------------------------------
    def _worker_loop(self, wid: int) -> None:
        """Run one fuzzing worker, recovering per-iteration failures.

        A bug in the mutator, a transient disk error or a lost database race
        must cost *one* input, not a whole worker for the rest of the
        campaign (that is how a run ends up alive but executing nowhere).
        Only failures to start the worker at all are treated as fatal for the
        thread, and those are retried with a backoff.
        """
        rng = random.Random(self.cfg.seed * 1000 + wid)
        report_path = os.path.join(self._report_dir, "worker-%02d.log" % wid)
        worker = None
        stat = self.stats[wid]
        backoff = 0.1
        try:
            while not self.stop_event.is_set():
                if worker is None:
                    try:
                        worker = Worker(self.cfg.binary, report_path)
                    except Exception as exc:
                        self._note_worker_error(wid, "start", exc)
                        self.stop_event.wait(backoff)
                        backoff = min(5.0, backoff * 2)
                        continue
                    backoff = 0.1
                corpus = self._snapshot_corpus()
                if not corpus:
                    time.sleep(0.05)
                    continue
                parent = self._pick_parent(rng, corpus)
                try:
                    with open(self.store.corpus_path(parent), "rb") as fh:
                        base = fh.read()
                except OSError:
                    self._drop_corpus_entry(parent)
                    continue
                try:
                    data, op_mix = mutate_traced(rng, base, self.cfg.max_len)
                    if not data:
                        continue
                    result = worker.run(data)
                except Exception as exc:
                    # the worker itself may be wedged; discard it and restart
                    self._note_worker_error(wid, "iterate", exc)
                    if worker is not None:
                        try:
                            worker.stop()
                        except Exception:
                            pass
                    worker = None
                    continue

                self._note_op(op_mix, result.crashed)
                with self.lock:
                    self.execs += 1
                    stat.execs += 1

                if result.crashed:
                    try:
                        self._record_crash(worker, wid, data, result, parent)
                    except Exception as exc:
                        # the crash itself is real and was counted; only the
                        # bookkeeping failed
                        self._note_worker_error(wid, "record-crash", exc)
                elif self.cov.add(result.edges):
                    cid = self.store.write_corpus(
                        data, origin="fuzz", edges=len(result.edges),
                        depth=(parent.get("depth") or 0) + 1, parent=parent["id"])
                    self._append_corpus({
                        "id": cid, "path": os.path.join("corpus", cid[:12]),
                        "size": len(data), "edges": len(result.edges),
                        "depth": (parent.get("depth") or 0) + 1,
                        "parent": parent["id"], "origin": "fuzz",
                    })
                else:
                    self.store.bump_corpus_hit(parent["id"])
        finally:
            if worker is not None:
                worker.stop()

    def _note_worker_error(self, wid: int, where: str, exc: BaseException) -> None:
        import traceback
        with self.lock:
            self.worker_errors += 1
            stat = self.stats[wid]
            stat.errors += 1
        self.store.event("error", "worker %d %s: %s" % (wid, where, exc))
        self.store.event("error", traceback.format_exc()[-600:])

    def _drop_corpus_entry(self, row: dict) -> None:
        """Remove a corpus row whose file vanished (trim raced the worker)."""
        with self._corpus_lock:
            self._corpus = [r for r in self._corpus if r.get("id") != row.get("id")]

    def _record_crash(self, worker: Worker, wid: int, data: bytes,
                      result, parent: dict) -> None:
        stat = self.stats[wid]
        sig = bucket_mod.classify(result.report)
        now = time.time()
        self.restart_times.append(now)
        with self.lock:
            self.crashes += 1
            stat.crashes += 1
            stat.restarts += 1
        key = sig.key
        b = self.buckets.buckets.get(key)
        created = b is None
        # keep the report + input only for the first few crashes of a bucket;
        # afterwards only the counters matter for the dashboard
        known = b["unique_inputs"] if b else set()
        import hashlib as _h
        sha = _h.sha1(data).hexdigest()
        keep = created or (sha not in known and len(known) < 25)
        crash_id = self.store.add_crash(key, data, sig, result.report,
                                        keep_report=created, keep_file=keep)
        if created:
            self.buckets.buckets[key] = {
                "id": key, "bug_class": sig.bug_class, "family": sig.family,
                "location": sig.location,
                "function": sig.function, "object_hint": sig.object_hint,
                "label": sig.label, "status": "open", "first_seen": now,
                "last_seen": now, "crashes": [], "unique_inputs": set(),
                "top_frames": sig.top_frames, "sample_report": result.report,
                "regression": None, "classes": {sig.bug_class},
            }
            self.store.event("bucket", "new bucket %s (%s)" % (sig.label, key))
            if self._minimise_queue is not None:
                self._minimise_queue.put((key, bytes(data)))
        b = self.buckets.buckets[key]
        b["last_seen"] = now
        b.setdefault("classes", set()).add(sig.bug_class)
        b["crashes"].append(crash_id)
        import hashlib
        b["unique_inputs"].add(hashlib.sha1(data).hexdigest())
        self.store.upsert_bucket({
            **b, "unique_inputs": len(b["unique_inputs"]),
            "total_crashes": len(b["crashes"]),
            "bug_class": "+".join(sorted(b.get("classes", {sig.bug_class}))),
        })

    # ------------------------------------------------------------------
    # automatic minimisation of new buckets
    # ------------------------------------------------------------------
    def _minimise_loop(self) -> None:
        """Keep one minimised reproducer per bucket, in the background.

        Minimisation costs a few hundred worker executions per bucket, so it
        runs on a separate thread and never slows down the fuzzing workers.
        """
        from .minimize import Minimiser
        m = None
        while True:
            try:
                item = self._minimise_queue.get(timeout=0.5)
            except queue.Empty:
                if self.stop_event.is_set() and self._minimise_queue.empty():
                    return
                continue
            if item is None:
                return
            bucket_id, data = item
            try:
                if m is None:
                    m = Minimiser(self.cfg.binary,
                                  workdir=os.path.join(self.cfg.workdir, "minimise"))
                out, report = m.minimise(data, bucket_id)
                bucket_dir = os.path.join(self.store.root, "crashes", bucket_id)
                os.makedirs(bucket_dir, exist_ok=True)
                with open(os.path.join(bucket_dir, "minimised"), "wb") as fh:
                    fh.write(out)
                with open(os.path.join(bucket_dir, "minimised.asan.txt"), "w") as fh:
                    fh.write(report)
                reg = self.store.get_meta("minimised", {})
                reg[bucket_id] = {"before": len(data), "after": len(out),
                                  "execs": m.execs, "at": time.time()}
                self.store.set_meta("minimised", reg)
                self.store.event("minimise", "bucket %s: %d -> %d bytes"
                                 % (bucket_id, len(data), len(out)))
            except Exception as exc:
                self.store.event("error", "minimise %s: %s" % (bucket_id, exc))

    # ------------------------------------------------------------------
    # monitoring
    # ------------------------------------------------------------------
    def _monitor_loop(self) -> None:
        last_execs = 0
        last_time = time.time()
        while not self.stop_event.is_set():
            self.stop_event.wait(self.cfg.sample_interval)
            now = time.time()
            with self.lock:
                execs = self.execs
            rate = (execs - last_execs) / max(1e-6, now - last_time)
            last_execs, last_time = execs, now
            self._last_rate = rate
            self._sample()
            if self.cfg.minimize_every > 0:
                now2 = time.time()
                if now2 - getattr(self, "_last_trim", 0.0) >= self.cfg.minimize_every:
                    self._last_trim = now2
                    try:
                        self.trim_corpus(self.cfg.minimize_ratio)
                    except Exception as exc:
                        self.store.event("error", "corpus trim: %s" % exc)

    def _sample(self, final: bool = False) -> None:
        sample = {
            "execs": self.execs,
            "exec_rate": self._last_rate,
            "edges": self.cov.count,
            "crashes": self.crashes,
            "workers": len(self.stats),
            "buckets": len(self.buckets.buckets),
        }
        self.samples.append(sample)
        self.store.add_sample(sample)
        self.store.set_meta("execs_final", self.execs)
        if self._op_crash_rate:
            self.store.set_meta("op_crash_yield", self._op_crash_rate)

    # ------------------------------------------------------------------
    # corpus maintenance
    # ------------------------------------------------------------------
    def trim_corpus(self, target_ratio: float = 0.25) -> dict:
        """Drop inputs whose edges are all covered by somebody else."""
        from .corpusmin import CorpusMinimiser
        rows = self._snapshot_corpus()
        items = []
        for r in rows:
            try:
                with open(self.store.corpus_path(r), "rb") as fh:
                    items.append((r["id"], fh.read()))
            except OSError:
                continue
        keep, stats = CorpusMinimiser(self.cfg.binary).trim(items, target_ratio)
        keep_set = set(keep)
        # never trim the seed corpus below a few entries, it anchors the grammar
        seeds = [r["id"] for r in rows if r["origin"] == "seed"]
        keep_set |= set(seeds[:8])
        drop = [cid for cid in (r["id"] for r in rows) if cid not in keep_set]
        self.store.remove_corpus(drop)
        self._reload_corpus()
        stats["dropped"] = len(drop)
        stats["at"] = time.time()
        self.store.set_meta("last_trim", stats)
        self.store.event("corpus", "trimmed %d -> %d inputs (%d dropped)"
                         % (stats["before"], stats["after"], len(drop)))
        return stats

    # ------------------------------------------------------------------
    # queries used by the UI
    # ------------------------------------------------------------------
    def status(self) -> dict:
        elapsed = (self.finished_at or time.time()) - self.started if self.started else 0
        return {
            "running": self.running,
            "started": self.started,
            "elapsed": elapsed,
            "execs": self.execs,
            "exec_rate": self._last_rate,
            "edges": self.cov.count,
            "crashes": self.crashes,
            "buckets": len(self.buckets.buckets),
            "corpus": len(self._snapshot_corpus()),
            "workers": [
                {"id": s.worker_id, "execs": s.execs, "crashes": s.crashes,
                 "restarts": s.restarts, "errors": s.errors} for s in self.stats
            ],
            "op_crash_yield": self.op_stats(),
            "crash_rate": (self.crashes / self.execs) if self.execs else 0.0,
            "worker_errors": self.worker_errors,
        }
