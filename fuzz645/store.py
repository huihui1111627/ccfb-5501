"""Durable campaign store (SQLite) shared by the engine and the web console."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Iterable, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS corpus (
    id TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    edges INTEGER NOT NULL,
    depth INTEGER NOT NULL,
    parent TEXT, added REAL NOT NULL, hits INTEGER NOT NULL DEFAULT 0,
    origin TEXT NOT NULL DEFAULT 'seed');
CREATE TABLE IF NOT EXISTS crashes (
    id TEXT PRIMARY KEY,
    bucket TEXT NOT NULL,
    input_path TEXT NOT NULL,
    input_sha TEXT NOT NULL,
    size INTEGER NOT NULL,
    signature TEXT NOT NULL,
    report TEXT NOT NULL,
    created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS buckets (
    id TEXT PRIMARY KEY,
    bug_class TEXT NOT NULL, location TEXT NOT NULL,
    function TEXT NOT NULL, object_hint TEXT NOT NULL,
    label TEXT NOT NULL, status TEXT NOT NULL,
    first_seen REAL NOT NULL, last_seen REAL NOT NULL,
    unique_inputs INTEGER NOT NULL DEFAULT 0,
    total_crashes INTEGER NOT NULL DEFAULT 0,
    regression TEXT,
    top_frames TEXT, sample_report TEXT);
CREATE TABLE IF NOT EXISTS samples (
    at REAL NOT NULL, execs INTEGER NOT NULL, exec_rate REAL NOT NULL,
    edges INTEGER NOT NULL, crashes INTEGER NOT NULL,
    workers INTEGER NOT NULL, buckets INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    at REAL NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL);
"""


class Store:
    def __init__(self, root: str):
        self.root = root
        os.makedirs(os.path.join(root, "corpus"), exist_ok=True)
        os.makedirs(os.path.join(root, "crashes"), exist_ok=True)
        os.makedirs(os.path.join(root, "reports"), exist_ok=True)
        self.db_path = os.path.join(root, "campaign.db")
        self._local = threading.local()
        self._crash_lock = threading.Lock()
        self._crash_seq = 0
        self._init_db()

    # sqlite connections are per thread
    @property
    def db(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA)

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- meta -----------------------------------------------------------
    def set_meta(self, key: str, value) -> None:
        self.db.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (key, json.dumps(value)))
        self.db.commit()

    def get_meta(self, key: str, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def event(self, kind: str, message: str) -> None:
        self.db.execute("INSERT INTO events(at,kind,message) VALUES(?,?,?)",
                        (time.time(), kind, message))
        self.db.commit()

    # -- corpus ---------------------------------------------------------
    def write_corpus(self, data: bytes, origin: str, edges: int, depth: int,
                     parent: Optional[str] = None) -> str:
        import hashlib
        sha = hashlib.sha1(data).hexdigest()
        path = os.path.join("corpus", sha[:12])
        full = os.path.join(self.root, path)
        if not os.path.exists(full):
            with open(full, "wb") as fh:
                fh.write(data)
        self.db.execute(
            "INSERT OR IGNORE INTO corpus(id,path,size,edges,depth,parent,added,origin)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (sha, path, len(data), edges, depth, parent, time.time(), origin))
        self.db.commit()
        return sha

    def bump_corpus_hit(self, cid: str) -> None:
        self.db.execute("UPDATE corpus SET hits=hits+1 WHERE id=?", (cid,))
        self.db.commit()

    def corpus(self, origin: Optional[str] = None) -> List[dict]:
        sql = "SELECT * FROM corpus"
        args = ()
        if origin:
            sql += " WHERE origin=?"
            args = (origin,)
        sql += " ORDER BY added"
        rows = self.db.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    def corpus_path(self, row: dict) -> str:
        return os.path.join(self.root, row["path"])

    def remove_corpus(self, ids: Iterable[str]) -> int:
        removed = 0
        for cid in ids:
            row = self.db.execute("SELECT path FROM corpus WHERE id=?", (cid,)).fetchone()
            if row:
                try:
                    os.unlink(os.path.join(self.root, row["path"]))
                except OSError:
                    pass
                self.db.execute("DELETE FROM corpus WHERE id=?", (cid,))
                removed += 1
        self.db.commit()
        return removed

    # -- crashes --------------------------------------------------------
    def add_crash(self, bucket_id: str, data: bytes, signature, report: str,
                  keep_report: bool = True, keep_file: bool = True) -> str:
        """Record one crash.

        The full ASan report is only kept for the first crash of a bucket (it
        is what the UI shows); subsequent crashes keep just the signature so a
        long campaign does not fill the disk with near identical reports.
        """
        import hashlib
        sha = hashlib.sha1(data).hexdigest()
        # The id must be unique even when two workers hit the same input at
        # the same moment.  A per-process counter is racy under threads, so
        # the id is derived from the payload plus a row count that races are
        # allowed to collide on -- the INSERT below retries on conflict.
        with self._crash_lock:
            self._crash_seq += 1
        crash_id = "%s-%06x" % (sha[:12], self._crash_seq & 0xFFFFFF)
        while self.db.execute("SELECT 1 FROM crashes WHERE id=?",
                              (crash_id,)).fetchone():
            with self._crash_lock:
                self._crash_seq += 1
            crash_id = "%s-%06x" % (sha[:12], self._crash_seq & 0xFFFFFF)
        if keep_file:
            crash_dir = os.path.join(self.root, "crashes", crash_id)
            os.makedirs(crash_dir, exist_ok=True)
            input_path = os.path.join(crash_dir, "input")
            with open(input_path, "wb") as fh:
                fh.write(data)
            if keep_report:
                with open(os.path.join(crash_dir, "asan.txt"), "w") as fh:
                    fh.write(report)
            rel_input = os.path.relpath(input_path, self.root)
        else:
            rel_input = ""
        try:
            self.db.execute(
                "INSERT INTO crashes(id,bucket,input_path,input_sha,size,"
                "signature,report,created) VALUES(?,?,?,?,?,?,?,?)",
                (crash_id, bucket_id, rel_input, sha, len(data),
                 signature.label, report if keep_report else "", time.time()))
            self.db.commit()
        except sqlite3.IntegrityError:
            # lost a race with another worker on the id; the crash counters in
            # `buckets` still account for it, only the row is a duplicate
            self.db.rollback()
        return crash_id

    def crashes(self, bucket_id: Optional[str] = None) -> List[dict]:
        sql = "SELECT * FROM crashes"
        args = ()
        if bucket_id:
            sql += " WHERE bucket=?"
            args = (bucket_id,)
        return [dict(r) for r in self.db.execute(sql + " ORDER BY created DESC", args)]

    def crash_input(self, row: dict) -> bytes:
        if not row.get("input_path"):
            raise FileNotFoundError("crash input was not retained")
        with open(os.path.join(self.root, row["input_path"]), "rb") as fh:
            return fh.read()

    # -- buckets --------------------------------------------------------
    def upsert_bucket(self, b: dict) -> None:
        self.db.execute(
            "INSERT INTO buckets(id,bug_class,location,function,object_hint,label,"
            "status,first_seen,last_seen,unique_inputs,total_crashes,regression,"
            "top_frames,sample_report) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen, "
            "bug_class=excluded.bug_class, location=excluded.location, "
            "unique_inputs=excluded.unique_inputs, total_crashes=excluded.total_crashes,"
            "regression=excluded.regression, sample_report=excluded.sample_report",
            (b["id"], b["bug_class"], b["location"], b["function"],
             b["object_hint"], b["label"], b["status"], b["first_seen"],
             b["last_seen"], b["unique_inputs"], b["total_crashes"],
             json.dumps(b.get("regression")) if b.get("regression") else None,
             json.dumps(b["top_frames"]), b["sample_report"]))
        self.db.commit()

    def set_bucket_status(self, bucket_id: str, status: str, regression=None) -> None:
        self.db.execute("UPDATE buckets SET status=?, regression=? WHERE id=?",
                        (status, json.dumps(regression) if regression else None,
                         bucket_id))
        self.db.commit()

    def buckets(self) -> List[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM buckets ORDER BY first_seen").fetchall()]

    # -- samples --------------------------------------------------------
    def add_sample(self, s: dict) -> None:
        self.db.execute(
            "INSERT INTO samples(at,execs,exec_rate,edges,crashes,workers,buckets)"
            " VALUES(?,?,?,?,?,?,?)",
            (time.time(), s["execs"], s["exec_rate"], s["edges"],
             s["crashes"], s["workers"], s["buckets"]))
        self.db.commit()

    def samples(self, limit: int = 600) -> List[dict]:
        rows = self.db.execute(
            "SELECT * FROM samples ORDER BY at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in reversed(rows)]
