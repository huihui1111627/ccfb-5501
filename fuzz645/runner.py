"""Persistent worker driver: one subprocess, many inputs, crash detection.

Each worker execs ``build/worker-buggy`` (ASan instrumented, persistent loop).
An input is written to stdin as ``u32 len || payload``; the reply is
``u32 edge_count || u32 edges[]``.  If the worker dies instead of replying,
the ASan report (written by the worker's error callback) is picked up from the
spool file and the worker is restarted.
"""
from __future__ import annotations

import os
import struct
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional

HELLO_MAGIC = 0x35363444
HELLO_PROTO = 1
QUIT = 0xFFFFFFFF
EXIT_SANITIZER = 97
EXIT_DEATH = 98


class WorkerError(RuntimeError):
    pass


@dataclass
class ExecResult:
    edges: List[int]
    crashed: bool
    report: str = ""
    exit_code: Optional[int] = None


class Worker:
    def __init__(self, binary: str, report_path: str, env: Optional[dict] = None):
        self.binary = binary
        self.report_path = report_path
        self.env = dict(os.environ)
        self.env.update({
            "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0:handle_segv=1:"
                            "handle_abort=1:print_summary=1:"
                            "symbolize=1:fast_unwind_on_malloc=0",
            "UBSAN_OPTIONS": "print_stacktrace=1",
        })
        if env:
            self.env.update(env)
        self.proc: Optional[subprocess.Popen] = None
        self.guard_count = 0
        self.starts = 0
        self._start()

    # -- lifecycle ------------------------------------------------------
    def _start(self) -> None:
        self.close_report()
        self.proc = subprocess.Popen(
            [self.binary, self.report_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=self.env, bufsize=0,
        )
        hello = self.proc.stdout.read(12)
        if len(hello) != 12:
            raise WorkerError("worker failed to handshake (exit=%s)"
                              % self.proc.poll())
        magic, proto, guards = struct.unpack("<III", hello)
        if magic != HELLO_MAGIC or proto != HELLO_PROTO:
            raise WorkerError("bad handshake %08x/%d" % (magic, proto))
        self.guard_count = guards
        self.starts += 1

    def close_report(self) -> None:
        try:
            with open(self.report_path, "wb"):
                pass
        except OSError:
            pass

    def _read_report(self) -> str:
        try:
            with open(self.report_path, "rb") as fh:
                return fh.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def restart(self) -> None:
        self.stop()
        self._start()

    def stop(self) -> None:
        p = self.proc
        self.proc = None
        if p is None:
            return
        try:
            if p.poll() is None:
                try:
                    p.stdin.write(struct.pack("<I", QUIT))
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
                try:
                    p.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=2.0)
        finally:
            for stream in (p.stdin, p.stdout):
                try:
                    stream.close()
                except Exception:
                    pass

    # -- per input ------------------------------------------------------
    def run(self, data: bytes) -> ExecResult:
        if self.proc is None:
            self._start()
        assert self.proc is not None and self.proc.stdin and self.proc.stdout
        try:
            self.proc.stdin.write(struct.pack("<I", len(data)))
            if data:
                self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            return self._dead()

        hdr = self.proc.stdout.read(4)
        if len(hdr) != 4:
            return self._dead()
        count, = struct.unpack("<I", hdr)
        if count > self.guard_count + 16:
            self.proc.kill()
            self.proc.wait()
            return self._dead()
        payload = self.proc.stdout.read(count * 4) if count else b""
        if len(payload) != count * 4:
            return self._dead()
        edges = list(struct.unpack("<%dI" % count, payload)) if count else []
        return ExecResult(edges=edges, crashed=False)

    def _dead(self) -> ExecResult:
        assert self.proc is not None
        try:
            self.proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        code = self.proc.returncode
        report = self._read_report()
        self.proc = None
        self._start()
        return ExecResult(edges=[], crashed=True, report=report, exit_code=code)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()


def batch_run(binary: str, report_dir: str, items, env=None) -> List[ExecResult]:
    """Convenience helper used by minimisation and regression."""
    os.makedirs(report_dir, exist_ok=True)
    results = []
    with Worker(binary, os.path.join(report_dir, "report.log"), env=env) as w:
        for data in items:
            results.append(w.run(data))
    return results
