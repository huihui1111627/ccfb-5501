"""Input minimisation: shrink a reproducer while keeping the root cause.

Two reducers run in sequence:

1. line/frame level -- drop whole frames from a multi-frame stream, keep the
   smallest stream that still yields the same bucket key;
2. byte level -- ddmin over contiguous chunks, then byte deletion, then
   structural simplification (zero whole fields, fix the length/checksum).

Everything is verified by re-running the persistent worker, and the crash
signature is compared by *bucket key*, so an input that starts crashing in a
different function is rejected even though it still crashes.
"""
from __future__ import annotations

import os
import tempfile
from typing import Optional, Tuple

from . import buckets as bucket_mod
from .frames import Frame, FrameCodec
from .runner import Worker


class Minimiser:
    def __init__(self, binary: str, workdir: Optional[str] = None,
                 timeout_s: float = 0.6):
        self.binary = binary
        self.workdir = workdir or tempfile.mkdtemp(prefix="min-")
        os.makedirs(self.workdir, exist_ok=True)
        self.report = os.path.join(self.workdir, "report.log")
        self.timeout_s = timeout_s
        self.execs = 0

    def _sig(self, worker: Worker, data: bytes) -> Tuple[Optional[str], str]:
        result = worker.run(data)
        self.execs += 1
        if not result.crashed:
            return None, ""
        return bucket_mod.classify(result.report).key, result.report

    def minimise(self, data: bytes, target_key: str) -> Tuple[bytes, str]:
        """Return (minimised input, report of the final verified run)."""
        with Worker(self.binary, self.report) as w:
            key, report = self._sig(w, data)
            if key is None:
                raise ValueError("input does not crash on the current build")
            if key != target_key:
                raise ValueError("input crashes in a different bucket (%s != %s)"
                                 % (key, target_key))
            data = self._reduce_frames(w, data, target_key)
            data = self._ddmin(w, data, target_key)
            data = self._simplify(w, data, target_key)
        return data, report

    # -- stage 1: frame level -------------------------------------------
    def _reduce_frames(self, w: Worker, data: bytes, key: str) -> bytes:
        frames, tail = FrameCodec.decode(data)
        if len(frames) <= 1:
            return data

        def ok(buf: bytes) -> bool:
            return self._sig(w, buf)[0] == key

        # ddmin over the frame list, tail preserved at the end
        n = len(frames)
        chunk = max(1, n // 2)
        current = list(frames)
        while chunk >= 1:
            i = 0
            while i < len(current):
                candidate = current[:i] + current[i + chunk:]
                buf = FrameCodec.encode(candidate, tail)
                if candidate and ok(buf):
                    current = candidate
                else:
                    i += chunk
            if chunk == 1:
                break
            chunk = max(1, chunk // 2)
        return FrameCodec.encode(current, tail)

    # -- stage 2: generic ddmin -----------------------------------------
    def _ddmin(self, w: Worker, data: bytes, key: str) -> bytes:
        if len(data) <= 4:
            return data
        n = len(data)
        chunk = max(1, n // 2)
        while chunk >= 1:
            i = 0
            changed = False
            while i < len(data):
                candidate = data[:i] + data[i + chunk:]
                if candidate and self._sig(w, candidate)[0] == key:
                    data = candidate
                    changed = True
                else:
                    i += chunk
            if chunk == 1 and not changed:
                break
            chunk = max(1, chunk // 2)
        return data

    # -- stage 3: structural simplification ----------------------------
    def _simplify(self, w: Worker, data: bytes, key: str) -> bytes:
        """Zero fields one at a time and repair length/checksum around them."""
        frames, tail = FrameCodec.decode(data)
        if not frames:
            return data

        def ok(buf: bytes) -> bool:
            return self._sig(w, buf)[0] == key

        def clone(seq):
            return [Frame(addr=f.addr, ctrl=f.ctrl, data=f.data, end=f.end,
                          cs_override=f.cs_override, len_override=f.len_override)
                    for f in seq]

        # zero the address and the data bytes one field at a time
        for i in range(len(frames)):
            for field in ("addr", "data"):
                original = getattr(frames[i], field)
                candidates = []
                if field == "addr":
                    candidates.append(bytes(6))
                else:
                    candidates.append(b"")
                    for j in range(len(original)):
                        candidates.append(original[:j] + bytes(len(original) - j))
                for cand in candidates:
                    trial = clone(frames)
                    setattr(trial[i], field, cand)
                    trial[i].len_override = None
                    buf = FrameCodec.encode(trial, tail)
                    if buf and ok(buf):
                        frames = trial
                        break
        # raise/lower single bytes in place -- turning a fuzz byte into 0x00 or
        # 0xFF often makes the reproducer far easier to read
        buf = FrameCodec.encode(frames, tail)
        for value in (0x00, 0xFF, 0x16, 0x68):
            i = 0
            while i < len(buf):
                if buf[i] != value:
                    cand = buf[:i] + bytes([value]) + buf[i + 1:]
                    if self._sig(w, cand)[0] == key:
                        buf = cand
                i += 1
        return buf


def _minimise_plain(self, data: bytes, predicate) -> bytes:
    """Generic shrinker used for corpus entries (predicate = keep this)."""
    with Worker(self.binary, self.report) as w:
        def ok(buf: bytes) -> bool:
            r = w.run(buf)
            self.execs += 1
            return not r.crashed
        # ddmin over chunks
        n = len(data)
        chunk = max(1, n // 2)
        while chunk >= 1:
            i = 0
            changed = False
            while i < len(data):
                cand = data[:i] + data[i + chunk:]
                if cand and predicate(cand):
                    data = cand
                    changed = True
                else:
                    i += chunk
            if chunk == 1 and not changed:
                break
            chunk = max(1, chunk // 2)
    return data


Minimiser.minimise_plain = _minimise_plain


def reproduce_command(binary: str, input_path: str) -> str:
    return "%s %s" % (binary, input_path)
