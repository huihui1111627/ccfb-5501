"""Integration tests: every planted defect, bucketing invariants, regression.

These tests drive the real ASan instrumented worker, so they are marked
``slow`` and need the project to be built first (``./build.sh`` and
``./build.sh --fixed``).  Run with:  python3 -m pytest tests/test_integration.py
"""
import os
import shutil
import struct
import subprocess
import tempfile
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUGGY = os.path.join(ROOT, "build", "worker-buggy")
FIXED = os.path.join(ROOT, "build", "worker-fixed")
REPRO = os.path.join(ROOT, "build", "repro-buggy")

pytestmark = pytest.mark.skipif(not os.path.exists(BUGGY),
                                reason="run ./build.sh first")


def cs(body):
    return sum(body) & 0xFF


def frame(addr=(0x11,) * 6, ctrl=0x11, data=b"\x10\x90\x00\x01", end=0x16,
          fix_cs=True, declared=None):
    declared = len(data) if declared is None else declared
    body = bytes([0x68]) + bytes(addr) + bytes([0x68, ctrl, declared & 0xFF]) + data
    c = cs(body) if fix_cs else cs(body) ^ 0xFF
    return body + bytes([c, end])


# one hand built reproducer per planted defect, in the order of defects.md
DEFECT_CASES = {
    "D01": (frame(data=b"A" * 240), "parse_frame_2007"),
    # 1997 layout: L is two bytes, so the stream needs L low byte followed by
    # the high byte; L2 = 100 with only 9 data bytes present overruns the copy
    "D02": (bytes([0x68]) + bytes([0x11] * 6) + bytes([0x68, 0x11, 100, 0])
            + b"B" * 9, "parse_frame_1997"),
    "D03": (frame(data=b"C" * 4, fix_cs=False), "checksum_retry"),
    "D04": (frame(addr=(0x11, 0x22, 0x33, 0x44, 0x55, 0xAB)), "addr_decode"),
    "D05": (frame(data=b"\x10\x90\xF0\x01"), "dispatch_item"),
    "D06": (frame(ctrl=0xFF), "dispatch"),
    "D07": (frame(ctrl=0x91, data=b"\x00\x00\x00\x00") +
            frame(ctrl=0x91, data=b"\x00\x00\x00\x00", fix_cs=False), "retransmit_cache"),
    "D08": (b"".join(frame(ctrl=0x91, data=b"\x00\x00\x00\x00") for _ in range(6)),
            "record_batch"),
}


class Session:
    """Keep one persistent worker alive for all tests in a module."""

    def __init__(self):
        from fuzz645.runner import Worker
        self.tmp = tempfile.mkdtemp(prefix="it-")
        self.worker = Worker(BUGGY, os.path.join(self.tmp, "report.log"))

    def run(self, data):
        return self.worker.run(data)

    def close(self):
        self.worker.stop()


@pytest.fixture(scope="module")
def sess():
    s = Session()
    yield s
    s.close()


@pytest.mark.parametrize("name", sorted(DEFECT_CASES))
def test_defect_crashes_and_buckets(sess, name):
    from fuzz645.buckets import classify
    data, function = DEFECT_CASES[name]
    result = sess.run(data)
    assert result.crashed, "%s did not crash the buggy build" % name
    sig = classify(result.report)
    assert sig.function == function, \
        "%s bucketed as %s, expected %s" % (name, sig.function, function)


def test_all_eight_root_causes_are_distinct():
    from fuzz645.buckets import classify
    from fuzz645.runner import Worker
    tmp = tempfile.mkdtemp(prefix="it-")
    keys = {}
    with Worker(BUGGY, os.path.join(tmp, "r.log")) as w:
        for name, (data, _fn) in DEFECT_CASES.items():
            r = w.run(data)
            assert r.crashed
            keys[name] = classify(r.report).key
    assert len(set(keys.values())) == len(keys), \
        "root causes merged: %r" % keys


@pytest.mark.parametrize("name", sorted(DEFECT_CASES))
def test_defect_does_not_crash_fixed_build(name):
    """Every planted defect must be gone from the -DDL645_FIXED build.

    Guards against a "fix" that only narrows the range (the first BCD fix
    still loaded the out of range index and had to clamp it explicitly).
    """
    from fuzz645.runner import Worker
    if not os.path.exists(FIXED):
        pytest.skip("run ./build.sh --fixed first")
    data, _fn = DEFECT_CASES[name]
    tmp = tempfile.mkdtemp(prefix="fx-")
    with Worker(FIXED, os.path.join(tmp, "r.log")) as w:
        r = w.run(data)
    assert not r.crashed, "%s still crashes the fixed build:\n%s" % (
        name, r.report[:600])


def test_normal_frames_do_not_crash(sess):
    for ctrl in (0x11, 0x12, 0x91, 0x92, 0xB1, 0xC1):
        r = sess.run(frame(ctrl=ctrl))
        assert not r.crashed, "legal frame ctrl=%02X crashed" % ctrl


def test_bucket_key_merges_nibble_variants(sess):
    """D04 high and low nibble overrun are one bucket."""
    from fuzz645.buckets import classify
    hi = sess.run(frame(addr=(0xAB,) + (0x11,) * 5))
    lo = sess.run(frame(addr=(0xBA,) + (0x11,) * 5))
    assert hi.crashed and lo.crashed
    assert classify(hi.report).key == classify(lo.report).key


def test_minimiser_preserves_bucket(sess):
    from fuzz645.buckets import classify
    from fuzz645.minimize import Minimiser
    data = DEFECT_CASES["D05"][0] * 3
    key = classify(sess.run(data).report).key
    m = Minimiser(BUGGY, os.path.join(sess.tmp, "min"))
    out, _report = m.minimise(data, key)
    assert len(out) < len(data)
    r = sess.run(out)
    assert r.crashed and classify(r.report).key == key


def test_regression_marks_fixed_and_open():
    from fuzz645.minimize import Minimiser
    from fuzz645.regress import run_regression
    from fuzz645.store import Store
    work = tempfile.mkdtemp(prefix="reg-")
    st = Store(work)
    m = Minimiser(BUGGY, os.path.join(work, "min"))
    keys = {}
    with open(os.path.join(work, "seed_corpus_placeholder"), "w"):
        pass
    for name, (data, _fn) in DEFECT_CASES.items():
        from fuzz645.buckets import classify
        from fuzz645.runner import Worker
        with Worker(BUGGY, os.path.join(work, "one.log")) as w:
            r = w.run(data)
            sig = classify(r.report)
        key = sig.key
        crash_id = st.add_crash(key, data, sig, r.report)
        st.upsert_bucket({
            "id": key, "bug_class": sig.bug_class, "location": sig.location,
            "function": sig.function, "object_hint": sig.object_hint,
            "label": sig.label, "status": "open", "first_seen": time.time(),
            "last_seen": time.time(), "unique_inputs": 1, "total_crashes": 1,
            "regression": None, "top_frames": sig.top_frames,
            "sample_report": r.report,
        })
        out, _ = m.minimise(data, key)
        os.makedirs(os.path.join(st.root, "crashes", key), exist_ok=True)
        with open(os.path.join(st.root, "crashes", key, "minimised"), "wb") as fh:
            fh.write(out)
        keys[name] = key
    results = run_regression(st, FIXED, os.path.join(work, "reg"))
    summary = st.get_meta("last_regression")
    assert summary["fixed"] == len(DEFECT_CASES), summary
    assert all(r.status == "fixed" for r in results)


def test_unfixed_build_keeps_buckets_open():
    from fuzz645.regress import run_regression
    from fuzz645.store import Store
    work = tempfile.mkdtemp(prefix="reg2-")
    st = Store(work)
    from fuzz645.buckets import classify
    from fuzz645.runner import Worker
    with Worker(BUGGY, os.path.join(work, "one.log")) as w:
        r = w.run(DEFECT_CASES["D04"][0])
        sig = classify(r.report)
    st.add_crash(sig.key, DEFECT_CASES["D04"][0], sig, r.report)
    st.upsert_bucket({
        "id": sig.key, "bug_class": sig.bug_class, "location": sig.location,
        "function": sig.function, "object_hint": sig.object_hint,
        "label": sig.label, "status": "open", "first_seen": time.time(),
        "last_seen": time.time(), "unique_inputs": 1, "total_crashes": 1,
        "regression": None, "top_frames": sig.top_frames,
        "sample_report": r.report,
    })
    results = run_regression(st, BUGGY, os.path.join(work, "reg"))
    assert results[0].status == "still-open"
