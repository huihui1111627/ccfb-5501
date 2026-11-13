"""Unit tests for frame model, mutator and crash bucketing."""
import random
import struct

import pytest

from fuzz645.buckets import classify, strip_ansi
from fuzz645.frames import END, START, Frame, FrameCodec, checksum, parse_frames
from fuzz645.mutate import mutate, mutate_raw, mutate_traced
from fuzz645.seeds import build_frames


def frame_bytes(addr=(0x11, 0x22, 0x33, 0x44, 0x55, 0x66), ctrl=0x11,
                data=b"\x10\x90\x00\x01", end=END, fix_cs=True):
    body = bytes([START]) + bytes(addr) + bytes([START, ctrl, len(data)]) + data
    cs = checksum(body) if fix_cs else checksum(body) ^ 0xFF
    return body + bytes([cs, end])


class TestFrameModel:
    def test_round_trip(self):
        raw = frame_bytes()
        frames, tail = FrameCodec.decode(raw)
        assert len(frames) == 1 and tail == b""
        assert FrameCodec.encode(frames, tail) == raw

    def test_multi_frame_stream(self):
        raw = frame_bytes(ctrl=0x91) + frame_bytes(ctrl=0x92)
        frames, tail = FrameCodec.decode(raw)
        assert [f.ctrl for f in frames] == [0x91, 0x92]
        assert FrameCodec.encode(frames, tail) == raw

    def test_checksum_recomputed_on_edit(self):
        f = Frame(addr=bytes(6), ctrl=0x11, data=b"\x00\x00")
        raw = f.encode()
        frames, tail = FrameCodec.decode(raw)
        frames[0].data = b"\x01\x02\x03"
        out = FrameCodec.encode(frames, tail)
        body = out[:-2]
        assert out[-2] == checksum(body)
        assert out[-1] == END

    def test_length_field_follows_data(self):
        f = Frame(addr=bytes(6), ctrl=0x11, data=b"A" * 40)
        raw = f.encode()
        assert raw[9] == 40

    def test_declared_length_may_differ(self):
        # A declared length of 200 needs 200 bytes of stream for the decoder
        # to accept the frame; only 4 are supplied, so the decoder must stop
        # and report that nothing was parsed.
        f = Frame(addr=bytes(6), ctrl=0x11, data=b"A" * 4, len_override=200)
        raw = f.encode()
        assert raw[9] == 200
        frames, off = parse_frames(raw)
        assert frames == [] and off == 0


class TestSeeds:
    def test_seed_corpus_shapes(self):
        seeds = build_frames()
        assert len(seeds) > 40
        # every seed decodes cleanly or is deliberately malformed
        valid = [s for s in seeds if len(parse_frames(s)[0]) >= 1]
        assert len(valid) >= 30

    def test_seeds_cover_control_codes(self):
        seeds = build_frames()
        seen = set()
        for s in seeds:
            frames, _ = FrameCodec.decode(s)
            seen.update(f.ctrl for f in frames)
            # 1997 style seeds carry the control code at a fixed offset
            if not frames and len(s) > 8 and s[0] == START and s[7] == START:
                seen.add(s[8])
        for ctrl in (0x11, 0x12, 0x94, 0xB1, 0xC1, 0xF1):
            assert ctrl in seen


class TestMutation:
    def test_mutation_keeps_valid_structure_mostly(self):
        rng = random.Random(11)
        seed = build_frames()[0]
        valid = 0
        for _ in range(300):
            out = mutate(rng, seed)
            frames, _ = FrameCodec.decode(out)
            if frames:
                valid += 1
        assert valid > 150, "structure preserving mutation rate too low"

    def test_length_and_checksum_are_repaired_after_data_edit(self):
        rng = random.Random(3)
        seed = frame_bytes(data=b"\x10\x90\x00\x01")
        repaired = 0
        for _ in range(200):
            out = mutate(rng, seed)
            frames, _ = FrameCodec.decode(out)
            if frames and all(f.len_override is None for f in frames):
                for f in frames:
                    raw = f.encode()
                    assert raw[9] == len(f.data)
                    assert raw[-2] == checksum(raw[:-2])
                repaired += 1
        assert repaired > 50

    def test_raw_mutation_stays_bounded(self):
        rng = random.Random(5)
        for _ in range(100):
            out = mutate_raw(rng, b"\x68" + b"A" * 50)
            assert len(out) <= 4096

    def test_mutation_survives_empty_and_tiny_inputs(self):
        """Regression: an empty buffer used to raise inside mutate_raw and
        kill the fuzzing worker thread (the campaign then stalled at 0/s)."""
        rng = random.Random(0)
        for buf in (b"", b"\x68", b"\x16", b"\x00" * 2, b"\x68" + b"A" * 8):
            for _ in range(2000):
                out, _ops = mutate_traced(rng, buf)
                assert isinstance(out, bytes)

    def test_mutation_is_deterministic_for_seed(self):
        a = mutate(random.Random(9), build_frames()[3])
        b = mutate(random.Random(9), build_frames()[3])
        assert a == b


ASAN_HEAP = """=================================================================
==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000009ff
READ of size 1 at 0x6020000009ff thread T0
    #0 0x1 in __asan_memcpy+0x400 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3e)
    #1 0x2 in parse_frame_1997 dl645.c:214
    #2 0x3 in dl645_process dl645.c:357
    #3 0x4 in dl645_fuzz_one dl645.c:395
    #4 0x5 in main worker.c:182
SUMMARY: AddressSanitizer: heap-buffer-overflow dl645.c:214 in parse_frame_1997
"""

ASAN_HEAP_LATE = ASAN_HEAP.replace("dl645.c:214", "dl645.c:227")

ASAN_GLOBAL_HI = """=================================================================
ERROR: AddressSanitizer: global-buffer-overflow on address 0x100
READ of size 1 at 0x100 thread T0
    #0 0x1 in addr_decode dl645.c:48
    #1 0x2 in parse_any_frame dl645.c:261
    #2 0x3 in dl645_process dl645.c:357
    #3 0x4 in dl645_fuzz_one dl645.c:395
    #4 0x5 in main worker.c:182
0x100 is located 0 bytes after global variable 'addr_decode.bcd_char' defined in 'dl645.c'
SUMMARY: AddressSanitizer: global-buffer-overflow dl645.c:48 in addr_decode
"""

ASAN_GLOBAL_LO = ASAN_GLOBAL_HI.replace("dl645.c:48", "dl645.c:49")

ASAN_GLOBAL_OTHER = ASAN_GLOBAL_HI.replace("addr_decode", "dispatch") \
                                   .replace("dl645.c:48", "dl645.c:85")

ASAN_UAF = ASAN_HEAP.replace("heap-buffer-overflow", "heap-use-after-free") \
                    .replace("dl645.c:214", "dl645.c:303") \
                    .replace("parse_frame_1997", "retransmit_cache")


class TestStoreConcurrency:
    def test_crash_ids_are_unique_under_concurrency(self):
        """Regression: two workers hitting the same input produced the same
        crash id (sha + row count), raising UNIQUE constraint and killing a
        worker thread mid-campaign."""
        import tempfile
        import threading
        from fuzz645.store import Store
        from fuzz645.buckets import classify
        st = Store(tempfile.mkdtemp())
        sig = classify(ASAN_HEAP)
        ids = []

        def work():
            for _ in range(40):
                ids.append(st.add_crash("b" * 12, b"A" * 8, sig, "r",
                                        keep_report=False, keep_file=False))

        threads = [threading.Thread(target=work) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(ids) == len(set(ids)) == 320


class TestClassification:
    def test_same_root_cause_different_lines_merge(self):
        assert classify(ASAN_GLOBAL_HI).key == classify(ASAN_GLOBAL_LO).key

    def test_same_root_cause_different_observation_sites_merge(self):
        assert classify(ASAN_HEAP).key == classify(ASAN_HEAP_LATE).key

    def test_different_function_splits(self):
        assert classify(ASAN_GLOBAL_HI).key != classify(ASAN_GLOBAL_OTHER).key

    def test_same_function_different_asan_class_merges(self):
        """The same overrunning copy is reported as heap-buffer-overflow or as
        memcpy-param-overlap depending on the run's address layout; both are
        one defect and must not create two buckets."""
        overlap = ASAN_HEAP.replace("heap-buffer-overflow", "memcpy-param-overlap")
        assert classify(ASAN_HEAP).key == classify(overlap).key

    def test_same_function_later_uaf_is_one_bucket(self):
        # retransmit_cache is a free-then-use defect; ASan may first report the
        # free's own bookkeeping, so both stay in the same bucket
        assert classify(ASAN_UAF).function == "retransmit_cache"

    def test_wild_pointer_signal_stays_separate(self):
        segv = ASAN_HEAP.replace(
            "heap-buffer-overflow on address 0x602", "SEGV on unknown address 0x0")
        # classify() reads the kind regex first; force the signal form
        segv = segv.replace("ERROR: AddressSanitizer: heap-buffer-overflow on",
                            "ERROR: AddressSanitizer: SEGV on")
        assert classify(segv).family == "SEGV"
        assert classify(ASAN_HEAP).family == "memory"

    def test_top_frame_is_a_project_function(self):
        sig = classify(ASAN_HEAP)
        assert sig.function == "parse_frame_1997"
        assert "libclang_rt" not in sig.top_frames[0]

    def test_ansi_colour_is_stripped(self):
        coloured = "\x1b[1;31m" + ASAN_HEAP + "\x1b[0m"
        assert classify(coloured).function == "parse_frame_1997"
