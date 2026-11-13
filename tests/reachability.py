#!/usr/bin/env python3
"""One-off sanity check: every planted defect is reachable from a valid frame."""
import os
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKER = os.path.join(ROOT, "build", "worker-buggy")
TMP = tempfile.mkdtemp()


def checksum(b):
    return sum(b) & 0xFF


def frame(addr, ctrl, data, end=0x16, fix_cs=True):
    body = bytes([0x68]) + addr + bytes([0x68, ctrl]) + bytes([len(data)]) + data
    cs = checksum(body)
    if not fix_cs:
        cs ^= 0xFF
    return body + bytes([cs, end])


def main():
    report = os.path.join(TMP, "r.log")
    p = subprocess.Popen([WORKER, report], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         bufsize=0)
    hello = p.stdout.read(12)
    magic, proto, guards = struct.unpack("<III", hello)
    print("worker magic=%08x proto=%d guards=%d" % (magic, proto, guards))
    addr = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    cases = {
        "D01 len": frame(addr, 0x11, b"A" * 240),
        "D02 97 len": bytes([0x68]) + addr + bytes([0x68, 0x11]) +
                      struct.pack("<H", 200) + b"B" * 200 + b"\x16",
        "D03 cs retry": frame(addr, 0x11, b"C" * 4, fix_cs=False),
        "D04 bcd addr": frame(bytes([0xAB] * 6), 0x11, b"\x10\x90\x00\x01"),
        "D05 dec": frame(addr, 0x11, b"\x10\x90\xF0\x01"),
        "D06 ctrl": frame(addr, 0xFF, b"\x10\x90\x00\x01"),
        "D07 cache": frame(addr, 0x11, b"D" * 4, fix_cs=False),
        "D08 batch": b"".join(frame(addr, 0x91, b"\x00\x00\x00\x00")
                              for _ in range(6)),
    }
    for name, payload in cases.items():
        p.stdin.write(struct.pack("<I", len(payload)) + payload)
        hdr = p.stdout.read(4)
        if len(hdr) < 4:
            print("%-14s -> CRASH (worker died)" % name)
            break
        n, = struct.unpack("<I", hdr)
        p.stdout.read(n * 4)
        print("%-14s -> ok (%d edges)" % (name, n))
    try:
        p.stdin.write(struct.pack("<I", 0xFFFFFFFF))
    except BrokenPipeError:
        pass
    p.wait(timeout=5)
    if os.path.exists(report) and os.path.getsize(report):
        print("--- report ---")
        print(open(report, errors="replace").read()[:400])


if __name__ == "__main__":
    main()
