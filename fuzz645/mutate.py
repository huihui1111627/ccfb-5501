"""Structure aware mutation for DL/T 645 frames.

Strategy (chosen to reach the planted defects quickly):

* decode the input into frames + unstructured tail;
* pick a frame and apply a structural edit: control code (incl. 0xFF so the
  24 entry dispatch table is overrun), address BCD nibbles (0xA..0xF),
  data item id, decimals nibble, data length, appended item bytes;
* re-encode so the length byte and checksum always match the new payload
  ("length and checksum are repaired automatically");
* occasionally break the repair on purpose (checksum or end byte) because the
  retransmission cache and checksum retry paths only run on damaged frames;
* splice / duplicate / truncate frames to build multi frame streams;
* fall back to raw byte edits in the tail.
"""
from __future__ import annotations

import random
from .frames import END, MAX_DATA, Frame, FrameCodec, checksum

# Byte values that are useful for a concentrator: legal commands plus the
# out-of-range codes that trigger the 24-entry dispatch table overrun.
CTRL_VALUES = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
               0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A,
               0xB1, 0xC1, 0xD1, 0xE1, 0xF1, 0x00, 0x1F, 0x3F, 0x7F, 0xFF]

BCD_NIBBLES = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
               0xA, 0xB, 0xC, 0xD, 0xE, 0xF]           # 0xA..0xF overrun

DATA_IDS = [
    b"\x10\x90",   # DI 0x9010 电能量
    b"\x00\x00",   # 当前组合有功总电能 (常见)
    b"\x00\x01",
    b"\x02\x00",
    b"\x04\x00",
    b"\x1F\xFF",
    b"\xFF\xFF",
]

INTERESTING_LENS = [0, 1, 2, 3, 4, 5, 8, 12, 16, 32, 63, 64, 100, 127,
                    128, 199, 200, 201, 202, 240, 255]


def _rand_printable(rng: random.Random, lo: int, hi: int) -> bytes:
    return bytes(rng.randrange(lo, hi) for _ in range(rng.randrange(1, 25)))


def _bcd_addr(rng: random.Random) -> bytes:
    out = bytearray()
    for _ in range(6):
        hi = rng.choice(BCD_NIBBLES)
        lo = rng.choice(BCD_NIBBLES)
        out.append((hi << 4) | lo)
    return bytes(out)


def _fresh_frame(rng: random.Random) -> Frame:
    data = bytearray()
    if rng.random() < 0.8:
        data += rng.choice(DATA_IDS)
        if rng.random() < 0.7:
            data.append(rng.choice(BCD_NIBBLES) << 4 | rng.randrange(0, 4))  # decimals
            data += _rand_printable(rng, 0, 256)[: rng.randrange(1, 6)]
    else:
        data += _rand_printable(rng, 0, 256)
    if rng.random() < 0.1:
        data = bytearray([rng.randrange(0, 256) for _ in range(rng.randrange(0, 8))])
    return Frame(addr=_bcd_addr(rng) if rng.random() < 0.5 else bytes(6),
                 ctrl=rng.choice(CTRL_VALUES),
                 data=bytes(data[:MAX_DATA]),
                 end=END)


def _mutate_frame_traced(rng: random.Random, f: Frame):
    seen = []

    def note(op):
        seen.append(op)

    out = _mutate_frame(rng, f, note)
    return out, (seen[0] if seen else "frame")


def _mutate_frame(rng: random.Random, f: Frame, note=None) -> Frame:
    op = rng.choices(
        ["ctrl", "addr", "bcd_addr", "di", "dec", "data", "len", "end",
         "cs", "append_item", "truncate_data", "random_data"],
        weights=[12, 8, 8, 12, 10, 12, 12, 2, 4, 10, 4, 6],
    )[0]
    if note is not None:
        note(op)

    if op == "ctrl":
        f.ctrl = rng.choice(CTRL_VALUES)
    elif op == "addr":
        a = bytearray(f.addr)
        for _ in range(rng.randrange(1, 3)):
            a[rng.randrange(6)] = rng.randrange(0, 256)
        f.addr = bytes(a)
    elif op == "bcd_addr":
        a = bytearray(f.addr)
        bit = rng.randrange(12)
        byte_i, half = divmod(bit, 2)
        nib = rng.choice(BCD_NIBBLES) if rng.random() < 0.18 else rng.randrange(0, 10)
        if half == 0:
            a[byte_i] = (nib << 4) | (a[byte_i] & 0x0F)
        else:
            a[byte_i] = (a[byte_i] & 0xF0) | nib
        f.addr = bytes(a)
    elif op == "di":
        d = bytearray(f.data)
        if len(d) < 2:
            d = bytearray(rng.choice(DATA_IDS))
        else:
            d[0:2] = rng.choice(DATA_IDS)
        f.data = bytes(d)
    elif op == "dec":
        d = bytearray(f.data)
        if len(d) < 4:
            d += bytes(rng.choice(DATA_IDS)) + b"\x00\x00"
        d[2] = (rng.choice(BCD_NIBBLES) << 4) | (d[2] & 0x0F)
        f.data = bytes(d)
    elif op == "data":
        d = bytearray(f.data)
        if d:
            d[rng.randrange(len(d))] = rng.randrange(0, 256)
            f.data = bytes(d)
    elif op == "len":
        # Sometimes the declared length disagrees with the bytes that follow,
        # which is how a damaged length field reaches the parser.
        if rng.random() < 0.4:
            f.len_override = rng.choice([0, 1, 2, 3, 4, 8, 16, 100, 199,
                                         200, 201, 202, 220, 254, 255])
            if f.len_override > len(f.data) and rng.random() < 0.7:
                f.data = f.data + bytes(rng.randrange(0, 256)
                                        for _ in range(f.len_override - len(f.data)))
        else:
            want = rng.choice(INTERESTING_LENS)
            d = bytearray(f.data)
            if want < len(d):
                del d[want:]
            else:
                d += bytes(rng.randrange(0, 256) for _ in range(want - len(d)))
            f.data = bytes(d[:255])
            f.len_override = None
    elif op == "end":
        f.end = rng.choice([0x16, 0x16, 0x17, 0x00, 0x68])
    elif op == "cs":
        f.cs_override = (checksum(f.encode()[:-2]) ^ rng.choice([0x01, 0x80, 0xFF])) & 0xFF
    elif op == "append_item":
        d = bytearray(f.data)
        d += bytes(rng.randrange(0, 256) for _ in range(rng.randrange(1, 12)))
        f.data = bytes(d[:MAX_DATA])
    elif op == "truncate_data":
        f.data = f.data[: rng.randrange(0, len(f.data) + 1)]
    elif op == "random_data":
        f.data = bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, MAX_DATA + 1)))
    return f


def mutate_raw(rng: random.Random, buf: bytes) -> bytes:
    if not buf:
        return bytes([rng.randrange(0, 256)])
    b = bytearray(buf)
    for _ in range(rng.randrange(1, 8)):
        op = rng.choices(["flip", "byte", "insert", "delete", "dup", "chunk"],
                         weights=[30, 30, 12, 12, 8, 8])[0]
        if op == "flip" and b:
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
        elif op == "byte" and b:
            b[rng.randrange(len(b))] = rng.randrange(0, 256)
        elif op == "insert":
            i = rng.randrange(len(b) + 1)
            b[i:i] = bytes(rng.randrange(0, 256) for _ in range(rng.randrange(1, 9)))
        elif op == "delete" and len(b) > 1:
            i = rng.randrange(len(b))
            del b[i:i + rng.randrange(1, 5)]
        elif op == "dup" and b:
            i = rng.randrange(len(b))
            n = rng.randrange(1, 16)
            b[i:i] = b[i:i + n]
        elif op == "chunk" and b:
            i = rng.randrange(len(b))
            b[i:i + 1] = bytes([rng.choice([0x00, 0x16, 0x68, 0xFF, 0x80])])
        elif not b:
            # every structural op above needs at least one byte
            b.append(rng.randrange(0, 256))
    return bytes(b[:4096])


def mutate_traced(rng: random.Random, buf: bytes, max_len: int = 4096):
    """Like :func:`mutate` but also returns the structural operators used.

    The campaign records which operators produced a crash so the monitor can
    show the crash yield of each mutation class."""
    used = []

    def note(op):
        used.append(op)

    out = _mutate(rng, buf, max_len, note)
    return out, used


def mutate(rng: random.Random, buf: bytes, max_len: int = 4096) -> bytes:
    """One mutation round.  Returns the new input."""
    return _mutate(rng, buf, max_len, lambda op: None)


def _mutate(rng: random.Random, buf: bytes, max_len: int = 4096, note=None) -> bytes:
    frames, tail = FrameCodec.decode(buf)

    if not frames:
        if rng.random() < 0.6:
            fresh = [_fresh_frame(rng) for _ in range(rng.randrange(1, 4))]
            return FrameCodec.encode(fresh, tail)[:max_len]
        return mutate_raw(rng, buf)[:max_len]

    rounds = 1 if rng.random() < 0.75 else rng.randrange(2, 4)
    for _ in range(rounds):
        op = rng.choices(
            ["frame", "splice", "delete", "dup", "tail", "raw", "append_frame",
             "prefix"],
            weights=[55, 8, 6, 8, 6, 8, 6, 3],
        )[0]
        if note is not None:
            note(op)
        if op == "frame":
            i = rng.randrange(len(frames))
            frames[i], inner = _mutate_frame_traced(rng, frames[i])
            if note is not None:
                note(inner)
        elif op == "splice" and len(frames) >= 2:
            i, j = rng.sample(range(len(frames)), 2)
            cut = rng.randrange(0, min(len(frames[i].data), len(frames[j].data)) + 1)
            frames[i].data = frames[j].data[:cut] + frames[i].data[cut:]
        elif op == "delete" and len(frames) > 1:
            del frames[rng.randrange(len(frames))]
        elif op == "dup":
            i = rng.randrange(len(frames))
            src = frames[i]
            frames.insert(i, Frame(addr=src.addr, ctrl=src.ctrl, data=src.data,
                                   end=src.end, cs_override=src.cs_override,
                                   len_override=src.len_override))
        elif op == "tail":
            tail = mutate_raw(rng, tail) if tail else bytes(
                rng.randrange(0, 256) for _ in range(rng.randrange(1, 20)))
        elif op == "raw":
            out = mutate_raw(rng, FrameCodec.encode(frames, tail))
            return out[:max_len]
        elif op == "append_frame":
            frames.append(_fresh_frame(rng))
        elif op == "prefix":
            frames.insert(0, _fresh_frame(rng))

    if rng.random() < 0.03:            # occasionally go fully unstructured
        return mutate_raw(rng, buf)[:max_len]
    return FrameCodec.encode(frames, tail)[:max_len]
