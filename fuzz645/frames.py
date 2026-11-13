"""DL/T 645 frame model: build, validate, repair and re-encode frames.

The mutator works on a structured view of the input rather than raw bytes so
that length fields and the checksum stay consistent after every edit.  A raw
byte mutator still exists (``mutate_raw``) for the tail of the input where
structure is unknown.

Frame layout used by the target (all little endian, low byte first):

    68 | A0 A1 A2 A3 A4 A5 | 68 | C | L | DATA[L] | CS | 16
       |                   |                        |
       +- address (BCD) ---+                        +- sum of bytes 0..(10+L)
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional

START = 0x68
END = 0x16
MIN_FRAME = 12
MAX_DATA = 200


def checksum(data: bytes) -> int:
    return sum(data) & 0xFF


@dataclass
class Frame:
    addr: bytes = bytes(6)
    ctrl: int = 0x11
    data: bytes = b""
    end: int = END
    cs_override: Optional[int] = None   # used when generating broken seeds
    len_override: Optional[int] = None  # declared L may disagree with len(data)

    def encode(self) -> bytes:
        declared = len(self.data) if self.len_override is None else (self.len_override & 0xFF)
        body = bytes([START]) + self.addr + bytes([START, self.ctrl & 0xFF, declared]) + self.data
        cs = checksum(body) if self.cs_override is None else self.cs_override & 0xFF
        return body + bytes([cs, self.end & 0xFF])

    @property
    def total_len(self) -> int:
        return MIN_FRAME + (len(self.data) if self.len_override is None
                            else (self.len_override & 0xFF))


def parse_frames(buf: bytes) -> (List[Frame], int):
    """Split a byte stream into consecutive frames.

    Returns (frames, offset_of_first_unparsed_byte).  A frame is accepted only
    if the structure fits; the checksum is not required to be valid so that
    mutated (intentionally corrupt) inputs survive a decode/encode round trip.
    """
    frames: List[Frame] = []
    off = 0
    n = len(buf)
    while off + MIN_FRAME <= n:
        if buf[off] != START or buf[off + 7] != START:
            break
        L = buf[off + 9]
        total = MIN_FRAME + L
        if off + total > n:
            break
        avail = min(L, n - (off + 10))
        f = Frame(addr=bytes(buf[off + 1:off + 7]), ctrl=buf[off + 8],
                  data=bytes(buf[off + 10:off + 10 + avail]),
                  end=buf[off + 11 + L],
                  len_override=L if avail != L else None)
        frames.append(f)
        off += total
        if len(frames) > 64:      # bound the structured view
            break
    return frames, off


class FrameCodec:
    """Decode -> mutate -> encode pipeline used by the mutator."""

    @staticmethod
    def decode(buf: bytes) -> (List[Frame], bytes):
        frames, off = parse_frames(buf)
        return frames, buf[off:]

    @staticmethod
    def encode(frames: List[Frame], tail: bytes) -> bytes:
        return b"".join(f.encode() for f in frames) + tail
