"""Seed corpus generation from the DL/T 645 frame grammar.

Seeds are generated from the frame grammar rather than captured from the
field: the concentrator never gets to see every control code / data item
combination, so the corpus starts with one seed per interesting structure.
"""
from __future__ import annotations

import os
import random
from typing import List

from .frames import END, Frame, checksum

ADDRS = [
    bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),          # 广播
    bytes([0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),          # 通配
    bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
    bytes([0x78, 0x56, 0x34, 0x12, 0x00, 0x00]),
]

CONTROLS = [
    (0x11, "读数据 (2007)"),
    (0x12, "读后续数据"),
    (0x13, "读通信地址"),
    (0x14, "读数据 (1997)"),
    (0x15, "读冻结"),
    (0x16, "读事件"),
    (0x17, "读参数"),
    (0x18, "读密钥版本"),
    (0x19, "读通信速率"),
    (0x1A, "读日/月冻结"),
    (0x91, "读数据应答"),
    (0x92, "读后续应答"),
    (0x94, "1997 应答"),
    (0xB1, "写数据"),
    (0xC1, "写地址"),
    (0xD1, "写密钥"),
    (0xE1, "安全认证"),
    (0xF1, "跳闸/保电"),
]

DATA_ITEMS = [
    (b"\x00\x00\x00\x00", "当前组合有功总电能 DI 0x0000"),
    (b"\x10\x90\x00\x00", "电能量 DI 0x9010, dec=0"),
    (b"\x10\x90\x20\x00", "电能量 DI 0x9010, dec=2"),
    (b"\x10\x90\x70\x00", "电能量 DI 0x9010, dec=7"),
    (b"\x10\x90\xF0\x00", "电能量 DI 0x9010, dec=15 (非法 BCD)"),
    (b"\x00\x01\x02\x00", "正向有功总电能"),
    (b"\x02\x00\x80\x00", "变量 DI 0x0002"),
    (b"\x04\x00\x01\x02\x03\x04", "参变量 DI 0x0004"),
    (b"\x08\x00\x00\x00", "事件 DI 0x0008"),
    (b"\xFF\xFF\x00\x00", "保留 DI"),
    (b"\x00\x00", "最短数据项"),
]


def build_frames() -> List[bytes]:
    seeds: List[bytes] = []

    # 1. every control code with a representative data item
    for ctrl, _ in CONTROLS:
        for addr in ADDRS[:3]:
            data = DATA_ITEMS[1][0]
            f = Frame(addr=addr, ctrl=ctrl, data=data)
            seeds.append(f.encode())

    # 2. every data item under a read / answer control code
    for item, _ in DATA_ITEMS:
        for ctrl in (0x11, 0x91):
            f = Frame(addr=ADDRS[2], ctrl=ctrl, data=item)
            seeds.append(f.encode())

    # 3. stream of several concatenated frames (batch bookkeeping)
    stream = b"".join(Frame(addr=ADDRS[2], ctrl=ctrl, data=item).encode()
                      for ctrl, item in zip([0x91, 0x91, 0x91, 0x92],
                                            [i[0] for i in DATA_ITEMS[:4]]))
    seeds.append(stream)
    seeds.append(b"".join(Frame(addr=ADDRS[2], ctrl=0x91,
                                data=DATA_ITEMS[1][0]).encode() for _ in range(8)))

    # 4. damaged frames: the retransmission / checksum retry paths only run
    #    on frames whose checksum does not match
    good = Frame(addr=ADDRS[2], ctrl=0x91, data=b"\x00\x00\x00\x00")
    bad = Frame(addr=ADDRS[2], ctrl=0x91, data=b"\x00\x00\x00\x00",
                cs_override=checksum(good.encode()[:10]) ^ 0x5A)
    seeds.append(bad.encode())
    seeds.append(good.encode() + bad.encode())
    seeds.append(bad.encode() + good.encode() + bad.encode())

    # 5. 1997 style long frame (two byte length)
    body = bytes([0x68]) + ADDRS[2] + bytes([0x68, 0x94, 0xC8, 0x00]) + b"\x33" * 200
    seeds.append(body + bytes([checksum(body), END]))

    # 6. malformed / truncated shapes
    seeds.append(bytes([0x68]))
    seeds.append(bytes([0x68]) + ADDRS[2])
    seeds.append(bytes([0x68]) + ADDRS[2] + bytes([0x68]))
    seeds.append(bytes([0x68]) + ADDRS[2] + bytes([0x68, 0x11, 200]))
    seeds.append(good.encode()[:-1])
    seeds.append(good.encode() + b"\x16\x16")
    seeds.append(b"\x00" * 32)
    seeds.append(bytes(range(256)))

    return seeds


def write_corpus(directory: str) -> int:
    os.makedirs(directory, exist_ok=True)
    rng = random.Random(645)
    count = 0
    for raw in build_frames():
        path = os.path.join(directory, "seed-%04d" % count)
        with open(path, "wb") as fh:
            fh.write(raw)
        count += 1
    return count


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "corpus"
    print("wrote %d seeds to %s" % (write_corpus(target), target))
