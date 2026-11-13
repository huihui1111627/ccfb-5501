"""Crash normalisation and bucketing.

Every ASan report is reduced to a *root cause key* so that the same underlying
bug reached through different byte sequences, mutated lengths or unrelated
frames ends up in a single bucket:

  key = (bug_class, top_source_location, global_object_or_access_kind)

The top frame of an ASan report is unreliable for this: one screenshot of the
same defect can be a memcpy interceptor, a different call site inside the
parser or a sanitizer runtime helper.  So the key is built from the first
*frame that belongs to the project* plus the "located ... global variable"
hint that ASan prints for global overflows.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

ANSI = re.compile(r"\x1b\[[0-9;]*m")
FRAME = re.compile(r"^\s*#(\d+)\s+0x[0-9a-f]+\s+in\s+(\S+)\s+(\S+?)(?::(\d+))?$")
GLOBAL_OBJ = re.compile(r"global variable '([^']+)'")
FATAL = re.compile(r"ERROR: AddressSanitizer: fatal-signal-(\d+)", re.I)
SIGNAL = re.compile(r"ERROR: AddressSanitizer: (\w+) on unknown address")
KIND = re.compile(r"ERROR: AddressSanitizer: ([a-z][a-z\-]+)")
RUNTIME = re.compile(r"(libclang_rt|__asan|dyld|libsystem|libdyld)")
PROJ_SUFFIX = (".c", ".cc", ".cpp", ".h")

# ASan error classes that all describe the same kind of defect (an invalid
# memory access).  Which one is printed depends on the address layout of the
# moment, not on the root cause.
MEMORY_CLASSES = frozenset({
    "heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
    "heap-use-after-free", "use-after-free", "use-after-poison",
    "stack-use-after-return", "stack-use-after-scope", "double-free",
    "memcpy-param-overlap", "negative-size-param", "dynamic-stack-buffer-overflow",
    "container-overflow", "allocation-size-too-big", "intra-object-overflow",
    "unknown-crash",
})


@dataclass
class CrashSignature:
    bug_class: str
    location: str            # "file:line" of the first project frame
    function: str
    object_hint: str         # global variable or empty
    top_frames: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        """Root cause key: (memory safety family, function owning the access).

        ASan's own ``location`` is too fine grained: the high nibble and the
        low nibble of the same BCD decode are two different lines, and a 1997
        length overrun can be observed at the copy or at the trailer read.
        The *function* is the smallest unit that still separates distinct bugs
        here (``addr_decode``, ``dispatch``, ``parse_frame_1997``, ...).

        The error class is also coarsened.  The *same* overrunning copy in
        ``parse_frame_1997`` is reported as ``heap-buffer-overflow`` when it
        reads past the end of the heap object and as ``memcpy-param-overlap``
        when a later run happens to have the two ranges overlap -- ASan picks
        whichever check fires first on those bytes.  Those are one defect, so
        all memory-safety classes collapse into ``memory`` and only
        non-memory classes (``SEGV`` from a wild pointer, ``trap``) stay
        distinct.
        """
        raw = "%s|func:%s" % (self.family, self.function)
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    @property
    def family(self) -> str:
        if self.bug_class in MEMORY_CLASSES:
            return "memory"
        return self.bug_class

    @property
    def label(self) -> str:
        return "%s %s" % (self.bug_class, self.location)


def strip_ansi(text: str) -> str:
    return ANSI.sub("", text)


BT_LINE = re.compile(r"^\s*\d+\s+(\S+)\s+0x[0-9a-f]+\s+(\S+)\s*\+\s*(\d+)$")


def project_frames(report: str) -> List[Tuple[str, str, Optional[int]]]:
    """Frames that belong to the project (target/ or engine/), innermost first."""
    out = []
    for line in report.splitlines():
        m = FRAME.match(line.strip().rstrip(","))
        if m:
            _idx, func, file, line_no = m.groups()
            if RUNTIME.search(file) or RUNTIME.search(func):
                continue
            if file.endswith(PROJ_SUFFIX):
                out.append((func, file, int(line_no) if line_no else None))
            continue
        b = BT_LINE.match(line)
        if b:
            image, func, _off = b.groups()
            if RUNTIME.search(image) or RUNTIME.search(func):
                continue
            if func in ("main", "start", "_mh_execute_header"):
                continue
            out.append((func, image, None))
    return out


def classify(report: str) -> CrashSignature:
    text = strip_ansi(report)
    fat = FATAL.search(text)
    kind_m = KIND.search(text)
    sig_m = SIGNAL.search(text)
    if fat:
        sig = int(fat.group(1))
        bug_class = "trap" if sig == 5 else "fatal-signal-%d" % sig
    elif sig_m:
        # "SEGV on unknown address" -- a wild pointer, not a redzone overflow
        bug_class = sig_m.group(1)
    elif kind_m and not kind_m.group(1).startswith("fatal-signal"):
        bug_class = kind_m.group(1)
    elif "@@DEATH" in text:
        bug_class = "fatal-signal"
    else:
        bug_class = "unknown"

    obj_m = GLOBAL_OBJ.search(text)
    object_hint = obj_m.group(1).split(".")[-1] if obj_m else ""

    frames = project_frames(text)
    if frames:
        # innermost project frame + call chain
        func, file, line = frames[0]
        location = "%s:%s" % (file.split("/")[-1], line if line is not None else "?")
        func_name = func
    else:
        location = "no-project-frame"
        func_name = "?"
    chain = ["%s (%s:%s)" % (f, file.split("/")[-1], line if line is not None else "-")
             for f, file, line in frames[:4]]
    return CrashSignature(bug_class=bug_class, location=location,
                          function=func_name, object_hint=object_hint,
                          top_frames=chain)


def summarise(report: str) -> str:
    """One line human summary: the ASan SUMMARY line, or the signal line."""
    text = strip_ansi(report)
    for line in text.splitlines():
        if line.startswith("SUMMARY: AddressSanitizer"):
            return line.split(": ", 1)[-1]
    for line in text.splitlines():
        if "ERROR: AddressSanitizer" in line:
            return line.strip()
    if "@@DEATH" in text:
        return "worker died without an ASan report (fatal signal)"
    return "unrecognised crash report"


class BucketRegistry:
    """In-memory bucket table, persisted by the store."""

    def __init__(self):
        self.buckets: Dict[str, dict] = {}

    def ingest(self, signature: CrashSignature, crash_id: str, report: str,
               input_sha: str, size: int, timestamp: float) -> Tuple[str, bool]:
        key = signature.key
        created = False
        b = self.buckets.get(key)
        if b is None:
            b = {
                "id": key, "bug_class": signature.bug_class,
                "location": signature.location, "function": signature.function,
                "object_hint": signature.object_hint,
                "label": signature.label,
                "status": "open", "first_seen": timestamp, "last_seen": timestamp,
                "crashes": [], "unique_inputs": set(),
                "top_frames": signature.top_frames,
                "sample_report": report,
                "regression": None,
            }
            self.buckets[key] = b
            created = True
        b["last_seen"] = timestamp
        b["crashes"].append(crash_id)
        b["unique_inputs"].add(input_sha)
        return key, created
