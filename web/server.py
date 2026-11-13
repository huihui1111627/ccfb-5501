#!/usr/bin/env python3
"""Web console for the DL/T 645 fuzz campaign.

Pages
-----
  /               目标       target binary, build flags, planted defects
  /corpus         语料       seed generation, corpus contents, trim actions
  /monitor        运行监控   live exec rate, coverage, per worker stats
  /crashes        崩溃分桶   buckets grouped by root cause, reproducers
  /regression     回归       re-run reproducers on the fixed build

Run:
  python3 web/server.py --workdir runs/campaign --binary build/worker-buggy
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from flask import Flask, jsonify, render_template, request, send_from_directory

from fuzz645 import buckets as bucket_mod
from fuzz645.campaign import Campaign, CampaignConfig
from fuzz645.corpusmin import CorpusMinimiser
from fuzz645.minimize import Minimiser
from fuzz645.regress import run_regression
from fuzz645.store import Store

app = Flask(__name__, template_folder=os.path.join(ROOT, "web", "templates"),
            static_folder=os.path.join(ROOT, "web", "static"))

STATE: dict = {"campaign": None, "store": None, "cfg": None, "regression": None,
               "jobs": {}}
LOCK = threading.Lock()

DEFECTS = []          # filled from docs/defects.json at startup


def store() -> Store:
    return STATE["store"]


def campaign() -> Campaign:
    return STATE["campaign"]


def json_error(message: str, code: int = 400):
    return jsonify({"ok": False, "error": message}), code


# ----------------------------------------------------------------------
# pages
# ----------------------------------------------------------------------
@app.route("/")
def page_target():
    meta = store().get_meta("target", {})
    return render_template("target.html", defects=DEFECTS, meta=meta)


@app.route("/corpus")
def page_corpus():
    return render_template("corpus.html")


@app.route("/monitor")
def page_monitor():
    return render_template("monitor.html")


@app.route("/crashes")
def page_crashes():
    return render_template("crashes.html")


@app.route("/regression")
def page_regression():
    return render_template("regression.html")


# ----------------------------------------------------------------------
# API: target
# ----------------------------------------------------------------------
@app.route("/api/target")
def api_target():
    meta = store().get_meta("target", {})
    counts = {}
    for b in store().buckets():
        counts[b["location"]] = counts.get(b["location"], 0) + 1
    return jsonify({
        "ok": True,
        "meta": meta,
        "defects": DEFECTS,
        "status": campaign().status() if campaign() else None,
        "buckets": len(store().buckets()),
    })


# ----------------------------------------------------------------------
# API: corpus
# ----------------------------------------------------------------------
@app.route("/api/corpus")
def api_corpus():
    rows = store().corpus()
    by_origin = {}
    for r in rows:
        by_origin[r["origin"]] = by_origin.get(r["origin"], 0) + 1
    entries = []
    for r in sorted(rows, key=lambda r: r["added"]):
        entry = dict(r)
        entry.pop("path", None)
        try:
            with open(store().corpus_path(r), "rb") as fh:
                entry["preview"] = fh.read(64).hex()
        except OSError:
            entry["preview"] = ""
        entries.append(entry)
    trim = store().get_meta("last_trim")
    return jsonify({"ok": True, "count": len(rows), "by_origin": by_origin,
                    "entries": entries[-400:], "trim": trim})


@app.route("/api/corpus/<cid>", methods=["GET"])
def api_corpus_input(cid):
    row = store().db.execute("SELECT * FROM corpus WHERE id=?", (cid,)).fetchone()
    if not row:
        return json_error("unknown corpus id", 404)
    with open(store().corpus_path(dict(row)), "rb") as fh:
        data = fh.read()
    return jsonify({"ok": True, "id": cid, "hex": data.hex(),
                    "decoded": decode_hex(data)})


@app.route("/api/corpus/trim", methods=["POST"])
def api_corpus_trim():
    with LOCK:
        try:
            stats = campaign().trim_corpus(0.25)
            return jsonify({"ok": True, "stats": stats})
        except Exception as exc:
            return json_error(str(exc), 500)


@app.route("/api/corpus/minimize/<cid>", methods=["POST"])
def api_corpus_minimize(cid):
    row = store().db.execute("SELECT * FROM corpus WHERE id=?", (cid,)).fetchone()
    if not row:
        return json_error("unknown corpus id", 404)
    with open(store().corpus_path(dict(row)), "rb") as fh:
        data = fh.read()
    m = Minimiser(STATE["cfg"].binary, workdir=os.path.join(STATE["cfg"].workdir, "min-tmp"))
    out = m.minimise_plain(data, lambda d: not _crashes(d))
    return jsonify({"ok": True, "before": len(data), "after": len(out),
                    "hex": out.hex(), "execs": m.execs, "decoded": decode_hex(out)})


# ----------------------------------------------------------------------
# API: monitor
# ----------------------------------------------------------------------
@app.route("/api/status")
def api_status():
    camp = campaign()
    if camp is not None:
        return jsonify({"ok": True, "status": camp.status(),
                        "latest": (camp.samples[-1] if camp.samples else None)})
    # console opened without starting a campaign: report what the previous
    # run left in the database rather than a wall of zeros
    samples = store().samples(1)
    started = store().get_meta("started", 0) or 0
    finished = store().get_meta("finished", 0) or 0
    last = samples[-1] if samples else {}
    status = {
        "running": False,
        "started": started,
        "elapsed": (finished or time.time()) - started if started else 0,
        "execs": store().get_meta("execs_final", last.get("execs", 0)) or 0,
        "exec_rate": 0,
        "edges": last.get("edges", 0),
        "crashes": last.get("crashes", 0),
        "buckets": len(store().buckets()),
        "corpus": len(store().corpus()),
        "workers": [],
        "worker_errors": 0,
        "crash_rate": 0,
        "op_crash_yield": store().get_meta("op_crash_yield", {}),
    }
    return jsonify({"ok": True, "status": status, "latest": last or None})


@app.route("/api/samples")
def api_samples():
    limit = int(request.args.get("limit", 600))
    rows = store().samples(limit)
    camp = campaign()
    if camp and camp.samples and (not rows or time.time() - rows[-1]["at"] < 10):
        rows = rows + [{"at": time.time(), **camp.samples[-1]}]
    return jsonify({"ok": True, "samples": rows})


@app.route("/api/campaign/start", methods=["POST"])
def api_start():
    body = request.get_json(silent=True) or {}
    camp = campaign()
    with LOCK:
        if camp and camp.running:
            return json_error("campaign already running", 409)
        cfg = CampaignConfig(
            binary=STATE["cfg"].binary, workdir=STATE["cfg"].workdir,
            workers=int(body.get("workers", 8)),
            duration=float(body.get("duration", 1800)),
            seed=int(body.get("seed", 645)),
            minimize_every=float(body.get("minimize_every", 0)),
        )
        STATE["campaign"] = Campaign(cfg)
        STATE["campaign"].start()
        store().set_meta("target", {})
    return jsonify({"ok": True, "status": STATE["campaign"].status()})


@app.route("/api/campaign/stop", methods=["POST"])
def api_stop():
    camp = campaign()
    if camp and camp.running:
        camp.stop()
        return jsonify({"ok": True})
    return json_error("not running", 409)


@app.route("/api/ops")
def api_ops():
    return jsonify({"ok": True, "yield": store().get_meta("op_crash_yield", {}),
                    "minimised": store().get_meta("minimised", {})})


@app.route("/api/monitor/workers")
def api_workers():
    camp = campaign()
    return jsonify({"ok": True, "workers": camp.status()["workers"]})


# ----------------------------------------------------------------------
# API: crashes / buckets
# ----------------------------------------------------------------------
@app.route("/api/buckets")
def api_buckets():
    rows = store().buckets()
    minimised = store().get_meta("minimised") or {}
    out = []
    for b in rows:
        entry = dict(b)
        entry.pop("sample_report", None)
        entry["top_frames"] = json.loads(entry.get("top_frames") or "[]")
        entry["regression"] = json.loads(entry["regression"]) if entry.get("regression") else None
        entry["minimised"] = minimised.get(b["id"])
        entry["reproducer_ready"] = os.path.exists(
            os.path.join(store().root, "crashes", b["id"], "minimised"))
        out.append(entry)
    return jsonify({"ok": True, "buckets": out})


@app.route("/api/buckets/<bid>")
def api_bucket(bid):
    b = store().db.execute("SELECT * FROM buckets WHERE id=?", (bid,)).fetchone()
    if not b:
        return json_error("unknown bucket", 404)
    entry = dict(b)
    entry["top_frames"] = json.loads(entry.get("top_frames") or "[]")
    entry["regression"] = json.loads(entry["regression"]) if entry.get("regression") else None
    crashes = store().crashes(bid)
    for c in crashes:
        c.pop("report", None)
    return jsonify({"ok": True, "bucket": entry, "crashes": crashes,
                    "sample_report": b["sample_report"]})


@app.route("/api/buckets/<bid>/minimise", methods=["POST"])
def api_bucket_minimise(bid):
    b = store().db.execute("SELECT * FROM buckets WHERE id=?", (bid,)).fetchone()
    if not b:
        return json_error("unknown bucket", 404)
    cached = os.path.join(store().root, "crashes", bid, "minimised")
    if os.path.exists(cached):
        with open(cached, "rb") as fh:
            out = fh.read()
        command = "%s %s" % (STATE["cfg"].repro_binary,
                             os.path.relpath(cached, ROOT))
        before = len(out)
        meta = (store().get_meta("minimised") or {}).get(bid)
        if meta:
            before = meta.get("before", before)
        return jsonify({"ok": True, "bucket": bid, "cached": True,
                        "before": before, "after": len(out),
                        "hex": out.hex(), "execs": 0, "command": command,
                        "decoded": decode_hex(out)})
    crashes = store().crashes(bid)
    if not crashes:
        return json_error("bucket has no stored crash", 404)
    data = store().crash_input(crashes[0])
    m = Minimiser(STATE["cfg"].binary, workdir=os.path.join(STATE["cfg"].workdir, "min-tmp"))
    try:
        out, report = m.minimise(data, bid)
    except Exception as exc:
        return json_error(str(exc), 500)
    crash_dir = os.path.join(store().root, "crashes", bid, "minimised")
    with open(crash_dir, "wb") as fh:
        fh.write(out)
    binary = STATE["cfg"].repro_binary
    command = "%s %s" % (binary, os.path.relpath(crash_dir, ROOT))
    with open(crash_dir + ".txt", "w") as fh:
        fh.write(report)
    return jsonify({"ok": True, "bucket": bid, "before": len(data), "after": len(out),
                    "hex": out.hex(), "execs": m.execs, "command": command,
                    "decoded": decode_hex(out)})


@app.route("/api/crashes/<cid>/download")
def api_crash_download(cid):
    row = store().db.execute("SELECT * FROM crashes WHERE id=?", (cid,)).fetchone()
    if not row:
        return json_error("unknown crash", 404)
    path = row["input_path"]
    return send_from_directory(store().root, path, as_attachment=True,
                               download_name="input-%s.bin" % cid[:12])


@app.route("/api/buckets/<bid>/report")
def api_bucket_report(bid):
    b = store().db.execute("SELECT * FROM buckets WHERE id=?", (bid,)).fetchone()
    if not b:
        return json_error("unknown bucket", 404)
    return jsonify({"ok": True, "report": b["sample_report"]})


# ----------------------------------------------------------------------
# API: regression
# ----------------------------------------------------------------------
@app.route("/api/regression", methods=["GET"])
def api_regression_get():
    rows = []
    for b in store().buckets():
        reg = json.loads(b["regression"]) if b.get("regression") else None
        rows.append({"id": b["id"], "label": b["label"], "status": b["status"],
                     "bug_class": b["bug_class"], "location": b["location"],
                     "regression": reg})
    return jsonify({"ok": True, "last": store().get_meta("last_regression"),
                    "results": STATE.get("regression"), "buckets": rows})


@app.route("/api/regression/run", methods=["POST"])
def api_regression_run():
    with LOCK:
        fixed = STATE["cfg"].fixed_binary
        if not os.path.exists(fixed):
            return json_error("fixed build missing: run build.sh --fixed", 400)
        results = run_regression(store(), fixed)
        payload = [r.__dict__ for r in results]
        STATE["regression"] = payload
        STATUS["job"] = None
    return jsonify({"ok": True, "results": payload,
                    "summary": store().get_meta("last_regression")})


@app.route("/api/events")
def api_events():
    rows = store().db.execute(
        "SELECT at,kind,message FROM events ORDER BY at DESC LIMIT 200").fetchall()
    return jsonify({"ok": True, "events": [dict(r) for r in reversed(rows)]})


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def decode_hex(data: bytes):
    """Best effort human readable decode of an input."""
    from fuzz645.frames import FrameCodec
    frames, tail = FrameCodec.decode(data)
    out = []
    for f in frames:
        out.append({
            "address": f.addr.hex(),
            "ctrl": "%02X" % f.ctrl,
            "len": len(f.data),
            "declared_len": f.len_override if f.len_override is not None else len(f.data),
            "data": f.data.hex(),
            "end": "%02X" % f.end,
        })
    return {"frames": out, "tail": tail.hex(), "total": len(data)}


def _crashes(data: bytes) -> bool:
    from fuzz645.runner import Worker
    import tempfile
    with Worker(STATE["cfg"].binary, os.path.join(tempfile.mkdtemp(), "r.log")) as w:
        return w.run(data).crashed


STATUS = {"job": None}


# ----------------------------------------------------------------------
# bootstrap
# ----------------------------------------------------------------------
def load_defects():
    path = os.path.join(ROOT, "docs", "defects.json")
    try:
        with open(path) as fh:
            return json.load(fh)
    except OSError:
        return []


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workdir", default=os.path.join(ROOT, "runs", "campaign"))
    ap.add_argument("--binary", default=os.path.join(ROOT, "build", "worker-buggy"))
    ap.add_argument("--repro", default=os.path.join(ROOT, "build", "repro-buggy"))
    ap.add_argument("--fixed", default=os.path.join(ROOT, "build", "worker-fixed"))
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--duration", type=float, default=1800)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-autostart", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.workdir, exist_ok=True)
    STATE["store"] = Store(args.workdir)
    STATE["cfg"] = CampaignConfig(binary=args.binary, workdir=args.workdir,
                                  workers=args.workers, duration=args.duration)
    # paths used by the UI
    STATE["cfg"].fixed_binary = args.fixed
    STATE["cfg"].repro_binary = args.repro
    global DEFECTS
    DEFECTS = load_defects()

    store().set_meta("target", {
        "binary": args.binary,
        "fixed_binary": args.fixed,
        "repro": args.repro,
        "cc": "clang -O1 -g -fno-omit-frame-pointer "
              "-fsanitize=address -fsanitize-recover=address "
              "-fsanitize-coverage=trace-pc-guard,trace-cmp",
        "flags": "-fsanitize=address -fsanitize-recover=address "
                 "-fsanitize-coverage=trace-pc-guard,trace-cmp",
    })

    camp_file = None
    if not args.no_autostart:
        STATE["campaign"] = Campaign(STATE["cfg"])
        STATE["campaign"].start()
        print("campaign started: %d workers, %.0f s"
              % (args.workers, args.duration), file=sys.stderr)

    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
