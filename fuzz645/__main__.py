"""Command line driver for the DL/T 645 fuzz campaign.

    python3 -m fuzz645 run    --workdir runs/campaign --duration 1800 --workers 8
    python3 -m fuzz645 trim   --workdir runs/campaign
    python3 -m fuzz645 regress --workdir runs/campaign
    python3 -m fuzz645 report --workdir runs/campaign
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cmd_run(args) -> int:
    from .campaign import Campaign, CampaignConfig
    cfg = CampaignConfig(
        binary=args.binary, workdir=args.workdir, workers=args.workers,
        duration=args.duration, seed=args.seed,
        minimize_every=args.minimize_every,
    )
    c = Campaign(cfg)
    c.start()
    started = time.time()
    try:
        while c.running:
            time.sleep(args.report_every)
            s = c.status()
            print("[%6.0fs] execs=%7d rate=%6.1f/s edges=%4d crashes=%5d "
                  "buckets=%d corpus=%d"
                  % (time.time() - started, s["execs"], s["exec_rate"],
                     s["edges"], s["crashes"], s["buckets"], s["corpus"]),
                  flush=True)
            if args.duration and time.time() - started > args.duration + 300:
                break
    except KeyboardInterrupt:
        print("interrupted, stopping", flush=True)
    finally:
        c.stop()
        c.join(240)
    print(json.dumps({"execs": c.execs, "crashes": c.crashes,
                      "edges": c.cov.count, "buckets": len(c.store.buckets())}))
    return 0


def cmd_trim(args) -> int:
    from .campaign import Campaign, CampaignConfig
    cfg = CampaignConfig(binary=args.binary, workdir=args.workdir)
    c = Campaign(cfg)
    stats = c.trim_corpus(args.ratio)
    print(json.dumps(stats, indent=2))
    return 0


def cmd_regress(args) -> int:
    from .regress import run_regression
    from .store import Store
    st = Store(args.workdir)
    results = run_regression(st, args.fixed)
    for r in results:
        print("%-11s %-46s %s" % (r.status, r.label, r.new_signature or ""))
    print(json.dumps(st.get_meta("last_regression"), indent=2))
    return 0 if all(r.status == "fixed" for r in results) else 1


def cmd_report(args) -> int:
    from .store import Store
    st = Store(args.workdir)
    buckets = st.buckets()
    print("buckets: %d (%d open)" % (len(buckets),
                                    sum(1 for b in buckets if b["status"] != "fixed")))
    for b in buckets:
        print("  %-8s %-46s crashes=%-5d inputs=%-4d %s"
              % (b["status"], b["label"], b["total_crashes"],
                 b["unique_inputs"], b["id"]))
    last = st.get_meta("last_regression")
    if last:
        print("last regression: %s" % json.dumps(last))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="fuzz645", description=__doc__)
    ap.add_argument("--workdir", default=os.path.join(ROOT, "runs", "campaign"),
                    help="campaign directory (also accepted after the command)")
    ap.add_argument("--binary", default=os.path.join(ROOT, "build", "worker-buggy"))
    ap.add_argument("--fixed", default=os.path.join(ROOT, "build", "worker-fixed"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    global_opts = argparse.ArgumentParser(add_help=False)
    global_opts.add_argument("--workdir", dest="workdir", default=argparse.SUPPRESS)
    global_opts.add_argument("--binary", dest="binary", default=argparse.SUPPRESS)
    global_opts.add_argument("--fixed", dest="fixed", default=argparse.SUPPRESS)

    run = sub.add_parser("run", help="run a campaign", parents=[global_opts])
    run.add_argument("--duration", type=float, default=1800)
    run.add_argument("--workers", type=int, default=8)
    run.add_argument("--seed", type=int, default=645)
    run.add_argument("--minimize-every", type=float, default=0)
    run.add_argument("--report-every", type=float, default=30)
    run.set_defaults(func=cmd_run)

    trim = sub.add_parser("trim", help="minimise the corpus", parents=[global_opts])
    trim.add_argument("--ratio", type=float, default=0.25)
    trim.set_defaults(func=cmd_trim)

    reg = sub.add_parser("regress", help="replay reproducers on the fixed build",
                         parents=[global_opts])
    reg.set_defaults(func=cmd_regress)

    rep = sub.add_parser("report", help="print bucket status", parents=[global_opts])
    rep.set_defaults(func=cmd_report)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
