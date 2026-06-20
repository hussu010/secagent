"""secagent CLI — capture a browse into the map, then report on it."""

from __future__ import annotations

import argparse

from . import recon, report
from .allowlist import TargetNotAllowed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secagent", description="black-box web recon companion")
    sub = parser.add_subparsers(dest="cmd", required=True)

    cap = sub.add_parser("capture", help="capture a manual browse into the attack-surface map")
    cap.add_argument("target", nargs="?", default="http://localhost:3000")
    cap.add_argument("--db", default="recon.db")
    cap.add_argument("--allow-host", action="append", default=[],
                     help="permit a non-loopback target host (use only if authorized)")
    cap.add_argument("--record", default=None, help="also dump raw events to a fixture JSON")

    rep = sub.add_parser("report", help="print the attack-surface map")
    rep.add_argument("--db", default="recon.db")
    rep.add_argument("--html", default=None, help="also write an HTML report to this path")

    ann = sub.add_parser("annotate", help="summarize pending pages (needs ANTHROPIC_API_KEY)")
    ann.add_argument("--db", default="recon.db")
    ann.add_argument("--model", default="claude-sonnet-4-6")

    args = parser.parse_args(argv)

    if args.cmd == "capture":
        try:
            summary = recon.run_session(
                args.target, args.db,
                extra_hosts=tuple(args.allow_host),
                record_to=args.record,
            )
        except TargetNotAllowed as e:
            print(f"refused: {e}")
            return 2
        print(f"captured {summary['endpoints']} endpoints across {summary['pages']} pages "
              f"({summary['events']} events) -> {summary['db']}")
        return 0

    if args.cmd == "report":
        report.render(args.db, html_path=args.html)
        return 0

    if args.cmd == "annotate":
        from . import annotate as annotator
        from .store import Store

        client = annotator.anthropic_client(args.model)
        store = Store(args.db)
        try:
            counts = annotator.annotate_pending(store, client)
        finally:
            store.close()
        print(f"annotated: {counts['ok']} ok, {counts['missing']} missing, "
              f"{counts['skipped']} skipped")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
