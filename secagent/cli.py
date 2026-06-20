"""secagent CLI — capture a browse into the map, then report on it."""

from __future__ import annotations

import argparse

from . import recon, report
from .allowlist import TargetNotAllowed
from .env import load_dotenv


def main(argv: list[str] | None = None) -> int:
    # Load secrets from .env (ANTHROPIC_API_KEY) before any command runs. No-op if
    # the file is absent; an already-exported env var still wins.
    load_dotenv()
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

    h = sub.add_parser("hunt", help="autonomously hunt a lab from goal-only (needs ANTHROPIC_API_KEY)")
    h.add_argument("target", help="the lab instance URL (e.g. https://0a1b.web-security-academy.net)")
    h.add_argument("--goal", required=True, help="the lab goal text — the ONLY hint the agent gets")
    h.add_argument("--lab-id", required=True, help="stable label for this lab, e.g. sqli-login-bypass")
    h.add_argument("--db", default="recon.db")
    h.add_argument("--model", default="claude-opus-4-8")
    h.add_argument("--allow-host", action="append", default=[])
    h.add_argument("--allow-suffix", action="append", default=[],
                   help="extra allowed host suffix (e.g. .example-lab.net)")
    h.add_argument("--no-default-suffix", action="store_true",
                   help="do NOT auto-allow *.web-security-academy.net")
    h.add_argument("--headless", action="store_true")
    h.add_argument("--max-steps", type=int, default=12)
    h.add_argument("--max-requests", type=int, default=40)
    h.add_argument("--max-seconds", type=float, default=300.0)
    h.add_argument("--rate-pause", type=float, default=0.0,
                   help="seconds to pause between network actions (politeness / rate limit)")

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

    if args.cmd == "hunt":
        from .allowlist import WEB_SECURITY_ACADEMY_SUFFIX, assert_allowed

        hosts = tuple(args.allow_host)
        suffixes = tuple(args.allow_suffix)
        if not args.no_default_suffix:
            suffixes += (WEB_SECURITY_ACADEMY_SUFFIX,)

        # Allowlist refusal happens BEFORE importing the browser/LLM stack, so a
        # mis-typed target exits cleanly without a heavy import (and mirrors capture).
        try:
            assert_allowed(args.target, hosts, suffixes)
        except TargetNotAllowed as e:
            print(f"refused: {e}")
            return 2

        from .hunter import AnthropicHunter, run_hunt
        from .scorer import read_status
        from .session import open_session
        from .status import TOOL_ERROR
        from .store import Store

        store = Store(args.db)
        store.finalize_unfinished(TOOL_ERROR)  # crash recovery for any prior killed run
        llm = AnthropicHunter(args.model)
        try:
            with open_session(
                args.target, extra_hosts=hosts, extra_suffixes=suffixes, headless=args.headless
            ) as (session, scorer_page):

                def scorer_read():
                    # Isolated read (R1): reload the lab on a SEPARATE page and read its
                    # banner — never touches the hunter's active page.
                    def provider():
                        scorer_page.goto(args.target, wait_until="domcontentloaded")
                        return scorer_page.content()

                    return read_status(provider)

                final = run_hunt(
                    session=session, scorer_read=scorer_read, llm=llm, store=store,
                    lab_id=args.lab_id, base_url=args.target, goal=args.goal,
                    max_steps=args.max_steps, max_requests=args.max_requests,
                    max_seconds=args.max_seconds, rate_limit_pause_s=args.rate_pause,
                )
            print(f"hunt [{final.get('status')}] lab={args.lab_id} -> {args.db}")
            return 0
        finally:
            store.close()

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
