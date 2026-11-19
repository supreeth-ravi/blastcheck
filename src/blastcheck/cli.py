"""Command line: `blastcheck check` answers "are we affected?" for a whole GitHub org."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from . import __version__, confirm, incident as incident_mod, inventory, matcher, notify, report
from .github import GitHub, GitHubError, resolve_token
from .models import AFFECTED, AT_RISK, INCOMPLETE, Incident

EXIT = {AFFECTED: 1, AT_RISK: 1, INCOMPLETE: 2}
DEFAULT_CACHE = ".blastcheck/inventory.json"
DEFAULT_OUT = ".blastcheck/reports"
_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")


def say(message: str) -> None:
    sys.stderr.write(message + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blastcheck", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--org", required=True, help="GitHub org (or user) whose repos are checked")
        p.add_argument("--cache", default=DEFAULT_CACHE, help=f"inventory cache file (default {DEFAULT_CACHE})")
        p.add_argument("--no-cache", action="store_true", help="re-read every repo")
        p.add_argument("--include-archived", action="store_true")
        p.add_argument("--workers", type=int, default=8)
        p.add_argument("--quiet", action="store_true")

    setup = sub.add_parser("setup", help="build the inventory and show what the token can and cannot read")
    common(setup)

    check = sub.add_parser("check", help="check every repo against one incident")
    common(check)
    source = check.add_argument_group("incident (give a package, a URL, or a file)")
    source.add_argument("--package")
    source.add_argument("--ecosystem", help="PyPI, npm, Go, crates.io or Maven")
    source.add_argument("--bad", help="comma-separated bad versions, e.g. 1.26.1,1.26.2")
    source.add_argument("--last-clean")
    source.add_argument("--window", help="when the bad versions were live, free text")
    source.add_argument("--kind", default="malware", choices=["malware", "vulnerability"])
    source.add_argument("--title")
    source.add_argument("--source", action="append", default=[], help="reference link (repeatable)")
    source.add_argument("--url", help="article to read with Claude (needs blastcheck[ai] and a key)")
    source.add_argument("--incident", help="path to a saved incident JSON file")
    check.add_argument("--no-confirm", action="store_true", help="skip the OSV/registry confirmation lookup")
    check.add_argument("--out", default=DEFAULT_OUT, help=f"folder for the report files (default {DEFAULT_OUT})")
    check.add_argument("--issue-repo", help="owner/name of the repo to write the incident issue in")
    check.add_argument("--allow-public-issue-repo", action="store_true",
                       help="write the issue even if that repo is public (it will expose private repo names)")
    check.add_argument("--notify", action="store_true", help="send to Slack/email if configured in the environment")
    check.add_argument("--json", action="store_true", help="print the JSON summary to stdout")
    return parser


def load_incident(args: argparse.Namespace) -> Incident:
    given = [bool(args.incident), bool(args.url), bool(args.package)]
    if sum(given) != 1:
        raise incident_mod.IncidentError("give exactly one of --incident, --url, or --package with --ecosystem and --bad")
    if args.incident:
        return incident_mod.load(args.incident)
    if args.url:
        from . import extract  # optional path; keeps the core free of AI dependencies
        return extract.from_url(args.url)
    if not args.ecosystem or not args.bad:
        raise incident_mod.IncidentError("--package needs --ecosystem and --bad")
    return incident_mod.from_mapping({
        "package": args.package, "ecosystem": args.ecosystem, "bad_versions": args.bad,
        "last_clean": args.last_clean, "window": args.window, "kind": args.kind,
        "title": args.title, "sources": args.source,
    }, origin="manual")


def get_inventory(args: argparse.Namespace, gh: GitHub) -> tuple[dict, tuple[str, ...]]:
    if not _OWNER.match(args.org):
        raise GitHubError(400, f"{args.org!r} is not a valid GitHub org or user name")
    cache = {} if args.no_cache else inventory.load_cache(args.cache, args.org)
    progress = None if args.quiet else say
    result, skipped = inventory.build(gh, args.org, cache, args.include_archived, args.workers, progress)
    if not result:
        raise GitHubError(404, f"no repos visible in {args.org!r}; check the org name and the token's access")
    inventory.save_cache(args.cache, args.org, result)
    return result, skipped


def write_issue(args: argparse.Namespace, marker: str, title: str, body: str) -> str:
    """Create or update the incident issue. Refuses a public repo unless explicitly allowed."""
    if not _REPO.match(args.issue_repo):
        say(f"--issue-repo must look like owner/name, not {args.issue_repo!r}; no issue written")
        return ""
    writer = GitHub(resolve_token(names=("BLASTCHECK_ISSUE_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")))
    try:
        if not args.allow_public_issue_repo and not writer.is_private(args.issue_repo):
            say(f"{args.issue_repo} is public, so no issue was written: the report names private repos and files. "
                "Use a private repo, or pass --allow-public-issue-repo.")
            return ""
        url = writer.upsert_issue(args.issue_repo, marker, title, body)
        say(f"issue: {url}")
        return url
    except GitHubError as exc:
        say(f"could not write the issue in {args.issue_repo}: {exc}")
        return ""


def cmd_setup(args: argparse.Namespace) -> int:
    inventories, skipped = get_inventory(args, GitHub(resolve_token()))
    with_files = [i for i in inventories.values() if i.files_read]
    problems = [i for i in inventories.values() if i.errors]
    say(f"\n{len(inventories)} repos visible in {args.org}; {len(with_files)} have dependency files; "
        f"{sum(len(i.deps) for i in inventories.values())} dependency lines read.")
    for inv in problems:
        say(f"  could not fully read {inv.repo}: {inv.errors[0]}")
    if skipped:
        say(f"  {len(skipped)} archived repos skipped (use --include-archived to read them)")
    say("If a repo you expect is missing from the count, the token cannot see it.")
    return 2 if problems else 0


def cmd_check(args: argparse.Namespace) -> int:
    incident = load_incident(args)
    if not args.no_confirm:
        incident = incident_mod.with_confirmation(incident, confirm.confirm(incident))
    gh = GitHub(resolve_token())
    inventories, skipped = get_inventory(args, gh)
    results = matcher.match(incident, inventories.values())
    worst = matcher.headline(results)

    body = report.issue_body(incident, results, inventories, args.org, skipped=skipped)
    summary = report.summary(incident, results, args.org, skipped)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{incident.slug}.md").write_text(body + "\n")
    (out / f"{incident.slug}.json").write_text(json.dumps(summary, indent=2) + "\n")
    incident_mod.save(incident, out / f"{incident.slug}.incident.json")

    issue_url = ""
    if args.issue_repo:
        issue_url = write_issue(args, report.marker(incident), report.title(incident, results), body)
    if args.notify:
        text = notify.notice(report.HEADLINES[worst], incident.package, summary["reply"], issue_url)
        for outcome in notify.deliver(text, report.title(incident, results)):
            say(outcome)

    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as handle:
            handle.write(body + "\n")
    if args.json:
        sys.stdout.write(json.dumps({**summary, "issue_url": issue_url}, indent=2) + "\n")
    else:
        sys.stdout.write(f"\n{report.HEADLINES[worst]}\n{incident.confirmation.status}: "
                         f"{'; '.join(incident.confirmation.evidence)}\n\n{summary['reply']}\n\n"
                         f"Full report: {out / (incident.slug + '.md')}\n")
    return EXIT.get(worst, 0)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return cmd_setup(args) if args.command == "setup" else cmd_check(args)
    except incident_mod.IncidentError as exc:
        say(f"incident problem: {exc}")
    except GitHubError as exc:
        say(f"GitHub problem: {exc}")
    except Exception as exc:  # last-resort boundary: show a clear message, exit non-zero
        if type(exc).__name__ == "ExtractError":
            say(f"article problem: {exc}")
        else:
            raise
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
