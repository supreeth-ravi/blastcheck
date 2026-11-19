"""Command line: `blastcheck check` answers "are we affected?" for a whole GitHub org."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from . import __version__, confirm, incident as incident_mod, inventory, matcher, notify, report, watch
from .branches import Settings
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
        p.add_argument("--no-branches", action="store_true", help="read default branches only")
        p.add_argument("--branch-days", type=int, default=30,
                       help="also read branches pushed within this many days (default 30; 0 = deploy-named only)")
        p.add_argument("--max-branches", type=int, default=15, help="most extra branches read per repo (default 15)")
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

    sweep = sub.add_parser("watch", help="find known-malicious releases among the packages the org uses")
    common(sweep)
    sweep.add_argument("--recent-days", type=int, default=7,
                       help="report loose version ranges only for advisories this recent (default 7)")

    for p in (check, sweep):
        p.add_argument("--out", default=DEFAULT_OUT, help=f"folder for the report files (default {DEFAULT_OUT})")
        p.add_argument("--issue-repo", help="owner/name of the repo to write the incident issue in")
        p.add_argument("--allow-public-issue-repo", action="store_true",
                       help="write the issue even if that repo is public (it will expose private repo names)")
        p.add_argument("--notify", action="store_true", help="send to Slack/email if configured in the environment")
        p.add_argument("--json", action="store_true", help="print the JSON summary to stdout")
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
    settings = Settings(enabled=not args.no_branches, days=max(0, args.branch_days), limit=max(0, args.max_branches))
    cache = {} if args.no_cache else inventory.load_cache(args.cache, args.org, settings)
    progress = None if args.quiet else say
    result, skipped = inventory.build(gh, args.org, cache, args.include_archived, args.workers, progress, settings)
    if not result:
        raise GitHubError(404, f"no repos visible in {args.org!r}; check the org name and the token's access")
    inventory.save_cache(args.cache, args.org, result, settings)
    return result, skipped


def write_issue(args: argparse.Namespace, marker: str, title: str, body: str, reopen: bool = True,
                ) -> tuple[str, bool]:
    """Create or update the incident issue. Returns (issue URL, whether the repo is safe to publish to).

    A public repo is refused unless explicitly allowed, and so is one whose visibility could
    not be established: the report names private repos and files.
    """
    if not _REPO.match(args.issue_repo):
        say(f"--issue-repo must look like owner/name, not {args.issue_repo!r}; no issue written")
        return "", False
    writer = GitHub(resolve_token(names=("BLASTCHECK_ISSUE_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")))
    try:
        if not args.allow_public_issue_repo and not writer.is_private(args.issue_repo):
            say(f"{args.issue_repo} is public, so no issue or run summary was written: the report names private "
                "repos and files. Use a private repo, or pass --allow-public-issue-repo.")
            return "", False
    except GitHubError as exc:
        say(f"could not check whether {args.issue_repo} is private, so nothing was published there: {exc}")
        return "", False
    try:
        url = writer.upsert_issue(args.issue_repo, marker, title, body, reopen)
        say(f"issue: {url}")
        return url, True
    except GitHubError as exc:
        say(f"could not write the issue in {args.issue_repo}: {exc}")
        return "", True


class PublicRepoError(Exception):
    """Running in CI with a public (or unverifiable) target repo: stop before anything is logged."""


def preflight(args: argparse.Namespace) -> None:
    """In CI, logs, caches and artifacts are as visible as the repo the job runs in.

    So when running under GitHub Actions the target repo's visibility is checked before any
    work is done, not just before the issue is written. On a laptop the output only goes to the
    person running it, and the softer gate in write_issue() is enough.
    """
    if os.environ.get("GITHUB_ACTIONS") != "true" or not getattr(args, "issue_repo", None):
        return
    if args.allow_public_issue_repo:
        return
    if not _REPO.match(args.issue_repo):
        raise PublicRepoError(f"--issue-repo must look like owner/name, not {args.issue_repo!r}")
    writer = GitHub(resolve_token(names=("BLASTCHECK_ISSUE_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")))
    try:
        private = writer.is_private(args.issue_repo)
    except GitHubError as exc:
        raise PublicRepoError(f"could not confirm that {args.issue_repo} is private ({exc}); nothing was run") from exc
    if not private:
        raise PublicRepoError(
            f"{args.issue_repo} is public. The report, logs and cache would expose private repo names, so nothing "
            "was run. Run blastcheck from a private repo, or set allow-public if you really mean to.")


def cmd_setup(args: argparse.Namespace) -> int:
    inventories, skipped = get_inventory(args, GitHub(resolve_token()))
    with_files = [i for i in inventories.values() if i.files_read]
    problems = [i for i in inventories.values() if i.errors]
    say(f"\n{len(inventories)} repos visible in {args.org}; {len(with_files)} have dependency files; "
        f"{sum(len(i.deps) for i in inventories.values())} dependency lines read; "
        f"{sum(len(i.branches) for i in inventories.values())} other branches checked.")
    for inv in problems:
        say(f"  could not fully read {inv.repo}: {inv.errors[0]}")
    if skipped:
        say(f"  {len(skipped)} archived repos skipped (use --include-archived to read them)")
    private = sum(1 for i in inventories.values() if i.visibility == "private")
    say(f"  {private} private and {len(inventories) - private} public repos are visible to this token.")
    if report.only_public_visible(inventories):
        say(f"  WARNING: {report.PUBLIC_ONLY_WARNING}")
    say("If a repo you expect is missing from the count, the token cannot see it.")
    return 2 if problems else 0


def publish(args: argparse.Namespace, incident: Incident, results: tuple, inventories: dict, skipped: tuple[str, ...],
            reopen: bool) -> tuple[dict, str, bool]:
    """Write the report files, the issue, notices and run summary for one incident.

    Returns (summary, issue URL, whether the target repo is safe to publish to).
    """
    worst = matcher.headline(results)
    body = report.issue_body(incident, results, inventories, args.org, skipped=skipped)
    summary = report.summary(incident, results, args.org, skipped, inventories)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{incident.slug}.md").write_text(body + "\n")
    (out / f"{incident.slug}.json").write_text(json.dumps(summary, indent=2) + "\n")
    incident_mod.save(incident, out / f"{incident.slug}.incident.json")

    issue_url, publishable = "", True
    if args.issue_repo:
        issue_url, publishable = write_issue(args, report.marker(incident), report.title(incident, results), body, reopen)
    if args.notify:
        text = notify.notice(report.HEADLINES[worst], incident.package, summary["reply"], issue_url)
        for outcome in notify.deliver(text, report.title(incident, results)):
            say(outcome)

    # The run summary is as visible as the repo the workflow runs in: same gate as the issue.
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file and publishable:
        with open(summary_file, "a") as handle:
            handle.write(body + "\n")
    return summary, issue_url, publishable


def cmd_watch(args: argparse.Namespace) -> int:
    preflight(args)
    inventories, skipped = get_inventory(args, GitHub(resolve_token()))
    result = watch.sweep(inventories.values(), args.recent_days)
    unread = sorted(inv.repo for inv in inventories.values() if inv.errors or any(b.errors for b in inv.branches))
    found = []
    for match in result.matches:
        summary, issue_url, _ = publish(args, match.incident, match.results, inventories, skipped, reopen=False)
        found.append({"advisory": match.incident.advisory_id, "published": match.published[:10],
                      "package": match.incident.package, "ecosystem": match.incident.ecosystem,
                      "headline": summary["headline"], "repos": summary["repos"], "issue_url": issue_url})
    line = (f"Asked OSV about {result.packages} packages used in {len(inventories)} repos: {result.advisories} malware "
            f"advisories exist for them, {len(found)} match what the org uses"
            + (f", {result.quiet} concern only versions the org does not use" if result.quiet else "") + ".")
    caveats = list(result.notes)
    if unread:
        caveats.append(f"{len(unread)} repos could not be fully read, so the sweep did not cover them completely: "
                       + ", ".join(unread[:10]))
    if skipped:
        caveats.append(f"{len(skipped)} archived repos were not checked")
    if report.only_public_visible(inventories):
        caveats.append(report.PUBLIC_ONLY_WARNING)
    if args.json:
        sys.stdout.write(json.dumps({"owner": args.org, "packages": result.packages, "advisories": result.advisories,
                                     "matches": found, "quiet": result.quiet, "caveats": caveats}, indent=2) + "\n")
    else:
        sys.stdout.write("\n" + line + "\n")
        for item in found:
            affected = item["repos"]["affected"] + item["repos"]["at_risk"]
            sys.stdout.write(f"  {item['advisory']} {item['package']} ({item['ecosystem']}): {item['headline']} in "
                             f"{', '.join(affected)} {item['issue_url']}\n")
        for caveat in caveats:
            sys.stdout.write(f"  note: {caveat}\n")
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file and not found:
        with open(summary_file, "a") as handle:  # counts only: safe to show in any repo
            handle.write(f"### blastcheck daily sweep\n\n{line}\n")
            for caveat in caveats:
                if caveat == report.PUBLIC_ONLY_WARNING:
                    handle.write(f"\n> **Warning: {caveat}**\n")
    return 1 if found else 0


def cmd_check(args: argparse.Namespace) -> int:
    preflight(args)
    incident = load_incident(args)
    if not args.no_confirm:
        incident = incident_mod.with_confirmation(incident, confirm.confirm(incident))
    gh = GitHub(resolve_token())
    inventories, skipped = get_inventory(args, gh)
    results = matcher.match(incident, inventories.values())
    worst = matcher.headline(results)

    summary, issue_url, _ = publish(args, incident, results, inventories, skipped, reopen=True)
    out = Path(args.out)
    if args.json:
        sys.stdout.write(json.dumps({**summary, "issue_url": issue_url}, indent=2) + "\n")
    else:
        if summary["only_public_repos_visible"]:
            sys.stdout.write(f"\nWARNING: {report.PUBLIC_ONLY_WARNING}\n")
        sys.stdout.write(f"\n{report.HEADLINES[worst]}\n{incident.confirmation.status}: "
                         f"{'; '.join(incident.confirmation.evidence)}\n\n{summary['reply']}\n\n"
                         f"Full report: {out / (incident.slug + '.md')}\n")
    return EXIT.get(worst, 0)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return {"setup": cmd_setup, "check": cmd_check, "watch": cmd_watch}[args.command](args)
    except incident_mod.IncidentError as exc:
        say(f"incident problem: {exc}")
    except watch.WatchError as exc:
        say(f"sweep problem: {exc}")
    except PublicRepoError as exc:
        say(f"::error::{exc}" if os.environ.get("GITHUB_ACTIONS") == "true" else str(exc))
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
