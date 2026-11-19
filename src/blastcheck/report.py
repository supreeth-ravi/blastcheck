"""Turn results into the incident issue, a forwardable reply, and a JSON summary.

Everything that originates in a scanned repo (file paths, version specifiers, parse errors)
or in an article (title, indicators) is untrusted and is escaped before it reaches markdown.
"""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone

from .matcher import headline
from .models import AFFECTED, AT_RISK, INCOMPLETE, NOT_USED, SAFE_VERSION, Incident, RepoInventory, RepoResult

HEADLINES = {
    AFFECTED: "AFFECTED — a known-bad version is pinned",
    AT_RISK: "AT RISK — a loose version range could have pulled a bad version",
    INCOMPLETE: "INCOMPLETE — nothing bad found, but some repos could not be fully read",
    SAFE_VERSION: "NO BAD VERSION PINNED — the package is used, at safe versions only",
    NOT_USED: "NOT AFFECTED — the package is not used in any repo",
}
MAX_ROWS = 60
_CONTROL = re.compile(r"[\x00-\x1f\x7f  ]+")
_MARKDOWN = re.compile(r"([\\`*_{}\[\]()<>#|!~])")


def code(text: object, limit: int = 120, table: bool = False) -> str:
    """Untrusted text as an inline code span that cannot be closed from inside."""
    clean = _CONTROL.sub(" ", str(text)).strip()[:limit].replace("`", "'")
    if table:
        clean = clean.replace("|", "\\|")
    return f"`{clean}`" if clean else "(empty)"


def plain(text: object, limit: int = 300) -> str:
    """Untrusted text as inert prose: no links, images, HTML, tables or @mentions."""
    clean = _CONTROL.sub(" ", str(text)).strip()[:limit]
    clean = clean.replace("&", "&amp;")
    return _MARKDOWN.sub(r"\\\1", clean).replace("@", "@​")


def marker(incident: Incident) -> str:
    return f"<!-- blastcheck:{incident.slug} -->"


def title(incident: Incident, results: Iterable[RepoResult]) -> str:
    label = HEADLINES[headline(results)].split(" — ")[0]
    return f"[blastcheck] {incident.package} {incident.versions_text}: {label}"[:250]


def _by_verdict(results: Iterable[RepoResult], verdict: str) -> list[RepoResult]:
    return [r for r in results if r.verdict == verdict]


def _evidence_rows(results: list[RepoResult]) -> list[str]:
    rows = ["| Repo | Branch | File | Declared as |", "|---|---|---|---|"]
    total = sum(len(r.evidence) for r in results)
    count = 0
    for result in results:
        for dep in result.evidence:
            if count >= MAX_ROWS:
                rows.append(f"| … | | {total - count} more rows not shown | |")
                return rows
            joiner = "@" if dep.ecosystem == "npm" else (" " if dep.ecosystem in ("Go", "crates.io", "Maven") else "")
            declared = f"{dep.name}{joiner}{dep.spec}" if dep.spec else f"{dep.name} (no version)"
            if dep.via == "conda":
                declared += " (Conda package)"
            branch = code(dep.ref, table=True) if dep.ref else "default"
            rows.append(f"| {code(result.repo, table=True)} | {branch} | {code(dep.file, table=True)} "
                        f"| {code(declared, table=True)} |")
            count += 1
    return rows


def _confirmation_line(incident: Incident) -> str:
    conf = incident.confirmation
    evidence = "; ".join(plain(item) for item in conf.evidence)
    if conf.status == "confirmed":
        return "**Confirmed** by an outside source: " + evidence
    origin = {"article": "an article", "manual": "manual entry", "file": "an incident file",
              "advisory": "a published advisory"}.get(incident.origin, "manual entry")
    return (f"**Unconfirmed.** This incident comes from {origin} and no outside source has confirmed it yet. "
            + evidence)


def _checklist(incident: Incident, results: tuple[RepoResult, ...], skipped: tuple[str, ...]) -> list[str]:
    worst = headline(results)
    package = code(incident.package)
    bad = incident.versions_text
    steps: list[str] = []
    if _by_verdict(results, INCOMPLETE):
        steps.append("- [ ] Check the repos listed under \"Could not fully check\" by hand, or fix access and re-run")
    if worst in (AFFECTED, AT_RISK) and incident.kind == "malware":
        steps += [
            "- [ ] Do not run the affected environments; rebuild them from a clean base instead of cleaning in place",
            "- [ ] Find where the listed repos were installed or built since the bad release (CI runs, images, laptops)",
            "- [ ] Rotate every credential those environments could read, from a clean machine"
            + (f": {', '.join(plain(c, 80) for c in incident.credentials_at_risk)}" if incident.credentials_at_risk else ""),
            "- [ ] Review audit logs for use of those credentials after the install time",
        ]
        if incident.indicators:
            steps.append("- [ ] Look for these signs of compromise (as reported by the source, not verified here): "
                         + ", ".join(code(i) for i in incident.indicators))
    if worst in (AFFECTED, AT_RISK):
        target = code(incident.last_clean) if incident.last_clean else "a known-clean version"
        steps.append(f"- [ ] Pin {package} to {target} in the listed files and regenerate lock files")
    if incident.kind == "malware" and _by_verdict(results, SAFE_VERSION):
        steps.append("- [ ] For repos using the package at a safe version: a lock file that is safe today does not prove "
                     "a bad version was never installed. Check their CI and lock file history"
                     + (f" for the exposure window ({plain(incident.window)})" if incident.window else ""))
    steps += [
        f"- [ ] Block {package} {bad} in any package proxy or allow-list",
        f"- [ ] Ask the team whether anyone installed {package} by hand"
        + (f" during the exposure window ({plain(incident.window)})" if incident.window else "")
        + "; this scan cannot see laptops or servers",
    ]
    if skipped:
        steps.append(f"- [ ] {len(skipped)} archived repos were not checked; re-run with `--include-archived` if any are still deployed")
    return steps


def visible_counts(inventories: dict[str, RepoInventory]) -> tuple[int, int]:
    """(private, public) repos the token could see, among those whose visibility is known."""
    private = sum(1 for inv in inventories.values() if inv.visibility == "private")
    public = sum(1 for inv in inventories.values() if inv.visibility == "public")
    return private, public


def _coverage(results: tuple[RepoResult, ...], skipped: tuple[str, ...]) -> tuple[str, str]:
    """(opening words, caveat sentence). Says "all" only when nothing was left unread or skipped."""
    unread = len(_by_verdict(results, INCOMPLETE))
    caveats = []
    if unread:
        caveats.append(f"{unread} {'repo' if unread == 1 else 'repos'} could not be fully read, so this is not yet "
                       f"a complete answer; we are checking those by hand")
    if skipped:
        caveats.append(f"{len(skipped)} archived {'repo was' if len(skipped) == 1 else 'repos were'} not checked")
    opening = f"We checked all {len(results)} repos" if not caveats else f"We checked {len(results)} repos"
    return opening, (" " + ". ".join(caveats) + ".") if caveats else ""


def branch_coverage(inventories: dict[str, RepoInventory]) -> tuple[int, int, list[str]]:
    """(other branches checked, how many differed in dependency files, notes on limits)."""
    checked = sum(len(inv.branches) for inv in inventories.values())
    differing = sum(1 for inv in inventories.values() for branch in inv.branches if branch.differs)
    notes = Counter(inv.branch_note for inv in inventories.values() if inv.branch_note)
    return checked, differing, [f"{note} ({count} {'repo' if count == 1 else 'repos'})" for note, count in notes.most_common(4)]


def reply(incident: Incident, results: tuple[RepoResult, ...], skipped: tuple[str, ...] = (),
          branches_checked: int = 0) -> str:
    """A short plain-text answer suitable for forwarding. Never overstates what was checked."""
    worst = headline(results)
    opening, caveat = _coverage(results, skipped)
    affected = [r.repo for r in _by_verdict(results, AFFECTED)]
    at_risk = [r.repo for r in _by_verdict(results, AT_RISK)]
    bad = incident.versions_text
    name = incident.package
    if worst == AFFECTED:
        body = (f"{opening}. {len(affected)} pin an affected version of {name} ({bad}): {', '.join(affected)}. "
                f"Recommended next step: treat this as an incident, rebuild those environments and rotate the "
                f"credentials they could reach.")
        if at_risk:
            body += f" A further {len(at_risk)} use a loose version range that could have pulled one: {', '.join(at_risk)}."
    elif worst == AT_RISK:
        body = (f"{opening}. None pin an affected version of {name} ({bad}), but {len(at_risk)} use it with a loose "
                f"version range that could have pulled one: {', '.join(at_risk)}. Recommended next step: check when "
                f"those were last installed and pin them to a safe version.")
    elif worst == INCOMPLETE:
        body = f"{opening} and found no use of the affected versions of {name} ({bad}) in the ones we could read."
    else:
        where = "on their default branches"
        if branches_checked:
            where += f" or on the {branches_checked} other active branches we checked"
        body = (f"{opening}. None of them currently use the affected versions of {name} ({bad}) {where}, "
                f"so no remediation is needed in our code.")
    return body + caveat + (" This covers what the repos declare. It does not cover packages installed by hand on "
                            "laptops, servers or in built images.")


def issue_body(incident: Incident, results: tuple[RepoResult, ...], inventories: dict[str, RepoInventory],
               owner: str, now: datetime | None = None, skipped: tuple[str, ...] = ()) -> str:
    now = now or datetime.now(timezone.utc)
    worst = headline(results)
    counts = Counter(r.verdict for r in results)
    checked, differing, branch_notes = branch_coverage(inventories)
    private_seen, public_seen = visible_counts(inventories)
    lines = [
        marker(incident),
        f"## {HEADLINES[worst]}",
        "",
        f"**Incident:** {plain(incident.display_title)}",
        f"**Package:** {code(incident.package)} ({incident.ecosystem}) — bad versions: "
        + ("all versions" if incident.all_versions else ", ".join(code(v) for v in incident.bad_versions[:40]))
        + (f" and {len(incident.bad_versions) - 40} more" if len(incident.bad_versions) > 40 else "")
        + (f" — last clean: {code(incident.last_clean)}" if incident.last_clean else ""),
    ]
    if incident.window:
        lines.append(f"**Exposure window:** {plain(incident.window)}")
    lines += [
        _confirmation_line(incident),
        "",
        f"Checked **{len(results)}** repos in {code(owner)} on {now:%Y-%m-%d %H:%M} UTC"
        + (f": the {private_seen} private and {public_seen} public repos the token has access to." if private_seen + public_seen else ".")
        + (f" **{len(skipped)}** archived repos were skipped." if skipped else "")
        + (f" Besides each default branch, **{checked}** other branches were checked (deploy-named or recently "
           f"pushed); {differing} of them differ in their dependency files." if checked else ""),
        "",
        "| Verdict | Repos |",
        "|---|---:|",
        f"| Affected | {counts[AFFECTED]} |",
        f"| At risk | {counts[AT_RISK]} |",
        f"| Uses the package at a safe version | {counts[SAFE_VERSION]} |",
        f"| Does not use the package | {counts[NOT_USED]} |",
        f"| Could not fully check | {counts[INCOMPLETE]} |",
        "",
    ]
    for verdict, heading in ((AFFECTED, "Affected"), (AT_RISK, "At risk"),
                             (SAFE_VERSION, "Uses the package at a safe version")):
        group = _by_verdict(results, verdict)
        if group:
            lines += [f"### {heading}", "", *_evidence_rows(group), ""]
            if verdict == AT_RISK and any(dep.via == "conda" for r in group for dep in r.evidence):
                lines += ["Rows marked \"Conda package\" share a name and version with the bad release. Conda does not "
                          "install from this registry, so check that it is only a name collision.", ""]
    unread = _by_verdict(results, INCOMPLETE)
    if unread:
        lines += ["### Could not fully check", ""]
        lines += [f"- {code(r.repo)}: {plain(r.reason)}" for r in unread[:MAX_ROWS]]
        if len(unread) > MAX_ROWS:
            lines.append(f"- … and {len(unread) - MAX_ROWS} more")
        lines.append("")
    lines += ["### What to do", "", *_checklist(incident, results, skipped), "", "### Ready-to-send reply", "",
              "> " + plain(reply(incident, results, skipped, checked), 2000), ""]
    if incident.sources:
        lines += ["### Sources", "", *[f"- <{source}>" for source in incident.sources], ""]
    pushed = [inv.pushed_at for inv in inventories.values() if inv.pushed_at]
    lines += [
        "---",
        "Scope: dependency and lock files on each repo's default branch"
        + (f" and on {checked} other active branches" if checked else "")
        + ", as they are now. Not covered: "
        + ("the remaining branches" if checked else "other branches")
        + ", past states of a lock file, Dockerfiles, CI workflow files, Gradle and Bun files, "
        "and what is installed on laptops or servers."
        + (f" Most recent push seen: {max(pushed)[:10]}." if pushed else "")
        + ("".join(f" Note: {plain(note)}." for note in branch_notes)),
    ]
    return "\n".join(lines)


def summary(incident: Incident, results: tuple[RepoResult, ...], owner: str, skipped: tuple[str, ...] = (),
            inventories: dict[str, RepoInventory] | None = None) -> dict:
    counts = Counter(r.verdict for r in results)
    checked, differing, branch_notes = branch_coverage(inventories or {})
    private_seen, public_seen = visible_counts(inventories or {})
    return {
        "owner": owner,
        "package": incident.package,
        "ecosystem": incident.ecosystem,
        "bad_versions": list(incident.bad_versions),
        "confirmation": incident.confirmation.status,
        "headline": headline(results),
        "repos_checked": len(results),
        "archived_skipped": list(skipped),
        "visible_private_repos": private_seen,
        "visible_public_repos": public_seen,
        "other_branches_checked": checked,
        "other_branches_differing": differing,
        "branch_notes": branch_notes,
        "branch_findings": sorted({f"{r.repo}@{dep.ref}" for r in results for dep in r.evidence if dep.ref}),
        "counts": dict(counts),
        "repos": {v: [r.repo for r in _by_verdict(results, v)] for v in (AFFECTED, AT_RISK, SAFE_VERSION, INCOMPLETE)},
        "reply": reply(incident, results, skipped, checked),
    }
