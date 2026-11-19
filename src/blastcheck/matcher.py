"""Compare one incident with the inventory. No network, no AI."""
from __future__ import annotations

import posixpath
from collections.abc import Iterable
from dataclasses import replace

from . import versions
from .models import (AFFECTED, AT_RISK, INCOMPLETE, NOT_USED, SAFE_VERSION, BranchInventory, Dep, Incident,
                     RepoInventory, RepoResult)
from .parsers import LOCKS_FOR
from .parsers.python import normalise

SEVERITY = {AFFECTED: 4, AT_RISK: 3, INCOMPLETE: 2, SAFE_VERSION: 1, NOT_USED: 0}
_REASONS = {
    AFFECTED: "a known-bad version is pinned",
    AT_RISK: "the version range accepts a known-bad version and no lock file pins a safe one",
    SAFE_VERSION: "the package is used at a version outside the bad set",
    NOT_USED: "",
}


def _same_package(incident: Incident, dep: Dep) -> bool:
    if dep.ecosystem != incident.ecosystem:
        return False
    if incident.ecosystem == "PyPI":
        return dep.name == normalise(incident.package)
    if incident.ecosystem == "crates.io":
        return dep.name.replace("_", "-") == incident.package.replace("_", "-")
    return dep.name == incident.package


def _is_bad(incident: Incident, version: str) -> bool:
    return any(versions.same(version, bad) for bad in incident.bad_versions)


def _could_pull_bad(incident: Incident, dep: Dep) -> bool:
    return any(versions.accepts(incident.ecosystem, dep.spec, bad) for bad in incident.bad_versions)


def _pinned_by_lock(dep: Dep, deps: Iterable[Dep]) -> bool:
    """True when a lock file of the matching tool, in the same folder, pins this package.

    A requirements file is never covered: pip does not read lock files.
    """
    locks = LOCKS_FOR.get(posixpath.basename(dep.file), frozenset())
    folder = posixpath.dirname(dep.file)
    return any(
        other.exact and posixpath.dirname(other.file) == folder and posixpath.basename(other.file) in locks
        for other in deps
    )


def _evaluate(incident: Incident, all_deps: Iterable[Dep], errors: Iterable[str], unparsed: Iterable[str],
              ) -> tuple[str, tuple[Dep, ...], str]:
    """Verdict, the lines that justify it, and a reason, for one view of a repo's files."""
    deps = tuple(dep for dep in all_deps if _same_package(incident, dep))
    pinned_bad = tuple(dep for dep in deps if dep.exact and dep.version and _is_bad(incident, dep.version))
    if pinned_bad:
        return AFFECTED, pinned_bad, _REASONS[AFFECTED]
    loose = tuple(dep for dep in deps
                  if not dep.exact and _could_pull_bad(incident, dep) and not _pinned_by_lock(dep, deps))
    if loose:
        return AT_RISK, loose, _REASONS[AT_RISK]
    prefix = f"{incident.ecosystem}:"
    problems = list(errors) + [f"{entry[len(prefix):]}: this file type is not supported yet"
                               for entry in unparsed if entry.startswith(prefix)]
    if problems:
        return INCOMPLETE, deps, "; ".join(problems[:3])
    return (SAFE_VERSION, deps, _REASONS[SAFE_VERSION]) if deps else (NOT_USED, (), "")


def _branch_view(inventory: RepoInventory, branch: BranchInventory) -> list[Dep]:
    """The branch's full set of dependency lines: the default branch's, with its differences applied."""
    replaced = set(branch.changed_paths) | set(branch.removed_paths)
    return [dep for dep in inventory.deps if dep.file not in replaced] + list(branch.deps)


def match_repo(incident: Incident, inventory: RepoInventory) -> RepoResult:
    verdict, evidence, reason = _evaluate(incident, inventory.deps, inventory.errors, inventory.unparsed)
    best = (verdict, evidence, reason)
    extra: list[Dep] = []
    for branch in inventory.branches:
        if not branch.differs:
            continue
        b_verdict, b_evidence, b_reason = _evaluate(incident, _branch_view(inventory, branch), branch.errors,
                                                    branch.unparsed)
        worse = SEVERITY[b_verdict] > SEVERITY[verdict]
        changed = set(branch.changed_paths)
        relevant = b_evidence if worse else tuple(dep for dep in b_evidence if dep.file in changed)
        if b_verdict not in (AFFECTED, AT_RISK, INCOMPLETE) or not (worse or relevant):
            continue
        tagged = tuple(replace(dep, ref=branch.ref) for dep in relevant)
        label = f"on branch {branch.ref}: {b_reason}"
        if SEVERITY[b_verdict] > SEVERITY[best[0]]:
            best, extra = (b_verdict, tagged, label), []
        elif b_verdict == best[0] and b_verdict != INCOMPLETE:
            extra.extend(tagged)
    return RepoResult(inventory.repo, best[0], tuple(best[1]) + tuple(extra), best[2])


def match(incident: Incident, inventories: Iterable[RepoInventory]) -> tuple[RepoResult, ...]:
    return tuple(sorted((match_repo(incident, inv) for inv in inventories), key=lambda r: r.repo.lower()))


def headline(results: Iterable[RepoResult]) -> str:
    """Worst verdict across the org; 'incomplete' beats any clean verdict."""
    found = {result.verdict for result in results}
    return max(found, key=SEVERITY.__getitem__) if found else NOT_USED
