"""Compare one incident with the inventory. No network, no AI."""
from __future__ import annotations

import posixpath
from collections.abc import Iterable

from . import versions
from .models import (AFFECTED, AT_RISK, INCOMPLETE, NOT_USED, SAFE_VERSION, VERDICT_ORDER, Dep,
                     Incident, RepoInventory, RepoResult)
from .parsers import LOCKS_FOR
from .parsers.python import normalise


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


def match_repo(incident: Incident, inventory: RepoInventory) -> RepoResult:
    deps = tuple(dep for dep in inventory.deps if _same_package(incident, dep))
    pinned_bad = tuple(dep for dep in deps if dep.exact and dep.version and _is_bad(incident, dep.version))
    if pinned_bad:
        return RepoResult(inventory.repo, AFFECTED, pinned_bad, "a known-bad version is pinned")

    loose = tuple(
        dep for dep in deps
        if not dep.exact and _could_pull_bad(incident, dep) and not _pinned_by_lock(dep, deps)
    )
    if loose:
        return RepoResult(inventory.repo, AT_RISK, loose,
                          "the version range accepts a known-bad version and no lock file pins a safe one")

    unparsed = [entry.split(":", 1)[1] for entry in inventory.unparsed if entry.startswith(f"{incident.ecosystem}:")]
    problems = list(inventory.errors) + [f"{path}: this file type is not supported yet" for path in unparsed]
    if problems:
        return RepoResult(inventory.repo, INCOMPLETE, deps, "; ".join(problems[:3]))
    if deps:
        return RepoResult(inventory.repo, SAFE_VERSION, deps, "the package is used at a version outside the bad set")
    return RepoResult(inventory.repo, NOT_USED, (), "")


def match(incident: Incident, inventories: Iterable[RepoInventory]) -> tuple[RepoResult, ...]:
    return tuple(sorted((match_repo(incident, inv) for inv in inventories), key=lambda r: r.repo.lower()))


def headline(results: Iterable[RepoResult]) -> str:
    """Worst verdict across the org; 'incomplete' beats any clean verdict."""
    found = {result.verdict for result in results}
    for verdict in (AFFECTED, AT_RISK):
        if verdict in found:
            return verdict
    if INCOMPLETE in found:
        return INCOMPLETE
    for verdict in VERDICT_ORDER[2:]:
        if verdict in found:
            return verdict
    return NOT_USED
