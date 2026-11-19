"""Automatic mode: find known-malicious releases among the packages the org already uses.

Instead of reading every new malware report in the world (hundreds a day, almost all for
packages nobody here uses), this asks OSV about each package name in the inventory, keeps
the malware advisories, and runs the normal matcher for each. Only public package names
leave the environment. A few requests cover thousands of packages.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from . import http, matcher
from .models import AFFECTED, AT_RISK, Confirmation, Incident, RepoInventory, RepoResult

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
OSV_PAGE = "https://osv.dev/vulnerability/"
BATCH = 500
MAX_PAGES = 20
MAX_VERSIONS = 2000
_ADVISORY_ID = re.compile(r"^MAL-\d{4}-\d+$")
_VERSION = re.compile(r"^v?\d[A-Za-z0-9.+\-_!]{0,60}$")
Fetch = Callable[..., http.Response]
Key = tuple[str, str]  # (ecosystem, package name)


class WatchError(Exception):
    """The sweep could not be completed, so its silence would mean nothing."""


@dataclass(frozen=True)
class Match:
    incident: Incident
    results: tuple[RepoResult, ...]
    published: str


@dataclass(frozen=True)
class Sweep:
    packages: int  # distinct packages asked about
    advisories: int  # malware advisories found for them
    matches: tuple[Match, ...]  # advisories that hit the org (affected, or recent and at risk)
    quiet: int  # advisories that concern only versions the org does not use
    notes: tuple[str, ...]  # advisories that could not be interpreted


def package_keys(inventories: Iterable[RepoInventory]) -> list[Key]:
    """Every distinct package the org uses, on any branch that was read."""
    keys: set[Key] = set()
    for inv in inventories:
        for dep in inv.deps:
            keys.add((dep.ecosystem, dep.name))
        for branch in inv.branches:
            for dep in branch.deps:
                keys.add((dep.ecosystem, dep.name))
    return sorted(keys)


def _query(keys: list[Key], tokens: dict[int, str], fetch: Fetch) -> list[dict]:
    queries = []
    for index, (ecosystem, name) in enumerate(keys):
        query: dict = {"package": {"ecosystem": ecosystem, "name": name}}
        if index in tokens:
            query["page_token"] = tokens[index]
        queries.append(query)
    data = fetch("POST", OSV_BATCH, payload={"queries": queries}).json()
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list) or len(results) != len(keys):
        raise WatchError("OSV returned an unexpected answer")
    return results


def malware_ids(keys: list[Key], fetch: Fetch | None = None) -> dict[Key, list[str]]:
    """Malware advisory ids per package. Raises WatchError if OSV cannot be read completely."""
    fetch = fetch or http.request
    found: dict[Key, list[str]] = {}
    try:
        for start in range(0, len(keys), BATCH):
            chunk = keys[start:start + BATCH]
            tokens: dict[int, str] = {}
            pending = list(range(len(chunk)))
            for _ in range(MAX_PAGES):
                asked = [chunk[i] for i in pending]
                results = _query(asked, {n: tokens[i] for n, i in enumerate(pending) if i in tokens}, fetch)
                next_pending = []
                for i, result in zip(pending, results):
                    for vuln in (result or {}).get("vulns") or []:
                        vuln_id = str(vuln.get("id", ""))
                        if _ADVISORY_ID.match(vuln_id):
                            found.setdefault(chunk[i], []).append(vuln_id)
                    token = (result or {}).get("next_page_token")
                    if token:
                        tokens[i] = token
                        next_pending.append(i)
                pending = next_pending
                if not pending:
                    break
            else:
                raise WatchError("OSV kept returning more pages than expected")
    except (http.HttpError, ValueError) as exc:
        raise WatchError(f"OSV could not be read: {exc}") from exc
    return {key: sorted(set(ids)) for key, ids in found.items()}


def _same_name(ecosystem: str, left: str, right: str) -> bool:
    if ecosystem in ("PyPI", "crates.io"):
        normalise = lambda value: re.sub(r"[-_.]+", "-", value).lower()  # noqa: E731
        return normalise(left) == normalise(right)
    return left == right


def _bounded_ranges(advisory: dict, ecosystem: str, name: str) -> tuple[tuple[str, str, bool], ...]:
    """Version ranges from an advisory that lists no explicit versions: (introduced, upper, inclusive)."""
    found: list[tuple[str, str, bool]] = []
    for affected in advisory.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("ecosystem") != ecosystem or not _same_name(ecosystem, str(package.get("name", "")), name):
            continue
        for version_range in affected.get("ranges") or []:
            if version_range.get("type") == "GIT":
                continue
            low = ""
            for event in version_range.get("events") or []:
                if "introduced" in event:
                    low = str(event["introduced"])
                    continue
                upper = event.get("fixed") or event.get("last_affected") or event.get("limit")
                if low and upper and all(_VERSION.match(v) for v in (low if low != "0" else "0.0.0", str(upper))):
                    found.append((low if low != "0" else "0.0.0", str(upper), "last_affected" in event))
                    low = ""
    return tuple(found[:20])


def to_incident(advisory: dict, key: Key) -> Incident | None:
    """Turn one OSV malware advisory into an incident for `key`, or None if it cannot be used."""
    ecosystem, name = key
    advisory_id = str(advisory.get("id", ""))
    if not _ADVISORY_ID.match(advisory_id) or advisory.get("withdrawn"):
        return None
    versions: list[str] = []
    whole_package = False
    for affected in advisory.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("ecosystem") != ecosystem or not _same_name(ecosystem, str(package.get("name", "")), name):
            continue
        versions.extend(str(v) for v in affected.get("versions") or [] if _VERSION.match(str(v)))
        for version_range in affected.get("ranges") or []:
            events = version_range.get("events") or []
            starts_at_zero = any(event.get("introduced") == "0" for event in events)
            has_end = any("fixed" in event or "last_affected" in event or "limit" in event for event in events)
            whole_package = whole_package or (starts_at_zero and not has_end)
    versions = sorted(set(versions))[:MAX_VERSIONS]
    ranges = () if versions or whole_package else _bounded_ranges(advisory, ecosystem, name)
    if not versions and not whole_package and not ranges:
        return None
    return Incident(
        package=name, ecosystem=ecosystem, bad_versions=tuple(versions), kind="malware",
        title=str(advisory.get("summary") or f"Malicious code in {name} ({ecosystem})")[:200],
        sources=(OSV_PAGE + advisory_id,), origin="advisory", all_versions=whole_package, advisory_id=advisory_id,
        bad_ranges=ranges,
        confirmation=Confirmation("confirmed", (f"OSV malware advisory {advisory_id}",)),
    )


def sweep(inventories: Iterable[RepoInventory], recent_days: int = 7, fetch: Fetch | None = None,
          now: datetime | None = None) -> Sweep:
    """Check the whole inventory against OSV's malware advisories.

    A pinned bad version always counts. A loose range that could resolve to a bad version
    counts only while the advisory is recent: malicious releases are removed from the
    registry quickly, after which a loose range can no longer pull them.
    """
    inventories = list(inventories)
    fetch = fetch or http.request
    now = now or datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=max(0, recent_days))).isoformat()
    keys = package_keys(inventories)
    ids_by_package = malware_ids(keys, fetch)

    matches: list[Match] = []
    notes: list[str] = []
    quiet = 0
    advisories = 0
    for key, ids in sorted(ids_by_package.items()):
        for advisory_id in ids:
            advisories += 1
            try:
                advisory = fetch("GET", OSV_VULN + advisory_id).json()
            except (http.HttpError, ValueError) as exc:
                raise WatchError(f"OSV advisory {advisory_id} could not be read: {exc}") from exc
            incident = to_incident(advisory if isinstance(advisory, dict) else {}, key)
            if incident is None:
                if not (isinstance(advisory, dict) and advisory.get("withdrawn")):
                    notes.append(f"{advisory_id} for {key[1]} lists no versions that could be interpreted")
                continue
            results = matcher.match(incident, inventories)
            worst = matcher.headline(results)
            published = str(advisory.get("published") or advisory.get("modified") or "")
            recent = published >= cutoff
            if worst == AFFECTED or (worst == AT_RISK and recent):
                matches.append(Match(incident, results, published))
            else:
                quiet += 1
    return Sweep(len(keys), advisories, tuple(matches), quiet, tuple(notes))
