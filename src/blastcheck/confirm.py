"""Ask outside sources whether the incident's versions are really bad.

Sends only the public package name and versions. An article alone never confirms an
incident: OSV must list a malware advisory, or the registry must show the release yanked.
"""
from __future__ import annotations

from collections.abc import Callable
from urllib.parse import quote

from . import http
from .models import Confirmation, Incident

OSV_QUERY = "https://api.osv.dev/v1/query"
Fetch = Callable[..., http.Response]


def _osv_evidence(incident: Incident, version: str, fetch: Fetch) -> list[str]:
    payload = {"package": {"name": incident.package, "ecosystem": incident.ecosystem}, "version": version}
    data = fetch("POST", OSV_QUERY, payload=payload).json()
    vulns = data.get("vulns", []) if isinstance(data, dict) else []
    wanted = "MAL-" if incident.kind == "malware" else ""
    ids = [v["id"] for v in vulns if v.get("id", "").startswith(wanted)]
    return [f"OSV lists {vuln_id} for {incident.package} {version}" for vuln_id in ids[:3]]


def _pypi_evidence(incident: Incident, version: str, fetch: Fetch) -> tuple[list[str], list[str]]:
    """Returns (confirming evidence, notes that do not confirm)."""
    url = f"https://pypi.org/pypi/{quote(incident.package, safe='')}/{quote(version, safe='')}/json"
    try:
        data = fetch("GET", url).json()
    except http.HttpError as exc:
        if exc.status == 404:
            return [], [f"{incident.package} {version} is not on PyPI (removed, or never published)"]
        raise
    files = data.get("urls", []) if isinstance(data, dict) else []
    if files and all(f.get("yanked") for f in files):
        reason = next((f.get("yanked_reason") for f in files if f.get("yanked_reason")), "")
        return [f"PyPI shows {incident.package} {version} as yanked{': ' + reason if reason else ''}"], []
    return [], []


def confirm(incident: Incident, fetch: Fetch = http.request) -> Confirmation:
    """Never raises: an unreachable source leaves the incident unconfirmed, with a note."""
    evidence: list[str] = []
    notes: list[str] = []
    for version in incident.bad_versions:
        try:
            evidence.extend(_osv_evidence(incident, version, fetch))
        except (http.HttpError, ValueError) as exc:
            notes.append(f"OSV could not be reached for {version} ({exc})")
        if incident.ecosystem == "PyPI":
            try:
                found, extra = _pypi_evidence(incident, version, fetch)
                evidence.extend(found)
                notes.extend(extra)
            except (http.HttpError, ValueError) as exc:
                notes.append(f"PyPI could not be reached for {version} ({exc})")
    if evidence:
        return Confirmation("confirmed", tuple(evidence))
    return Confirmation("unconfirmed", tuple(notes) or ("no outside source lists these versions as bad yet",))
