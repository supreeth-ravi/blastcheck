"""Create, validate, load and save incident definitions."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, replace
from pathlib import Path

from .models import ECOSYSTEMS, Confirmation, Incident

_PACKAGE = re.compile(r"^[@A-Za-z0-9][A-Za-z0-9._\-/@:]{0,213}$")
_VERSION = re.compile(r"^v?\d[A-Za-z0-9.+\-_!]{0,60}$")
_URL = re.compile(r"^https://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]*)?$")
_ALIASES = {"pypi": "PyPI", "pip": "PyPI", "python": "PyPI", "npm": "npm", "node": "npm", "go": "Go",
            "golang": "Go", "cargo": "crates.io", "crates.io": "crates.io", "rust": "crates.io", "maven": "Maven"}


class IncidentError(ValueError):
    """The incident definition is missing something or is malformed."""


def canonical_ecosystem(value: str) -> str:
    ecosystem = _ALIASES.get((value or "").strip().lower())
    if ecosystem is None:
        raise IncidentError(f"unknown ecosystem {value!r}; use one of {', '.join(ECOSYSTEMS)}")
    return ecosystem


def validate(incident: Incident) -> Incident:
    if not _PACKAGE.match(incident.package or ""):
        raise IncidentError(f"package name looks wrong: {incident.package!r}")
    if not incident.bad_versions and not incident.all_versions and not incident.bad_ranges:
        raise IncidentError("at least one bad version is required")
    for version in incident.bad_versions:
        if not _VERSION.match(version):
            raise IncidentError(f"version looks wrong: {version!r}")
    if incident.last_clean and not _VERSION.match(incident.last_clean):
        raise IncidentError(f"last clean version looks wrong: {incident.last_clean!r}")
    if incident.kind not in ("malware", "vulnerability"):
        raise IncidentError(f"kind must be 'malware' or 'vulnerability', not {incident.kind!r}")
    return replace(incident, ecosystem=canonical_ecosystem(incident.ecosystem))


def _strings(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    return tuple(str(item).strip()[:200] for item in value if str(item).strip())  # type: ignore[union-attr]


def from_mapping(data: dict, origin: str) -> Incident:
    """Build an incident from untrusted key/value data, keeping only known fields."""
    incident = Incident(
        package=str(data.get("package", "")).strip(),
        ecosystem=str(data.get("ecosystem", "")).strip(),
        bad_versions=_strings(data.get("bad_versions"))[:50],
        title=str(data.get("title") or "").strip()[:200],
        kind=str(data.get("kind") or "malware").strip(),
        last_clean=(str(data["last_clean"]).strip() or None) if data.get("last_clean") else None,
        window=(str(data["window"]).strip()[:200] or None) if data.get("window") else None,
        indicators=_strings(data.get("indicators"))[:30],
        credentials_at_risk=_strings(data.get("credentials_at_risk"))[:30],
        sources=tuple(s for s in _strings(data.get("sources")) if _URL.match(s))[:20],
        origin=origin,
    )
    return validate(incident)


def load(path: str | Path) -> Incident:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise IncidentError(f"cannot read incident file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise IncidentError(f"incident file {path} must contain a JSON object")
    return from_mapping(data, origin="file")


def save(incident: Incident, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(asdict(incident), indent=2) + "\n")
    return target


def with_confirmation(incident: Incident, confirmation: Confirmation) -> Incident:
    return replace(incident, confirmation=confirmation)
