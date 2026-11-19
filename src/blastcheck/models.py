"""Immutable data shapes shared by every module."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

AFFECTED = "affected"
AT_RISK = "at_risk"
SAFE_VERSION = "uses_safe_version"
NOT_USED = "not_used"
INCOMPLETE = "incomplete"

VERDICT_ORDER = (AFFECTED, AT_RISK, SAFE_VERSION, NOT_USED)

ECOSYSTEMS = ("PyPI", "npm", "Go", "crates.io", "Maven")


@dataclass(frozen=True)
class Dep:
    """One dependency line found in one file of one repo."""

    file: str
    ecosystem: str
    name: str
    version: str | None  # exact version when known, else None
    spec: str  # the raw specifier as written
    exact: bool  # True when `version` is what will be installed


@dataclass(frozen=True)
class RepoInventory:
    """Everything read from one repo, plus what could not be read."""

    repo: str
    pushed_at: str
    deps: tuple[Dep, ...] = ()
    errors: tuple[str, ...] = ()
    files_read: int = 0
    note: str = ""
    unparsed: tuple[str, ...] = ()  # "ecosystem:path" for dependency files we cannot parse

    def to_json(self) -> dict:
        """Compact form for the cache: each dependency is a short list, not an object."""
        data = asdict(self)
        data["deps"] = [[d.file, d.ecosystem, d.name, d.version, d.spec, d.exact] for d in self.deps]
        return data

    @staticmethod
    def from_json(data: dict) -> "RepoInventory":
        deps = tuple(Dep(*d) for d in data.get("deps", ()))
        return RepoInventory(
            repo=data["repo"],
            pushed_at=data.get("pushed_at", ""),
            deps=deps,
            errors=tuple(data.get("errors", ())),
            files_read=data.get("files_read", 0),
            note=data.get("note", ""),
            unparsed=tuple(data.get("unparsed", ())),
        )


@dataclass(frozen=True)
class Confirmation:
    """Whether an outside source agrees the versions are bad."""

    status: str  # "confirmed" | "unconfirmed"
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class Incident:
    """One reported attack or bad release."""

    package: str
    ecosystem: str
    bad_versions: tuple[str, ...]
    title: str = ""
    kind: str = "malware"  # "malware" | "vulnerability"
    last_clean: str | None = None
    window: str | None = None
    indicators: tuple[str, ...] = ()
    credentials_at_risk: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    origin: str = "manual"  # "manual" | "article" | "file"
    confirmation: Confirmation = field(default_factory=lambda: Confirmation("unconfirmed"))

    @property
    def slug(self) -> str:
        versions = "-".join(self.bad_versions[:3])
        raw = f"{self.ecosystem}-{self.package}-{versions}".lower()
        return "".join(ch if ch.isalnum() or ch in "-." else "-" for ch in raw)

    @property
    def display_title(self) -> str:
        return self.title or f"{self.package} {', '.join(self.bad_versions)} ({self.ecosystem})"


@dataclass(frozen=True)
class RepoResult:
    """The verdict for one repo, with the lines that justify it."""

    repo: str
    verdict: str
    evidence: tuple[Dep, ...] = ()
    reason: str = ""
