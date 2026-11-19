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
    ref: str = ""  # branch the line was found on; empty means the default branch


def _deps_to_json(deps: tuple[Dep, ...]) -> list[list]:
    return [[d.file, d.ecosystem, d.name, d.version, d.spec, d.exact] for d in deps]


def _deps_from_json(rows: object) -> tuple[Dep, ...]:
    return tuple(Dep(*row) for row in rows or ())  # type: ignore[union-attr]


@dataclass(frozen=True)
class BranchInventory:
    """What one non-default branch changes about the repo's dependency files."""

    ref: str
    head: str
    reason: str  # why this branch was picked
    deps: tuple[Dep, ...] = ()  # from files that differ from the default branch
    changed_paths: tuple[str, ...] = ()
    removed_paths: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    unparsed: tuple[str, ...] = ()

    @property
    def differs(self) -> bool:
        return bool(self.changed_paths or self.removed_paths or self.unparsed or self.errors)

    def to_json(self) -> dict:
        return {**asdict(self), "deps": _deps_to_json(self.deps)}

    @staticmethod
    def from_json(data: dict) -> "BranchInventory":
        return BranchInventory(
            ref=data["ref"], head=data.get("head", ""), reason=data.get("reason", ""),
            deps=_deps_from_json(data.get("deps")), changed_paths=tuple(data.get("changed_paths", ())),
            removed_paths=tuple(data.get("removed_paths", ())), errors=tuple(data.get("errors", ())),
            unparsed=tuple(data.get("unparsed", ())),
        )


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
    branches: tuple[BranchInventory, ...] = ()  # other branches that were checked
    branch_note: str = ""  # anything that limited which branches were checked

    def to_json(self) -> dict:
        """Compact form for the cache: each dependency is a short list, not an object."""
        data = asdict(self)
        data["deps"] = _deps_to_json(self.deps)
        data["branches"] = [branch.to_json() for branch in self.branches]
        return data

    @staticmethod
    def from_json(data: dict) -> "RepoInventory":
        deps = _deps_from_json(data.get("deps"))
        return RepoInventory(
            repo=data["repo"],
            pushed_at=data.get("pushed_at", ""),
            deps=deps,
            errors=tuple(data.get("errors", ())),
            files_read=data.get("files_read", 0),
            note=data.get("note", ""),
            unparsed=tuple(data.get("unparsed", ())),
            branches=tuple(BranchInventory.from_json(b) for b in data.get("branches", ())),
            branch_note=data.get("branch_note", ""),
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
