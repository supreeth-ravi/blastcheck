"""Build the org inventory: dependency files only, cached per repo by last push time.

Other branches are read by difference: a branch's file list carries a content fingerprint
for every file, so a dependency file identical to the default branch's is never downloaded.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import branches as branches_mod
from . import parsers
from .branches import Pick, Settings
from .github import MAX_BLOB_BYTES, GitHub, GitHubError
from .models import BranchInventory, Dep, RepoInventory

log = logging.getLogger(__name__)
# Includes the parser version: improving a parser must invalidate what older parsers extracted.
CACHE_VERSION = f"3.{parsers.PARSER_VERSION}"
SYMLINK_MODE = "120000"


def load_cache(path: str | Path | None, owner: str | None = None, settings: Settings | None = None,
               ) -> dict[str, RepoInventory]:
    if not path or not Path(path).exists():
        return {}
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("ignoring unreadable inventory cache %s: %s", path, exc)
        return {}
    if data.get("version") != CACHE_VERSION:
        return {}
    if owner is not None and data.get("owner", "").lower() != owner.lower():
        return {}  # a cache built for another org must never answer for this one
    if settings is not None and data.get("branch_settings") != settings.key:
        return {}  # a cache built with other branch rules covers a different set of branches
    return {name: RepoInventory.from_json(item) for name, item in data.get("repos", {}).items()}


def save_cache(path: str | Path, owner: str, inventories: dict[str, RepoInventory],
               settings: Settings | None = None) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": CACHE_VERSION,
        "owner": owner,
        "branch_settings": (settings or Settings()).key,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repos": {name: inv.to_json() for name, inv in sorted(inventories.items())},
    }
    target.write_text(json.dumps(payload, separators=(",", ":")) + "\n")


@dataclass
class _TreeRead:
    """What reading one file list produced."""

    deps: list[Dep] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)
    shas: dict[str, str] = field(default_factory=dict)  # dependency file path -> content fingerprint
    read_paths: list[str] = field(default_factory=list)


def _read_tree(gh: GitHub, full_name: str, tree: dict, texts: dict[str, str],
               same_as: dict[str, str] | None = None) -> _TreeRead:
    """Parse the dependency files in one file list.

    `texts` caches downloaded content by fingerprint for the whole repo. Files whose
    fingerprint equals `same_as[path]` are skipped entirely: they are already accounted for.
    """
    out = _TreeRead()
    if tree.get("truncated"):
        out.errors.append("file list was truncated by GitHub; some dependency files may be missing")
    for entry in tree.get("tree", []):
        path = entry.get("path", "")
        if entry.get("type") != "blob":
            continue
        ecosystem = parsers.unsupported_ecosystem(path)
        if ecosystem:
            out.unparsed.append(f"{ecosystem}:{path}")
            continue
        if not parsers.is_dependency_file(path):
            continue
        sha = entry.get("sha", "")
        out.shas[path] = sha
        if same_as is not None and same_as.get(path) == sha:
            continue
        if entry.get("mode") == SYMLINK_MODE:
            out.errors.append(f"{path}: is a symbolic link, so its content was not read")
            continue
        if entry.get("size", 0) > MAX_BLOB_BYTES:
            out.errors.append(f"{path}: too large to read")
            continue
        try:
            if sha not in texts:
                texts[sha] = gh.blob_text(full_name, sha)
            out.deps.extend(parsers.parse(path, texts[sha]))
            out.read_paths.append(path)
        except GitHubError as exc:
            out.errors.append(f"{path}: could not download ({exc})")
        except Exception as exc:  # a malformed manifest must not stop the scan, but must be reported
            out.errors.append(f"{path}: could not parse ({type(exc).__name__}: {str(exc)[:120]})")
    return out


def _read_branch(gh: GitHub, full_name: str, chosen: Pick, default: _TreeRead, texts: dict[str, str]) -> BranchInventory:
    try:
        tree = gh.tree(full_name, chosen.head)
    except GitHubError as exc:
        return BranchInventory(chosen.name, chosen.head, chosen.reason, errors=(f"could not list files: {exc}",))
    read = _read_tree(gh, full_name, tree, texts, same_as=default.shas)
    changed = sorted(path for path, sha in read.shas.items() if default.shas.get(path) != sha)
    removed = sorted(path for path in default.shas if path not in read.shas)
    new_unparsed = [entry for entry in read.unparsed if entry not in default.unparsed]
    return BranchInventory(chosen.name, chosen.head, chosen.reason, tuple(read.deps), tuple(changed), tuple(removed),
                           tuple(read.errors), tuple(new_unparsed))


def read_repo(gh: GitHub, repo: dict, picks: tuple[Pick, ...] = (), branch_note: str = "",
              branch_error: str = "") -> RepoInventory:
    """Read one repo's dependency files. Never raises: failures are recorded on the result."""
    name, full_name = repo["name"], repo["full_name"]
    pushed_at = repo.get("pushed_at") or ""
    try:
        tree = gh.tree(full_name, repo.get("default_branch") or "HEAD")
    except GitHubError as exc:
        if exc.status == 409:
            return RepoInventory(name, pushed_at, note="empty repository")
        return RepoInventory(name, pushed_at, errors=(f"could not list files: {exc}",))

    texts: dict[str, str] = {}
    default = _read_tree(gh, full_name, tree, texts)
    others = tuple(_read_branch(gh, full_name, chosen, default, texts) for chosen in picks)
    errors = default.errors + ([branch_error] if branch_error else [])
    return RepoInventory(name, pushed_at, tuple(default.deps), tuple(errors), len(default.read_paths),
                         unparsed=tuple(default.unparsed), branches=others, branch_note=branch_note)


def build(gh: GitHub, owner: str, cache: dict[str, RepoInventory] | None = None, include_archived: bool = False,
          workers: int = 8, progress: Callable[[str], None] | None = None, settings: Settings | None = None,
          ) -> tuple[dict[str, RepoInventory], tuple[str, ...]]:
    """Inventory every repo of `owner`, reusing cached repos that have not been pushed since.

    Returns the inventories and the names of archived repos that were skipped.
    """
    cache = cache or {}
    settings = settings or Settings()
    listed = gh.list_repos(owner)
    repos = [r for r in listed if include_archived or not r.get("archived")]
    skipped = tuple(sorted(r["name"] for r in listed if r.get("archived") and not include_archived))
    fresh: dict[str, RepoInventory] = {}
    stale: list[dict] = []
    for repo in repos:
        cached = cache.get(repo["name"])
        clean = cached and not cached.errors and not any(b.errors for b in cached.branches)
        if cached and clean and cached.pushed_at == (repo.get("pushed_at") or ""):
            fresh[repo["name"]] = cached
        else:
            stale.append(repo)
    if progress:
        progress(f"{len(repos)} repos: {len(fresh)} unchanged, {len(stale)} to read")

    plan: dict[str, tuple[tuple[Pick, ...], str, str]] = {}
    fallback = ((), "" if settings.enabled else "other branches were not checked (turned off)", "")
    if settings.enabled and stale:
        try:
            plan = branches_mod.plan(gh, owner, [r["name"] for r in stale], settings)
        except GitHubError as exc:
            # Branches were asked for and could not be listed: every repo is not fully read.
            fallback = ((), "", f"{branches_mod.NOT_LISTED}: {exc}")

    def work(repo: dict) -> RepoInventory:
        picks, note, branch_error = plan.get(repo["name"], fallback)
        result = read_repo(gh, repo, picks, note, branch_error)
        if progress:
            progress(f"read {repo['name']}: {result.files_read} files, {len(result.branches)} other branches, "
                     f"{len(result.errors)} problems")
        return result

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for result in pool.map(work, stale):
            fresh[result.repo] = result
    return fresh, skipped
