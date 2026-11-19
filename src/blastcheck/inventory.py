"""Build the org inventory: dependency files only, cached per repo by last push time."""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from . import parsers
from .github import MAX_BLOB_BYTES, GitHub, GitHubError
from .models import Dep, RepoInventory

log = logging.getLogger(__name__)
# Includes the parser version: improving a parser must invalidate what older parsers extracted.
CACHE_VERSION = f"2.{parsers.PARSER_VERSION}"
SYMLINK_MODE = "120000"


def load_cache(path: str | Path | None, owner: str | None = None) -> dict[str, RepoInventory]:
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
    return {name: RepoInventory.from_json(item) for name, item in data.get("repos", {}).items()}


def save_cache(path: str | Path, owner: str, inventories: dict[str, RepoInventory]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": CACHE_VERSION,
        "owner": owner,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repos": {name: inv.to_json() for name, inv in sorted(inventories.items())},
    }
    target.write_text(json.dumps(payload, separators=(",", ":")) + "\n")


def read_repo(gh: GitHub, repo: dict) -> RepoInventory:
    """Read one repo's dependency files. Never raises: failures are recorded on the result."""
    name, full_name = repo["name"], repo["full_name"]
    pushed_at = repo.get("pushed_at") or ""
    try:
        tree = gh.tree(full_name, repo.get("default_branch") or "HEAD")
    except GitHubError as exc:
        if exc.status == 409:
            return RepoInventory(name, pushed_at, note="empty repository")
        return RepoInventory(name, pushed_at, errors=(f"could not list files: {exc}",))

    errors: list[str] = []
    if tree.get("truncated"):
        errors.append("file list was truncated by GitHub; some dependency files may be missing")
    deps: list[Dep] = []
    unparsed: list[str] = []
    files_read = 0
    for entry in tree.get("tree", []):
        path = entry.get("path", "")
        if entry.get("type") != "blob":
            continue
        ecosystem = parsers.unsupported_ecosystem(path)
        if ecosystem:
            unparsed.append(f"{ecosystem}:{path}")
            continue
        if not parsers.is_dependency_file(path):
            continue
        if entry.get("mode") == SYMLINK_MODE:
            errors.append(f"{path}: is a symbolic link, so its content was not read")
            continue
        if entry.get("size", 0) > MAX_BLOB_BYTES:
            errors.append(f"{path}: too large to read")
            continue
        try:
            deps.extend(parsers.parse(path, gh.blob_text(full_name, entry["sha"])))
            files_read += 1
        except GitHubError as exc:
            errors.append(f"{path}: could not download ({exc})")
        except Exception as exc:  # a malformed manifest must not stop the scan, but must be reported
            errors.append(f"{path}: could not parse ({type(exc).__name__}: {str(exc)[:120]})")
    return RepoInventory(name, pushed_at, tuple(deps), tuple(errors), files_read, unparsed=tuple(unparsed))


def build(gh: GitHub, owner: str, cache: dict[str, RepoInventory] | None = None, include_archived: bool = False,
          workers: int = 8, progress: Callable[[str], None] | None = None,
          ) -> tuple[dict[str, RepoInventory], tuple[str, ...]]:
    """Inventory every repo of `owner`, reusing cached repos that have not been pushed since.

    Returns the inventories and the names of archived repos that were skipped.
    """
    cache = cache or {}
    listed = gh.list_repos(owner)
    repos = [r for r in listed if include_archived or not r.get("archived")]
    skipped = tuple(sorted(r["name"] for r in listed if r.get("archived") and not include_archived))
    fresh: dict[str, RepoInventory] = {}
    stale: list[dict] = []
    for repo in repos:
        cached = cache.get(repo["name"])
        if cached and cached.pushed_at == (repo.get("pushed_at") or "") and not cached.errors:
            fresh[repo["name"]] = cached
        else:
            stale.append(repo)
    if progress:
        progress(f"{len(repos)} repos: {len(fresh)} unchanged, {len(stale)} to read")

    def work(repo: dict) -> RepoInventory:
        result = read_repo(gh, repo)
        if progress:
            progress(f"read {repo['name']}: {result.files_read} files, {len(result.errors)} problems")
        return result

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for result in pool.map(work, stale):
            fresh[result.repo] = result
    return fresh, skipped
