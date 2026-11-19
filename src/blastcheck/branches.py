"""Decide which non-default branches are worth reading, cheaply.

Reading every branch would multiply the work for little gain: most are stale. The branches
that matter are the ones whose code is being installed now: branches named like a deploy
target, and branches pushed recently. One GraphQL request lists the branches of ~25 repos.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .github import GitHub

DEPLOY_NAME = re.compile(
    r"^(main|master|trunk|develop|development|dev|staging|stage|preprod|prod|production|live|uat|qa|"
    r"(release|hotfix)([-/_.].*)?)$", re.I)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
CHUNK = 25
LISTED_PER_REPO = 100

_REPO_FRAGMENT = """r%d: repository(owner: %s, name: %s) {
  defaultBranchRef { name target { oid } }
  refs(refPrefix: "refs/heads/", first: %d, orderBy: {field: TAG_COMMIT_DATE, direction: DESC}) {
    totalCount
    nodes { name target { oid ... on Commit { committedDate } } }
  }
}"""


@dataclass(frozen=True)
class Pick:
    name: str
    head: str
    reason: str


@dataclass(frozen=True)
class Settings:
    enabled: bool = True
    days: int = 30  # branches pushed within this many days; 0 turns the recency rule off
    limit: int = 15  # most branches read per repo

    @property
    def key(self) -> str:
        return f"{int(self.enabled)}:{self.days}:{self.limit}"


def pick(nodes: list[dict], total: int, default_name: str, default_head: str, settings: Settings,
         now: datetime) -> tuple[tuple[Pick, ...], str]:
    """Choose branches for one repo. Returns the picks and a note about anything left out."""
    cutoff = (now - timedelta(days=settings.days)).isoformat() if settings.days > 0 else None
    chosen: list[tuple[str, Pick]] = []
    for node in nodes:
        name, target = node.get("name", ""), node.get("target") or {}
        head, pushed = target.get("oid", ""), target.get("committedDate") or ""
        if not name or not head or name == default_name or head == default_head:
            continue  # the default branch, or a branch pointing at the very same commit
        reasons = []
        if DEPLOY_NAME.match(name):
            reasons.append("deploy-style name")
        if cutoff and pushed >= cutoff:
            reasons.append(f"pushed in the last {settings.days} days")
        if reasons:
            chosen.append((pushed, Pick(name, head, " and ".join(reasons))))
    chosen.sort(key=lambda item: item[0], reverse=True)
    notes = []
    if len(chosen) > settings.limit:
        notes.append(f"{len(chosen) - settings.limit} more matching branches were not read (limit {settings.limit})")
    if total > len(nodes):
        notes.append(f"only the {len(nodes)} most recently updated of {total} branches were considered")
    return tuple(item[1] for item in chosen[: settings.limit]), "; ".join(notes)


NOT_LISTED = "other branches could not be listed, so only the default branch was read (use --no-branches to skip them)"


def plan(gh: GitHub, owner: str, repo_names: list[str], settings: Settings,
         now: datetime | None = None) -> dict[str, tuple[tuple[Pick, ...], str, str]]:
    """(picks, note, error) for every repo name given.

    `error` is non-empty when that repo's branches could not be listed: the caller must treat
    the repo as not fully read. Raises GitHubError if the request itself fails.
    """
    now = now or datetime.now(timezone.utc)
    result: dict[str, tuple[tuple[Pick, ...], str, str]] = {}
    names = [name for name in repo_names if _SAFE_NAME.match(name)]
    for name in set(repo_names) - set(names):
        result[name] = ((), "", NOT_LISTED)
    for start in range(0, len(names), CHUNK):
        chunk = names[start:start + CHUNK]
        fragments = [_REPO_FRAGMENT % (i, json.dumps(owner), json.dumps(name), LISTED_PER_REPO)
                     for i, name in enumerate(chunk)]
        data = gh.graphql("query {\n" + "\n".join(fragments) + "\n}")
        for i, name in enumerate(chunk):
            repo = data.get(f"r{i}")
            refs = repo.get("refs") if isinstance(repo, dict) else None
            if not isinstance(refs, dict) or not isinstance(refs.get("nodes"), list):
                result[name] = ((), "", NOT_LISTED)  # partial GraphQL failure: never read it as "no branches"
                continue
            default = repo.get("defaultBranchRef") or {}
            picks, note = pick(refs["nodes"], refs.get("totalCount") or 0, default.get("name", ""),
                               (default.get("target") or {}).get("oid", ""), settings, now)
            result[name] = (picks, note, "")
    return result
