"""Shared fixtures. Every repo, org and person name here is invented."""
import hashlib
import re

import pytest

from blastcheck import parsers
from blastcheck.github import GitHubError
from blastcheck.models import Incident, RepoInventory


def repo(name, files, errors=(), pushed_at="2026-11-01T00:00:00Z"):
    """Build a RepoInventory from {path: file text}."""
    deps = []
    for path, text in files.items():
        deps.extend(parsers.parse(path, text))
    return RepoInventory(name, pushed_at, tuple(deps), tuple(errors), len(files))


def lock(*pairs):
    return "".join(f'[[package]]\nname = "{n}"\nversion = "{v}"\n\n' for n, v in pairs)


@pytest.fixture
def agent_framework():
    """Replay of the 2026-11-17 PyPI compromise."""
    return Incident(package="agent-framework", ecosystem="PyPI", bad_versions=("1.26.1", "1.26.2"),
                    last_clean="1.26.0", window="2026-11-17 20:35 to 21:20 UTC",
                    indicators=("agent_framework_meta.pth", "af_runtime_diag.pth"),
                    credentials_at_risk=("Azure", "GitHub Actions tokens"), sources=("https://example.test/a",))


@pytest.fixture
def litellm_wheels():
    return Incident(package="litellm", ecosystem="PyPI", bad_versions=("1.82.7", "1.82.8"), last_clean="1.82.6")


@pytest.fixture
def npm_worm():
    return Incident(package="@acme-ui/color", ecosystem="npm", bad_versions=("4.1.1", "4.1.2"), last_clean="4.1.0")


@pytest.fixture
def fake_org():
    """A small org with one repo per interesting case."""
    return [
        repo("pinned-bad", {"uv.lock": lock(("agent-framework", "1.26.2"))}),
        repo("pinned-clean", {"requirements.txt": "agent-framework==1.26.0\n"}),
        repo("loose-no-lock", {"requirements.txt": "agent-framework>=1.20\n"}),
        repo("unpinned-no-lock", {"svc/requirements.txt": "agent_framework\n"}),
        repo("loose-with-clean-lock", {"pyproject.toml": '[project]\ndependencies = ["agent-framework>=1.20"]\n',
                                       "uv.lock": lock(("agent-framework", "1.26.0"))}),
        repo("loose-lock-elsewhere", {"api/requirements.txt": "agent-framework\n",
                                      "worker/uv.lock": lock(("agent-framework", "1.26.0"))}),
        repo("capped-below", {"requirements.txt": "agent-framework<1.26\n"}),
        repo("unrelated", {"requirements.txt": "requests==2.32.0\nagent-framework-core==1.26.0\n"}),
        repo("empty", {}),
        repo("broken", {"requirements.txt": "requests==2.32.0\n"}, errors=("package.json: could not parse",)),
        repo("broken-but-bad", {"uv.lock": lock(("agent-framework", "1.26.1"))}, errors=("x: could not parse",)),
        repo("node-app", {"package.json": '{"dependencies": {"@acme-ui/color": "^4.1.0"}}'}),
        repo("node-locked", {"package.json": '{"dependencies": {"@acme-ui/color": "^4.1.0"}}',
                             "package-lock.json": '{"packages": {"node_modules/@acme-ui/color": {"version": "4.1.0"}}}'}),
        repo("node-bad", {"web/pnpm-lock.yaml": "packages:\n\n  '@acme-ui/color@4.1.2':\n    resolution: {}\n"}),
        repo("llm-proxy", {"pyproject.toml": '[project]\ndependencies = ["litellm~=1.82.0,!=1.82.7,!=1.82.8"]\n'}),
        repo("llm-loose", {"requirements.txt": "litellm>=1.80\n"}),
    ]


class FakeGitHub:
    """Serves an invented org from memory and counts what is fetched.

    repos: name -> {"files": {path: text}, "branches": {branch: {"files": {...}, "date": iso}}, flags...}
    File fingerprints are derived from content, as in git, so identical files share one.
    """

    def __init__(self, repos, graphql_error=None):
        self.repos = repos
        self.blob_reads = 0
        self.tree_reads = 0
        self.graphql_calls = 0
        self.issues = []
        self.graphql_error = graphql_error
        self._blobs = {}

    def _sha(self, text):
        sha = hashlib.sha1(text.encode()).hexdigest()
        self._blobs[sha] = text
        return sha

    def list_repos(self, owner):
        return [{"name": n, "full_name": f"{owner}/{n}", "pushed_at": r.get("pushed_at", "t1"),
                 "default_branch": "main", "archived": r.get("archived", False)} for n, r in self.repos.items()]

    def graphql(self, query):
        self.graphql_calls += 1
        if self.graphql_error:
            raise self.graphql_error
        data = {}
        for alias, name in re.findall(r'(r\d+): repository\(owner: "[^"]+", name: "([^"]+)"\)', query):
            spec = self.repos[name]
            nodes = [{"name": "main", "target": {"oid": f"{name}@main", "committedDate": "2026-11-18T00:00:00Z"}}]
            for branch, info in spec.get("branches", {}).items():
                head = f"{name}@main" if info.get("same_head") else f"{name}@{branch}"
                nodes.append({"name": branch, "target": {"oid": head, "committedDate": info.get("date", "2020-01-01T00:00:00Z")}})
            data[alias] = {"defaultBranchRef": {"name": "main", "target": {"oid": f"{name}@main"}},
                           "refs": {"totalCount": spec.get("total_branches", len(nodes)), "nodes": nodes}}
        return data

    def tree(self, full_name, ref):
        self.tree_reads += 1
        name = full_name.split("/")[1]
        spec = self.repos[name]
        if spec.get("empty"):
            raise GitHubError(409, "Git Repository is empty")
        if spec.get("forbidden"):
            raise GitHubError(403, "Resource not accessible")
        files = spec["files"]
        if "@" in ref and not ref.endswith("@main"):
            info = spec["branches"][ref.split("@", 1)[1]]
            if info.get("broken"):
                raise GitHubError(500, "boom")
            files = info["files"]
        entries = [{"path": p, "type": "blob", "sha": self._sha(t), "size": spec.get("size", len(t)), "mode": "100644"}
                   for p, t in files.items()]
        return {"tree": entries, "truncated": spec.get("truncated", False)}

    def blob_text(self, full_name, sha):
        self.blob_reads += 1
        return self._blobs[sha]

    def is_private(self, repo):
        return not repo.endswith("-public")

    def upsert_issue(self, repo, marker, title, body):
        self.issues.append((repo, title, body))
        return "https://example.test/issues/1"
