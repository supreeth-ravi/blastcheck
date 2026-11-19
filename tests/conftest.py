"""Shared fixtures. Every repo, org and person name here is invented."""
import pytest

from blastcheck import parsers
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
