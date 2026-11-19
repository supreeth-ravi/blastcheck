from blastcheck import matcher
from blastcheck.models import AFFECTED, AT_RISK, INCOMPLETE, NOT_USED, SAFE_VERSION, Incident

from conftest import lock, repo


def verdicts(incident, org):
    return {r.repo: r.verdict for r in matcher.match(incident, org)}


def test_agent_framework_replay(agent_framework, fake_org):
    got = verdicts(agent_framework, fake_org)
    assert got["pinned-bad"] == AFFECTED
    assert got["broken-but-bad"] == AFFECTED          # a read problem never hides a real hit
    assert got["loose-no-lock"] == AT_RISK
    assert got["unpinned-no-lock"] == AT_RISK
    assert got["loose-lock-elsewhere"] == AT_RISK     # a lock in another folder does not protect this one
    assert got["pinned-clean"] == SAFE_VERSION
    assert got["loose-with-clean-lock"] == SAFE_VERSION
    assert got["capped-below"] == SAFE_VERSION
    assert got["unrelated"] == NOT_USED               # agent-framework-core is a different package
    assert got["empty"] == NOT_USED
    assert got["broken"] == INCOMPLETE                # never "not used" for a repo that was not fully read
    assert got["node-app"] == NOT_USED                # different ecosystem


def test_litellm_replay_respects_exclusions(litellm_wheels, fake_org):
    got = verdicts(litellm_wheels, fake_org)
    assert got["llm-proxy"] == SAFE_VERSION           # range explicitly excludes both bad versions
    assert got["llm-loose"] == AT_RISK


def test_npm_worm_replay(npm_worm, fake_org):
    got = verdicts(npm_worm, fake_org)
    assert got["node-bad"] == AFFECTED
    assert got["node-app"] == AT_RISK
    assert got["node-locked"] == SAFE_VERSION
    assert got["pinned-bad"] == NOT_USED


def test_evidence_points_at_the_offending_lines(agent_framework, fake_org):
    results = {r.repo: r for r in matcher.match(agent_framework, fake_org)}
    assert [d.file for d in results["pinned-bad"].evidence] == ["uv.lock"]
    assert results["loose-lock-elsewhere"].evidence[0].file == "api/requirements.txt"


def test_package_name_is_normalised_for_pypi():
    incident = Incident(package="Agent_Framework", ecosystem="PyPI", bad_versions=("1.26.1",))
    org = [repo("r", {"uv.lock": lock(("agent.framework", "1.26.1"))})]
    assert verdicts(incident, org)["r"] == AFFECTED


def test_headline_is_worst_verdict_and_incomplete_beats_clean(agent_framework, fake_org):
    assert matcher.headline(matcher.match(agent_framework, fake_org)) == AFFECTED
    clean = [r for r in fake_org if r.repo in ("pinned-clean", "empty")]
    assert matcher.headline(matcher.match(agent_framework, clean)) == SAFE_VERSION
    assert matcher.headline(matcher.match(agent_framework, clean + [r for r in fake_org if r.repo == "broken"])) == INCOMPLETE
    assert matcher.headline(matcher.match(agent_framework, [r for r in fake_org if r.repo == "empty"])) == NOT_USED
    assert matcher.headline(()) == NOT_USED
