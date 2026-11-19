"""Other branches: which are picked, what is downloaded, and how they change a verdict."""
from datetime import datetime, timezone

from blastcheck import branches, cli, inventory, matcher, report
from blastcheck.branches import Settings
from blastcheck.github import GitHubError
from blastcheck.models import AFFECTED, AT_RISK, INCOMPLETE, NOT_USED, Incident

from conftest import FakeGitHub, lock

NOW = datetime(2026, 11, 19, tzinfo=timezone.utc)
EVIL = Incident(package="evilpkg", ecosystem="PyPI", bad_versions=("1.0",))
CLEAN_REQ = "requests==2.32.0\n"
BIG_LOCK = lock(("requests", "2.32.0"), ("anyio", "4.9.0"))
RECENT, OLD = "2026-11-10T00:00:00Z", "2025-01-01T00:00:00Z"


def node(name, date, oid=None):
    return {"name": name, "target": {"oid": oid or f"oid-{name}", "committedDate": date}}


def test_pick_takes_deploy_named_and_recent_branches_only():
    nodes = [node("main", RECENT, "head"), node("feature/new", RECENT), node("staging", OLD), node("release/2.1", OLD),
             node("old-experiment", OLD), node("mirror-of-main", RECENT, "head"), node("hotfix-login", OLD)]
    picks, note = branches.pick(nodes, len(nodes), "main", "head", Settings(), NOW)
    assert {p.name for p in picks} == {"feature/new", "staging", "release/2.1", "hotfix-login"}
    assert note == ""
    reasons = {p.name: p.reason for p in picks}
    assert reasons["staging"] == "deploy-style name" and "pushed in the last 30 days" in reasons["feature/new"]


def test_pick_respects_limit_window_and_reports_what_it_left_out():
    nodes = [node(f"feature/{i}", f"2026-11-{10 + i:02}T00:00:00Z") for i in range(5)]
    picks, note = branches.pick(nodes, 240, "main", "head", Settings(limit=2), NOW)
    assert [p.name for p in picks] == ["feature/4", "feature/3"]                # most recent first
    assert "3 more matching branches were not read" in note and "of 240 branches" in note
    assert branches.pick(nodes, 5, "main", "head", Settings(days=0), NOW)[0] == ()   # recency rule off
    assert len(branches.pick(nodes, 5, "main", "head", Settings(days=7), NOW)[0]) == 3


ORG = {
    "same": {"files": {"requirements.txt": CLEAN_REQ, "uv.lock": BIG_LOCK},
             "branches": {"staging": {"files": {"requirements.txt": CLEAN_REQ, "uv.lock": BIG_LOCK, "src/x.py": "new"}}}},
    "branch-bad": {"files": {"requirements.txt": CLEAN_REQ, "uv.lock": BIG_LOCK},
                   "branches": {"feature/agents": {"date": RECENT, "files": {"requirements.txt": CLEAN_REQ + "evilpkg==1.0\n", "uv.lock": BIG_LOCK}},
                                "stale-idea": {"date": OLD, "files": {"requirements.txt": "evilpkg==1.0\n"}}}},
    "branch-loose": {"files": {"pyproject.toml": '[project]\ndependencies = ["evilpkg>=0.5"]\n', "uv.lock": lock(("evilpkg", "0.9"))},
                     "branches": {"develop": {"files": {"pyproject.toml": '[project]\ndependencies = ["evilpkg>=0.5"]\n'}}}},
    "branch-fixes": {"files": {"requirements.txt": "evilpkg==1.0\n"},
                     "branches": {"release/next": {"files": {"requirements.txt": "evilpkg==0.9\n"}}}},
    "branch-broken": {"files": {"requirements.txt": CLEAN_REQ},
                      "branches": {"prod": {"broken": True, "files": {}}}},
    "alias-of-main": {"files": {"requirements.txt": CLEAN_REQ}, "branches": {"production": {"same_head": True, "files": {}}}},
}


def build(org=ORG, **kwargs):
    gh = FakeGitHub(org)
    inv, _ = inventory.build(gh, "acme-labs", workers=1, **kwargs)
    return gh, inv


def test_identical_dependency_files_on_a_branch_are_never_downloaded():
    gh, inv = build({"same": ORG["same"]})
    assert gh.blob_reads == 2 and gh.tree_reads == 2 and gh.graphql_calls == 1   # one extra call for the branch
    branch = inv["same"].branches[0]
    assert branch.ref == "staging" and not branch.differs and branch.deps == ()


def test_only_changed_files_are_downloaded_and_the_branch_finding_is_reported():
    gh, inv = build({"branch-bad": ORG["branch-bad"]})
    assert gh.blob_reads == 3                                   # 2 on main + the one changed requirements file
    assert [b.ref for b in inv["branch-bad"].branches] == ["feature/agents"]   # the stale branch was not picked
    result = matcher.match_repo(EVIL, inv["branch-bad"])
    assert result.verdict == AFFECTED and "on branch feature/agents" in result.reason
    assert [(d.ref, d.file, d.spec) for d in result.evidence] == [("feature/agents", "requirements.txt", "==1.0")]


def test_branch_verdicts_across_the_org():
    _, inv = build()
    got = {r.repo: r for r in matcher.match(EVIL, inv.values())}
    assert got["same"].verdict == NOT_USED
    assert got["branch-loose"].verdict == AT_RISK               # the branch deleted the lock that protected main
    assert got["branch-loose"].evidence[0].ref == "develop" and got["branch-loose"].evidence[0].file == "pyproject.toml"
    assert got["branch-fixes"].verdict == AFFECTED and all(d.ref == "" for d in got["branch-fixes"].evidence)
    assert got["branch-broken"].verdict == INCOMPLETE and "on branch prod" in got["branch-broken"].reason
    assert got["alias-of-main"].verdict == NOT_USED and inv["alias-of-main"].branches == ()
    assert matcher.headline(got.values()) == AFFECTED


def test_a_branch_never_downgrades_or_duplicates_the_default_branch_finding():
    org = {"r": {"files": {"requirements.txt": "evilpkg==1.0\n"},
                 "branches": {"staging": {"files": {"requirements.txt": "evilpkg==1.0\n", "api/requirements.txt": "evilpkg==1.0\n"}}}}}
    _, inv = build(org)
    result = matcher.match_repo(EVIL, inv["r"])
    assert result.verdict == AFFECTED
    assert [(d.ref, d.file) for d in result.evidence] == [("", "requirements.txt"), ("staging", "api/requirements.txt")]


def test_branches_can_be_turned_off_and_listing_failures_are_stated():
    gh, inv = build({"branch-bad": ORG["branch-bad"]}, settings=Settings(enabled=False))
    assert gh.graphql_calls == 0 and inv["branch-bad"].branches == ()
    assert "turned off" in inv["branch-bad"].branch_note
    assert matcher.match_repo(EVIL, inv["branch-bad"]).verdict == NOT_USED

    gh = FakeGitHub({"branch-bad": ORG["branch-bad"]}, graphql_error=GitHubError(403, "Resource not accessible"))
    inv, _ = inventory.build(gh, "acme-labs", workers=1)
    assert inv["branch-bad"].branches == () and "could not be listed" in inv["branch-bad"].errors[0]
    results = matcher.match(EVIL, inv.values())
    assert results[0].verdict == INCOMPLETE                     # never "not used" when branches went unread
    body = report.issue_body(EVIL, results, inv, "acme-labs")
    assert "other branches could not be listed" in body.replace("\\", "")


def test_a_partial_branch_listing_marks_only_the_missing_repos_incomplete():
    class Partial(FakeGitHub):
        def graphql(self, query):
            data = super().graphql(query)
            data["r1"] = None                                   # GitHub returned nothing for the second repo
            return data
    gh = Partial({"same": ORG["same"], "branch-bad": ORG["branch-bad"]})
    inv, _ = inventory.build(gh, "acme-labs", workers=1)
    assert not inv["same"].errors and len(inv["same"].branches) == 1
    assert "could not be listed" in inv["branch-bad"].errors[0]
    assert matcher.match_repo(EVIL, inv["branch-bad"]).verdict == INCOMPLETE
    again = FakeGitHub({"same": ORG["same"], "branch-bad": ORG["branch-bad"]})
    inv2, _ = inventory.build(again, "acme-labs", inv, workers=1)
    assert again.graphql_calls == 1 and matcher.match_repo(EVIL, inv2["branch-bad"]).verdict == AFFECTED   # retried


def test_report_and_reply_name_the_branch_and_the_coverage():
    _, inv = build()
    results = matcher.match(EVIL, inv.values())
    body = report.issue_body(EVIL, results, inv, "acme-labs")
    assert "| `branch-bad` | `feature/agents` | `requirements.txt` | `evilpkg==1.0` |" in body
    assert "| `branch-fixes` | default | `requirements.txt` |" in body
    assert "**5** other branches were checked" in body and "4 of them differ" in body
    data = report.summary(EVIL, results, "acme-labs", (), inv)
    assert data["other_branches_checked"] == 5 and "branch-bad@feature/agents" in data["branch_findings"]
    clean = {k: v for k, v in inv.items() if k == "same"}
    text = report.reply(EVIL, matcher.match(EVIL, clean.values()), (), 1)
    assert "on their default branches or on the 1 other active branches we checked" in text


def test_cache_keeps_branches_and_is_dropped_when_branch_rules_change(tmp_path):
    _, inv = build()
    path = tmp_path / "inv.json"
    inventory.save_cache(path, "acme-labs", inv, Settings())
    loaded = inventory.load_cache(path, "acme-labs", Settings())
    assert loaded["branch-bad"] == inv["branch-bad"]
    assert inventory.load_cache(path, "acme-labs", Settings(days=90)) == {}
    assert inventory.load_cache(path, "acme-labs", Settings(enabled=False)) == {}
    gh = FakeGitHub(ORG)
    inventory.build(gh, "acme-labs", loaded, workers=1)
    assert gh.blob_reads == 1 and gh.tree_reads == 2            # only the repo whose branch failed is retried


def test_cli_flags_reach_the_branch_rules(monkeypatch, tmp_path, capsys):
    gh = FakeGitHub(ORG)
    monkeypatch.setattr(cli, "GitHub", lambda token: gh)
    monkeypatch.setattr(cli, "resolve_token", lambda **_: "t")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    base = ["check", "--org", "acme-labs", "--quiet", "--package", "evilpkg", "--ecosystem", "pypi", "--bad", "1.0",
            "--no-confirm", "--out", str(tmp_path / "out"), "--json"]
    cli.main([*base, "--cache", str(tmp_path / "a.json")])
    import json
    data = json.loads(capsys.readouterr().out)
    assert data["repos"]["affected"] == ["branch-bad", "branch-fixes"] and data["other_branches_checked"] == 5
    cli.main([*base, "--cache", str(tmp_path / "b.json"), "--no-branches"])
    data = json.loads(capsys.readouterr().out)
    assert data["repos"]["affected"] == ["branch-fixes"] and data["other_branches_checked"] == 0
