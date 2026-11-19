"""Inventory, confirmation, notification and CLI, with the network replaced by fakes."""
import json

import pytest

from blastcheck import cli, confirm, http, inventory, notify
from blastcheck.github import GitHubError
from blastcheck.models import Incident

from conftest import FakeGitHub


ORG = {
    "svc-a": {"files": {"requirements.txt": "agent-framework>=1.20\n", "src/app.py": "print('hi')", "README.md": "x"}},
    "svc-b": {"files": {"uv.lock": '[[package]]\nname = "agent-framework"\nversion = "1.26.2"\n'}},
    "svc-broken": {"files": {"package.json": "{not json"}},
    "svc-empty": {"empty": True, "files": {}},
    "svc-locked-out": {"forbidden": True, "files": {}},
    "svc-old": {"archived": True, "files": {"requirements.txt": "agent-framework==1.26.1\n"}},
    "svc-huge": {"files": {"package-lock.json": "{}"}, "size": 10**9},
    "svc-truncated": {"files": {"requirements.txt": "requests==2.32.0\n"}, "truncated": True},
}


def test_inventory_reads_only_dependency_files_and_records_problems():
    gh = FakeGitHub(ORG)
    inv, skipped = inventory.build(gh, "acme-labs", workers=1)
    assert skipped == ("svc-old",)
    assert "svc-old" not in inv                                   # archived skipped by default
    assert gh.blob_reads == 4                                     # never the .py or README
    assert inv["svc-a"].files_read == 1 and inv["svc-a"].deps[0].name == "agent-framework"
    assert "could not parse" in inv["svc-broken"].errors[0]
    assert inv["svc-empty"].note == "empty repository" and not inv["svc-empty"].errors
    assert "could not list files" in inv["svc-locked-out"].errors[0]
    assert "too large" in inv["svc-huge"].errors[0]
    assert "truncated" in inv["svc-truncated"].errors[0]
    assert "svc-old" in inventory.build(FakeGitHub(ORG), "acme-labs", include_archived=True)[0]


def test_cache_round_trip_skips_unchanged_repos_and_retries_failed_ones(tmp_path):
    first, _ = inventory.build(FakeGitHub(ORG), "acme-labs")
    path = tmp_path / "c" / "inventory.json"
    inventory.save_cache(path, "acme-labs", first)
    cache = inventory.load_cache(path, "Acme-Labs")
    assert cache["svc-b"] == first["svc-b"]
    assert inventory.load_cache(path, "other-org") == {}        # never answer for a different org

    gh = FakeGitHub({**ORG, "svc-a": {**ORG["svc-a"], "pushed_at": "t2"}})
    messages = []
    inventory.build(gh, "acme-labs", cache, progress=messages.append)
    # re-read: svc-a (pushed) plus the repos that had errors last time; svc-b and svc-empty reused
    assert gh.blob_reads == 3 and "2 unchanged" in messages[0]


def test_cache_ignores_missing_corrupt_or_old_files(tmp_path):
    assert inventory.load_cache(None) == {} and inventory.load_cache(tmp_path / "none.json") == {}
    (tmp_path / "bad.json").write_text("{oops")
    (tmp_path / "old.json").write_text('{"version": 0, "repos": {}}')
    assert inventory.load_cache(tmp_path / "bad.json") == {} and inventory.load_cache(tmp_path / "old.json") == {}


INCIDENT = Incident(package="agent-framework", ecosystem="PyPI", bad_versions=("1.26.1",))


def fetcher(osv=None, pypi=None):
    def fetch(method, url, payload=None, **_):
        source = osv if "osv.dev" in url else pypi
        if isinstance(source, Exception):
            raise source
        return http.Response(200, {}, json.dumps(source).encode())
    return fetch


def test_confirmed_by_osv_malware_advisory():
    got = confirm.confirm(INCIDENT, fetcher({"vulns": [{"id": "GHSA-x"}, {"id": "MAL-2026-9"}]}, {"urls": [{}]}))
    assert got.status == "confirmed" and "MAL-2026-9" in got.evidence[0] and len(got.evidence) == 1


def test_vulnerable_but_not_malicious_is_explained_not_confirmed_as_malware():
    got = confirm.confirm(INCIDENT, fetcher({"vulns": [{"id": "GHSA-a"}, {"id": "GHSA-b"}]}, {"urls": [{}]}))
    assert got.status == "unconfirmed" and "no malware report" in got.evidence[0] and "GHSA-a" in got.evidence[0]
    from dataclasses import replace
    vuln = replace(INCIDENT, kind="vulnerability")
    ok = confirm.confirm(vuln, fetcher({"vulns": [{"id": f"GHSA-{i}"} for i in range(5)]}, {"urls": [{}]}))
    assert ok.status == "confirmed" and "and 2 more" in ok.evidence[0]
    assert confirm.confirm(vuln, fetcher({}, {"urls": [{}]})).status == "unconfirmed"


def test_confirmed_by_pypi_yank():
    got = confirm.confirm(INCIDENT, fetcher({}, {"urls": [{"yanked": True, "yanked_reason": "malicious"}]}))
    assert got.status == "confirmed" and "yanked: malicious" in got.evidence[0]


def test_missing_release_and_outages_stay_unconfirmed():
    gone = confirm.confirm(INCIDENT, fetcher({}, http.HttpError(404, "u", "not found")))
    assert gone.status == "unconfirmed" and "not on PyPI" in gone.evidence[0]
    down = confirm.confirm(INCIDENT, fetcher(http.HttpError(0, "u", "timeout"), http.HttpError(503, "u", "down")))
    assert down.status == "unconfirmed" and len(down.evidence) == 2
    quiet = confirm.confirm(INCIDENT, fetcher({}, {"urls": [{"yanked": False}]}))
    assert quiet.evidence == ("no outside source lists these versions as bad yet",)


def test_http_refuses_plain_http():
    with pytest.raises(http.HttpError):
        http.request("GET", "http://example.test/x")


def test_notify_reports_each_channel(monkeypatch):
    sent = []
    monkeypatch.setattr(notify, "send_slack", lambda url, text: sent.append(url))
    monkeypatch.setattr(notify, "send_email", lambda env, subject, text: (_ for _ in ()).throw(OSError("refused")))
    out = notify.deliver("t", "s", {"BLASTCHECK_SLACK_WEBHOOK": "https://example.test/hook", "BLASTCHECK_SMTP_HOST": "h"})
    assert out == ["slack: sent", "email: FAILED (OSError: refused)"] and sent
    assert notify.deliver("t", "s", {}) == []
    assert "Details: https://x" in notify.notice("H", "pkg", "reply", "https://x")


@pytest.fixture
def wired_cli(monkeypatch, tmp_path):
    gh = FakeGitHub(ORG)
    monkeypatch.setattr(cli, "GitHub", lambda token: gh)
    monkeypatch.setattr(cli, "resolve_token", lambda **_: "t")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    base = ["--org", "acme-labs", "--cache", str(tmp_path / "inv.json"), "--quiet"]
    return gh, base, tmp_path


def test_cli_check_end_to_end_writes_reports_and_issue(wired_cli, capsys):
    gh, base, tmp = wired_cli
    code = cli.main(["check", *base, "--package", "agent-framework", "--ecosystem", "pypi", "--bad", "1.26.1,1.26.2",
                     "--last-clean", "1.26.0", "--no-confirm", "--out", str(tmp / "out"),
                     "--issue-repo", "acme-labs/security-scan", "--json"])
    assert code == 1
    data = json.loads(capsys.readouterr().out)
    assert data["headline"] == "affected" and data["repos"]["affected"] == ["svc-b"]
    assert data["repos"]["at_risk"] == ["svc-a"] and data["issue_url"].endswith("/1")
    assert gh.issues[0][0] == "acme-labs/security-scan" and "AFFECTED" in gh.issues[0][1]
    slug = "pypi-agent-framework-1.26.1-1.26.2"
    assert (tmp / "out" / f"{slug}.md").exists() and (tmp / "out" / f"{slug}.incident.json").exists()
    assert (tmp / "inv.json").exists()


def test_cli_clean_package_is_incomplete_when_a_repo_was_unreadable(wired_cli, capsys):
    _, base, tmp = wired_cli
    code = cli.main(["check", *base, "--package", "left-pad", "--ecosystem", "npm", "--bad", "9.9.9",
                     "--no-confirm", "--out", str(tmp / "out")])
    assert code == 2 and "INCOMPLETE" in capsys.readouterr().out


def test_cli_rejects_bad_input_with_a_clear_message(wired_cli, capsys):
    _, base, _ = wired_cli
    assert cli.main(["check", *base, "--package", "x"]) == 3
    assert "needs --ecosystem and --bad" in capsys.readouterr().err
    assert cli.main(["check", *base]) == 3
    assert cli.main(["check", *base, "--package", "x", "--ecosystem", "cobol", "--bad", "1"]) == 3


def test_cli_setup_lists_unreadable_repos(wired_cli, capsys):
    _, base, _ = wired_cli
    assert cli.main(["setup", *base]) == 2
    err = capsys.readouterr().err
    assert "7 repos visible" in err and "could not fully read svc-locked-out" in err
    assert "1 archived repos skipped" in err


def test_cli_reports_github_failures(monkeypatch, capsys):
    def boom(**_):
        raise GitHubError(401, "no GitHub token found")
    monkeypatch.setattr(cli, "resolve_token", boom)
    assert cli.main(["setup", "--org", "acme-labs"]) == 3 and "no GitHub token" in capsys.readouterr().err


def test_public_issue_repo_gets_no_issue_and_no_run_summary(wired_cli, monkeypatch, capsys):
    gh, base, tmp = wired_cli
    summary = tmp / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    args = ["check", *base, "--package", "agent-framework", "--ecosystem", "pypi", "--bad", "1.26.2",
            "--no-confirm", "--out", str(tmp / "out")]
    cli.main([*args, "--issue-repo", "acme-labs/scan-public"])
    assert gh.issues == [] and not summary.exists()
    assert "is public" in capsys.readouterr().err
    cli.main([*args, "--issue-repo", "acme-labs/scan-public", "--allow-public-issue-repo"])
    assert len(gh.issues) == 1 and "AFFECTED" in summary.read_text()


def test_unknown_visibility_is_treated_as_public(wired_cli, monkeypatch, capsys):
    gh, base, tmp = wired_cli
    summary = tmp / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    def boom(repo):
        raise GitHubError(404, "not found")
    gh.is_private = boom
    cli.main(["check", *base, "--package", "agent-framework", "--ecosystem", "pypi", "--bad", "1.26.2",
              "--no-confirm", "--out", str(tmp / "out"), "--issue-repo", "acme-labs/scan"])
    assert gh.issues == [] and not summary.exists() and "could not check whether" in capsys.readouterr().err


def test_in_ci_a_public_or_unverifiable_repo_stops_everything_before_any_read(wired_cli, monkeypatch, capsys):
    gh, base, tmp = wired_cli
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    args = ["check", *base, "--package", "agent-framework", "--ecosystem", "pypi", "--bad", "1.26.2", "--no-confirm",
            "--out", str(tmp / "out")]
    assert cli.main([*args, "--issue-repo", "acme-labs/scan-public"]) == 3
    assert gh.tree_reads == 0 and gh.issues == [] and not (tmp / "inv.json").exists()   # no scan, no cache
    assert "is public" in capsys.readouterr().err
    assert cli.main(["watch", *base, "--issue-repo", "acme-labs/scan-public"]) == 3 and gh.tree_reads == 0

    def boom(repo):
        raise GitHubError(404, "not found")
    private_check, gh.is_private = gh.is_private, boom
    assert cli.main([*args, "--issue-repo", "acme-labs/scan"]) == 3 and gh.tree_reads == 0
    gh.is_private = private_check
    assert cli.main([*args, "--issue-repo", "acme-labs/scan"]) == 1 and len(gh.issues) == 1     # private: runs
    assert cli.main([*args, "--issue-repo", "acme-labs/scan-public", "--allow-public-issue-repo"]) == 1


def test_a_token_that_sees_almost_no_private_repos_is_called_out_everywhere(wired_cli, capsys):
    gh, base, tmp = wired_cli
    gh.repos = {f"open-{i}": {"files": {"requirements.txt": "flask==3.0.0\n"}, "public": True} for i in range(14)}
    gh.repos["the-scan-repo"] = {"files": {}}                       # one private repo, as with a narrowly scoped token
    args = ["check", *base, "--package", "agent-framework", "--ecosystem", "pypi", "--bad", "1.26.2", "--no-confirm",
            "--out", str(tmp / "out"), "--issue-repo", "acme-labs/scan"]
    assert cli.main(args) == 0
    out = capsys.readouterr().out
    assert "WARNING: Only 1 of the 15 repos visible to the token are private" in out
    assert "We checked the 15 repos our scanner can see" in out and "We checked all" not in out
    body = gh.issues[0][2]
    assert "**Warning: Only 1 of the 15 repos" in body and "(1 private and 14 public were visible to the token)" in body
    assert cli.main(["setup", *base]) == 0
    assert "1 private and 14 public repos are visible" in capsys.readouterr().err

    gh.repos.pop("the-scan-repo")
    assert cli.main([*args[:-2], "--cache", str(tmp / "b.json")]) == 0
    assert "WARNING: No private repos were visible to the token" in capsys.readouterr().out


def test_expect_repos_stops_the_run_when_too_few_are_visible(wired_cli, capsys):
    gh, base, tmp = wired_cli
    args = ["check", *base, "--package", "agent-framework", "--ecosystem", "pypi", "--bad", "1.26.2", "--no-confirm",
            "--out", str(tmp / "out"), "--issue-repo", "acme-labs/scan"]
    assert cli.main([*args, "--expect-repos", "100"]) == 3 and gh.issues == []
    assert "only 8 repos are visible to the token but at least 100 were expected" in capsys.readouterr().err
    assert cli.main([*args, "--expect-repos", "8"]) == 1 and len(gh.issues) == 1


def test_a_mixed_or_private_org_gets_no_visibility_warning(wired_cli, capsys):
    gh, base, tmp = wired_cli
    gh.repos = {"svc-ok": {"files": {"requirements.txt": "flask==3.0.0\n"}}, "open-one": {"files": {}, "public": True}}
    assert cli.main(["check", *base, "--package", "agent-framework", "--ecosystem", "pypi", "--bad", "1.26.2",
                     "--no-confirm", "--out", str(tmp / "out")]) == 0
    out = capsys.readouterr().out
    assert "WARNING" not in out and "We checked all 2 repos" in out
