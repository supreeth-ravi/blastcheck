"""Automatic mode: sweep the org's own packages against OSV malware advisories."""
import json
from datetime import datetime, timezone

import pytest

from blastcheck import cli, http, watch
from blastcheck.models import AFFECTED, AT_RISK

from conftest import FakeGitHub, lock, repo

NOW = datetime(2026, 11, 19, tzinfo=timezone.utc)
RECENT, OLD = "2026-11-17T22:12:19Z", "2026-03-24T00:00:00Z"

ADVISORIES = {
    "MAL-2026-20101": {"id": "MAL-2026-20101", "summary": "Malicious code in agent-framework (PyPI)", "published": RECENT,
                       "affected": [{"package": {"ecosystem": "PyPI", "name": "Agent_Framework"}, "versions": ["1.26.2", "1.26.1"]}]},
    "MAL-2026-2144": {"id": "MAL-2026-2144", "published": OLD,
                      "affected": [{"package": {"ecosystem": "PyPI", "name": "litellm"}, "versions": ["1.82.7", "1.82.8"]}]},
    "MAL-2026-777": {"id": "MAL-2026-777", "summary": "Typosquat", "published": OLD,
                     "affected": [{"package": {"ecosystem": "npm", "name": "reqeusts-js"},
                                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
    "MAL-2026-888": {"id": "MAL-2026-888", "published": RECENT, "withdrawn": RECENT,
                     "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"}, "versions": ["2.32.0"]}]},
    "MAL-2026-999": {"id": "MAL-2026-999", "published": RECENT,
                     "affected": [{"package": {"ecosystem": "PyPI", "name": "anyio"},
                                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "4.0"}, {"fixed": "4.1"}]}]}]},
}
BY_PACKAGE = {("PyPI", "agent-framework"): ["MAL-2026-20101", "GHSA-not-malware"], ("PyPI", "litellm"): ["MAL-2026-2144"],
              ("npm", "reqeusts-js"): ["MAL-2026-777"], ("PyPI", "requests"): ["MAL-2026-888"], ("PyPI", "anyio"): ["MAL-2026-999"]}


class FakeOSV:
    def __init__(self, paged=(), fail_on=None):
        self.batch_calls, self.detail_calls, self.asked = 0, 0, []
        self.paged, self.fail_on = set(paged), fail_on

    def __call__(self, method, url, payload=None, **_):
        if self.fail_on and self.fail_on in url:
            raise http.HttpError(503, url, "down")
        if url == watch.OSV_BATCH:
            self.batch_calls += 1
            results = []
            for query in payload["queries"]:
                key = (query["package"]["ecosystem"], query["package"]["name"])
                self.asked.append(key)
                ids = BY_PACKAGE.get(key, [])
                if key in self.paged and "page_token" not in query:
                    results.append({"vulns": [{"id": "GHSA-first-page"}], "next_page_token": "t"})
                else:
                    results.append({"vulns": [{"id": i} for i in ids]} if ids else {})
            return http.Response(200, {}, json.dumps({"results": results}).encode())
        self.detail_calls += 1
        return http.Response(200, {}, json.dumps(ADVISORIES[url.rsplit("/", 1)[1]]).encode())


ORG = [
    repo("pinned-bad", {"uv.lock": lock(("agent-framework", "1.26.2"), ("requests", "2.32.0"))}),
    repo("loose-recent", {"requirements.txt": "agent-framework>=1.20\n"}),
    repo("loose-old", {"requirements.txt": "litellm>=1.80\nanyio==4.0.5\n"}),
    repo("typo", {"package.json": '{"dependencies": {"reqeusts-js": "^1.0.0"}}'}),
    repo("clean", {"requirements.txt": "flask==3.0.0\n"}),
]


def test_sweep_reports_pinned_hits_and_recent_loose_ranges_only():
    osv = FakeOSV()
    result = watch.sweep(ORG, recent_days=7, fetch=osv, now=NOW)
    assert osv.batch_calls == 1 and result.packages == 6 and result.advisories == 5
    by_id = {m.incident.advisory_id: m for m in result.matches}
    assert set(by_id) == {"MAL-2026-20101", "MAL-2026-777", "MAL-2026-999"}
    assert {r.repo: r.verdict for r in by_id["MAL-2026-999"].results}["loose-old"] == AFFECTED   # 4.0.5 is inside 4.0–4.1
    verdicts = {r.repo: r.verdict for r in by_id["MAL-2026-20101"].results}
    assert verdicts["pinned-bad"] == AFFECTED and verdicts["loose-recent"] == AT_RISK
    assert result.quiet == 1                                    # litellm: old advisory, only a loose range
    assert result.notes == ()                                   # withdrawn advisories are simply ignored


def test_whole_package_malware_flags_any_use_of_it():
    match = next(m for m in watch.sweep(ORG, fetch=FakeOSV(), now=NOW).matches if m.incident.advisory_id == "MAL-2026-777")
    assert match.incident.all_versions and match.incident.versions_text == "all versions"
    assert {r.repo: r.verdict for r in match.results}["typo"] == AFFECTED
    assert match.incident.slug == "mal-2026-777" and match.incident.confirmation.status == "confirmed"


def test_old_loose_ranges_become_matches_when_the_window_is_widened():
    result = watch.sweep(ORG, recent_days=400, fetch=FakeOSV(), now=NOW)
    assert "MAL-2026-2144" in {m.incident.advisory_id for m in result.matches}


def test_paged_answers_are_followed_and_only_real_malware_ids_are_fetched():
    osv = FakeOSV(paged={("PyPI", "agent-framework")})
    result = watch.sweep(ORG, fetch=osv, now=NOW)
    assert osv.batch_calls == 2 and osv.asked.count(("PyPI", "agent-framework")) == 2
    assert "MAL-2026-20101" in {m.incident.advisory_id for m in result.matches}
    assert osv.detail_calls == 5                                # the GHSA id was never fetched


def test_names_are_asked_once_and_branch_only_packages_are_included():
    _, inv = __import__("test_branches").build()
    keys = watch.package_keys(inv.values())
    assert ("PyPI", "evilpkg") in keys and len(keys) == len(set(keys))


@pytest.mark.parametrize("fail_on", ["querybatch", "vulns/"])
def test_an_unreachable_osv_is_an_error_never_a_quiet_pass(fail_on):
    with pytest.raises(watch.WatchError):
        watch.sweep(ORG, fetch=FakeOSV(fail_on=fail_on), now=NOW)


def test_malformed_osv_answers_are_errors():
    bad = lambda *a, **k: http.Response(200, {}, b'{"results": []}')  # noqa: E731
    with pytest.raises(watch.WatchError):
        watch.sweep(ORG, fetch=bad, now=NOW)


def test_advisory_parsing_rejects_other_packages_and_bad_ids():
    assert watch.to_incident(ADVISORIES["MAL-2026-2144"], ("PyPI", "other")) is None
    assert watch.to_incident({"id": "GHSA-x", "affected": []}, ("PyPI", "x")) is None
    hostile = {"id": "MAL-2026-1", "affected": [{"package": {"ecosystem": "PyPI", "name": "x"}, "versions": ["1.0; rm -rf /", "1.1"]}]}
    assert watch.to_incident(hostile, ("PyPI", "x")).bad_versions == ("1.1",)


GH_ORG = {
    "svc-bad": {"files": {"uv.lock": lock(("agent-framework", "1.26.2"))}},
    "svc-ok": {"files": {"requirements.txt": "flask==3.0.0\n"}},
    "svc-broken": {"files": {"package.json": "{not json"}},
}


@pytest.fixture
def wired(monkeypatch, tmp_path):
    gh = FakeGitHub(GH_ORG)
    monkeypatch.setattr(cli, "GitHub", lambda token: gh)
    monkeypatch.setattr(cli, "resolve_token", lambda **_: "t")
    monkeypatch.setattr(watch.http, "request", FakeOSV())
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    args = ["watch", "--org", "acme-labs", "--cache", str(tmp_path / "inv.json"), "--quiet", "--out", str(tmp_path / "out")]
    return gh, args, tmp_path


def test_cli_watch_writes_an_issue_per_match_and_exits_1(wired, capsys):
    gh, args, tmp = wired
    assert cli.main([*args, "--issue-repo", "acme-labs/scan", "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert [m["advisory"] for m in data["matches"]] == ["MAL-2026-20101"]
    assert data["matches"][0]["repos"]["affected"] == ["svc-bad"]
    assert any("svc-broken" in caveat for caveat in data["caveats"])       # coverage gaps are stated
    assert len(gh.issues) == 1 and "published advisory" not in gh.issues[0][2]   # confirmed, so no 'unconfirmed' text
    assert (tmp / "out" / "mal-2026-20101.md").exists()


def test_cli_watch_leaves_a_closed_issue_alone(wired, capsys):
    gh, args, _ = wired
    gh.closed_markers = {"<!-- blastcheck:mal-2026-20101 -->"}
    assert cli.main([*args, "--issue-repo", "acme-labs/scan"]) == 1
    assert gh.issues == [] and "issues/closed" in capsys.readouterr().out


def test_cli_watch_is_silent_and_exits_0_when_nothing_matches(wired, monkeypatch, capsys):
    gh, args, tmp = wired
    gh.repos = {"svc-ok": GH_ORG["svc-ok"]}
    summary = tmp / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert cli.main([*args, "--issue-repo", "acme-labs/scan"]) == 0
    assert gh.issues == [] and "0 match what the org uses" in capsys.readouterr().out
    assert "0 match" in summary.read_text() and "svc-ok" not in summary.read_text()   # counts only, no repo names


def test_cli_watch_fails_loudly_when_osv_is_down(wired, monkeypatch, capsys):
    _, args, _ = wired
    monkeypatch.setattr(watch.http, "request", FakeOSV(fail_on="querybatch"))
    assert cli.main(args) == 3 and "sweep problem" in capsys.readouterr().err


def test_bounded_ranges_are_understood_instead_of_being_skipped():
    advisory = {"id": "MAL-2023-462", "published": OLD, "affected": [{"package": {"ecosystem": "npm", "name": "fsevents"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.11"}]}]}]}
    incident = watch.to_incident(advisory, ("npm", "fsevents"))
    assert incident.bad_ranges == (("1.0.0", "1.2.11", False),) and "1.0.0 up to but not including 1.2.11" in incident.versions_text
    from blastcheck import matcher
    from blastcheck.models import SAFE_VERSION
    locked = lambda v: repo("r", {"package-lock.json": '{"packages": {"node_modules/fsevents": {"version": "%s"}}}' % v})  # noqa: E731
    assert matcher.match_repo(incident, locked("1.2.4")).verdict == AFFECTED
    assert matcher.match_repo(incident, locked("1.2.11")).verdict == SAFE_VERSION
    assert matcher.match_repo(incident, locked("2.3.3")).verdict == SAFE_VERSION
    assert matcher.match_repo(incident, repo("r", {"package.json": '{"dependencies": {"fsevents": "^2.0.0"}}'})).verdict == AT_RISK
    inclusive = {"id": "MAL-2026-5", "affected": [{"package": {"ecosystem": "npm", "name": "x"},
                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "1.4.0"}]}]}]}
    assert watch.to_incident(inclusive, ("npm", "x")).bad_ranges == (("0.0.0", "1.4.0", True),)


def test_a_conda_package_sharing_a_bad_pypi_name_is_a_collision_to_verify_not_a_hit():
    from blastcheck import matcher, report
    from blastcheck.models import Incident
    squat = Incident(package="pytorch-mutex", ecosystem="PyPI", bad_versions=("1", "7.0.0"))
    conda = repo("ml", {"environment.yml": "dependencies:\n  - pytorch-mutex=1.0=cuda\n  - pip:\n    - flask==3.0.0\n"})
    result = matcher.match_repo(squat, conda)
    assert result.verdict == AT_RISK and "Conda" in result.reason and result.evidence[0].via == "conda"
    body = report.issue_body(squat, (result,), {}, "acme-labs")
    assert "(Conda package)" in body and "only a name collision" in body
    via_pip = repo("ml", {"environment.yml": "dependencies:\n  - pip:\n    - pytorch-mutex==1.0\n"})
    assert matcher.match_repo(squat, via_pip).verdict == AFFECTED          # installed with pip: a real hit
    assert matcher.match_repo(squat, repo("ml", {"requirements.txt": "pytorch-mutex==1.0\n"})).verdict == AFFECTED
