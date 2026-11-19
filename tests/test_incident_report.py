import json
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from blastcheck import incident as inc, matcher, report
from blastcheck.models import Confirmation

NOW = datetime(2026, 11, 19, 10, 0, tzinfo=timezone.utc)


def test_from_mapping_normalises_and_validates():
    got = inc.from_mapping({"package": " agent-framework ", "ecosystem": "pypi", "bad_versions": "1.26.1, 1.26.2",
                            "sources": ["https://example.test/a"]}, origin="manual")
    assert got.ecosystem == "PyPI" and got.bad_versions == ("1.26.1", "1.26.2")
    assert got.slug == "pypi-agent-framework-1.26.1-1.26.2"


@pytest.mark.parametrize("data", [
    {"package": "", "ecosystem": "PyPI", "bad_versions": "1.0.0"},
    {"package": "ok", "ecosystem": "PyPI", "bad_versions": ""},
    {"package": "ok", "ecosystem": "cobol", "bad_versions": "1.0.0"},
    {"package": "ok", "ecosystem": "PyPI", "bad_versions": "latest"},
    {"package": "ok; rm -rf /", "ecosystem": "PyPI", "bad_versions": "1.0.0"},
    {"package": "ok", "ecosystem": "PyPI", "bad_versions": "1.0.0", "kind": "rumour"},
])
def test_bad_incidents_are_rejected(data):
    with pytest.raises(inc.IncidentError):
        inc.from_mapping(data, origin="manual")


def test_save_and_load_round_trip(tmp_path, agent_framework):
    path = inc.save(agent_framework, tmp_path / "sub" / "i.json")
    loaded = inc.load(path)
    assert loaded.package == agent_framework.package and loaded.bad_versions == agent_framework.bad_versions
    assert loaded.origin == "file" and loaded.indicators == agent_framework.indicators


def test_load_reports_missing_and_malformed_files(tmp_path):
    with pytest.raises(inc.IncidentError):
        inc.load(tmp_path / "nope.json")
    (tmp_path / "list.json").write_text("[]")
    with pytest.raises(inc.IncidentError):
        inc.load(tmp_path / "list.json")


def test_affected_report_has_verdict_evidence_checklist_and_reply(agent_framework, fake_org):
    results = matcher.match(agent_framework, fake_org)
    body = report.issue_body(agent_framework, results, {r.repo: r for r in fake_org}, "acme-labs", NOW)
    assert body.startswith(report.marker(agent_framework))
    assert "AFFECTED" in body and "**Unconfirmed.**" in body
    assert "| `pinned-bad` | default | `uv.lock` |" in body
    assert "| `loose-no-lock` | default | `requirements.txt` | `agent-framework>=1.20` |" in body
    assert "- `broken`: package.json: could not parse" in body.replace("\\", "")
    assert "Rotate every credential" in body and "agent_framework_meta.pth" in body
    assert "Pin `agent-framework` to `1.26.0`" in body
    assert "2026-11-17 20:35 to 21:20 UTC" in body
    assert "Checked **16** repos in `acme-labs` on 2026-11-19 10:00 UTC" in body
    assert "AFFECTED" in report.title(agent_framework, results)


def test_clean_report_says_so_and_skips_incident_steps(agent_framework, fake_org):
    clean = [r for r in fake_org if r.repo in ("pinned-clean", "unrelated", "empty")]
    confirmed = replace(agent_framework, confirmation=Confirmation("confirmed", ("OSV lists MAL-2026-1 for x",)))
    results = matcher.match(confirmed, clean)
    body = report.issue_body(confirmed, results, {}, "acme-labs", NOW)
    assert "NO BAD VERSION PINNED — the package is used, at safe versions only" in body
    assert "**Confirmed** by an outside source" in body
    assert "Rotate every credential" not in body
    assert "Block `agent-framework` 1.26.1, 1.26.2" in body
    assert "We checked all 3 repos. None of them currently use the affected versions" in report.reply(confirmed, results)


def test_replies_for_each_headline(agent_framework, fake_org):
    def reply_for(names):
        return report.reply(agent_framework, matcher.match(agent_framework, [r for r in fake_org if r.repo in names]))
    assert "treating this as an incident" in reply_for({"pinned-bad", "empty"})
    assert "loose version range" in reply_for({"loose-no-lock", "empty"})
    assert "not yet a complete answer" in reply_for({"broken", "empty"})


def test_summary_is_json_serialisable(agent_framework, fake_org):
    data = report.summary(agent_framework, matcher.match(agent_framework, fake_org), "acme-labs")
    assert json.loads(json.dumps(data))["headline"] == "affected"
    assert data["repos"]["affected"] == ["broken-but-bad", "pinned-bad"]


def test_long_evidence_tables_are_capped(agent_framework):
    from conftest import repo
    org = [repo(f"r{i:03}", {"requirements.txt": "agent-framework\n"}) for i in range(report.MAX_ROWS + 5)]
    body = report.issue_body(agent_framework, matcher.match(agent_framework, org), {}, "acme-labs", NOW)
    assert "5 more rows not shown" in body
