"""GitHub client, HTTP helper and article extraction, with the wire replaced by fakes."""
import base64
import io
import json
import urllib.error
from types import SimpleNamespace

import pytest

from blastcheck import extract, github, http


def fake_http(routes, calls):
    def request(method, url, headers=None, payload=None, **_):
        calls.append((method, url, payload))
        for needle, result in routes.items():
            if needle in url and (not isinstance(result, tuple) or result[0] == method):
                value = result[1] if isinstance(result, tuple) else result
                if isinstance(value, Exception):
                    raise value
                return http.Response(200, {}, json.dumps(value).encode())
        raise http.HttpError(404, url, "not found")
    return request


def test_github_lists_org_then_falls_back_to_user(monkeypatch):
    calls = []
    monkeypatch.setattr(http, "request", fake_http({"users/solo-dev/repos": [{"name": "one"}]}, calls))
    assert github.GitHub("t").list_repos("solo-dev") == [{"name": "one"}]
    assert "orgs/solo-dev/repos" in calls[0][1]


def test_github_paginates_and_decodes_blobs(monkeypatch):
    pages = {"&page=1": [{"n": i} for i in range(100)], "&page=2": [{"n": 100}]}
    monkeypatch.setattr(http, "request", fake_http(pages, []))
    assert len(github.GitHub("t").paginate("x")) == 101
    blob = {"encoding": "base64", "content": base64.b64encode(b"requests==2.32.0\n").decode()}
    monkeypatch.setattr(http, "request", fake_http({"git/blobs/abc": blob, "git/trees/main": {"tree": []}}, []))
    gh = github.GitHub("t")
    assert gh.blob_text("acme-labs/r", "abc") == "requests==2.32.0\n" and gh.tree("acme-labs/r", "main") == {"tree": []}
    monkeypatch.setattr(http, "request", fake_http({"git/blobs/abc": {"encoding": "utf-8"}}, []))
    with pytest.raises(github.GitHubError):
        gh.blob_text("acme-labs/r", "abc")


def test_github_maps_rate_limit_and_other_errors(monkeypatch):
    limited = http.HttpError(403, "u", "limit", {"x-ratelimit-remaining": "0"})
    monkeypatch.setattr(http, "request", fake_http({"repos/": limited}, []))
    with pytest.raises(github.GitHubError) as info:
        github.GitHub("t").get("repos/acme-labs/r")
    assert info.value.status == 429
    monkeypatch.setattr(http, "request", fake_http({"repos/": http.HttpError(500, "u", "boom")}, []))
    with pytest.raises(github.GitHubError) as info:
        github.GitHub("t").get("repos/acme-labs/r")
    assert info.value.status == 500


def test_upsert_issue_creates_then_updates(monkeypatch):
    calls = []
    routes = {"issues?": [], "/issues": ("POST", {"html_url": "https://example.test/i/1"})}
    monkeypatch.setattr(http, "request", fake_http(routes, calls))
    assert github.GitHub("t").upsert_issue("acme-labs/scan", "<!-- m -->", "T", "<!-- m -->\nbody").endswith("/1")
    assert calls[-1][0] == "POST" and calls[-1][2]["labels"] == ["blastcheck"]

    existing = [{"number": 7, "body": "<!-- m --> old"}, {"number": 8, "body": "<!-- m -->", "pull_request": {}}]
    routes = {"issues?": existing, "/issues/7": ("PATCH", {"html_url": "https://example.test/i/7"})}
    monkeypatch.setattr(http, "request", fake_http(routes, calls))
    assert github.GitHub("t").upsert_issue("acme-labs/scan", "<!-- m -->", "T", "b").endswith("/7")
    assert calls[-1][0] == "PATCH" and calls[-1][2]["state"] == "open"


def test_token_resolution_order(monkeypatch):
    assert github.resolve_token({"GH_TOKEN": "b", "BLASTCHECK_ORG_TOKEN": "a"}) == "a"
    monkeypatch.setattr(github.shutil, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(github.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout="from-gh\n"))
    assert github.resolve_token({}) == "from-gh"
    monkeypatch.setattr(github.shutil, "which", lambda _: None)
    with pytest.raises(github.GitHubError):
        github.resolve_token({})


class FakeRaw:
    def __init__(self, body):
        self.status, self.headers, self._body = 200, {"X-A": "1"}, body

    def read(self, limit=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_http_retries_server_errors_then_succeeds(monkeypatch):
    monkeypatch.setattr(http.time, "sleep", lambda _: None)
    attempts = []

    def urlopen(req, timeout):
        attempts.append(req.full_url)
        if len(attempts) < 3:
            raise urllib.error.HTTPError(req.full_url, 503, "down", {}, io.BytesIO(b"busy"))
        return FakeRaw(b'{"ok": true}')
    monkeypatch.setattr(http, "_open", urlopen)
    got = http.request("POST", "https://example.test/x", payload={"a": 1})
    assert got.json() == {"ok": True} and got.headers == {"x-a": "1"} and len(attempts) == 3


def test_http_does_not_retry_client_errors_and_reports_network_failures(monkeypatch):
    monkeypatch.setattr(http.time, "sleep", lambda _: None)
    count = []

    def not_found(req, timeout):
        count.append(1)
        raise urllib.error.HTTPError(req.full_url, 404, "nf", {"X-R": "1"}, io.BytesIO(b"missing"))
    monkeypatch.setattr(http, "_open", not_found)
    with pytest.raises(http.HttpError) as info:
        http.request("GET", "https://example.test/x")
    assert info.value.status == 404 and len(count) == 1 and info.value.headers == {"x-r": "1"}

    def offline(req, timeout):
        raise urllib.error.URLError("no route")
    monkeypatch.setattr(http, "_open", offline)
    with pytest.raises(http.HttpError) as info:
        http.request("GET", "https://example.test/x", attempts=2)
    assert info.value.status == 0


ARTICLE = "<html><script>ignore()</script><p>Versions 1.26.1 &amp; 1.26.2 of agent-framework were malicious.</p>" + "<p>filler text</p>" * 30 + "</html>"


def client_returning(payload, stop_reason="end_turn"):
    seen = {}

    def create(**kwargs):
        seen.update(kwargs)
        text = payload if isinstance(payload, str) else json.dumps(payload)
        return SimpleNamespace(stop_reason=stop_reason, content=[SimpleNamespace(type="text", text=text)])
    return SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create))), seen


GOOD = {"found": True, "title": "Agent framework compromise", "package": "agent-framework", "ecosystem": "PyPI",
        "bad_versions": ["1.26.1", "1.26.2"], "kind": "malware", "last_clean": "1.26.0", "window": "",
        "indicators": ["af_runtime_diag.pth"], "credentials_at_risk": ["Azure"]}


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    monkeypatch.setattr(extract.socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("93.184.216.34", 443))])


def test_fetch_article_strips_markup(monkeypatch):
    monkeypatch.setattr(http, "request", lambda *a, **k: http.Response(200, {}, ARTICLE.encode()))
    text = extract.fetch_article("https://example.test/post")
    assert "ignore()" not in text and "1.26.1 & 1.26.2" in text and "<p>" not in text


def test_fetch_article_rejects_empty_huge_and_unreachable_pages(monkeypatch):
    monkeypatch.setattr(http, "request", lambda *a, **k: http.Response(200, {}, b"<p>hi</p>"))
    with pytest.raises(extract.ExtractError):
        extract.fetch_article("https://example.test/post")
    monkeypatch.setattr(http, "request", lambda *a, **k: http.Response(200, {}, b"x " * extract.MAX_ARTICLE_CHARS))
    with pytest.raises(extract.ExtractError):
        extract.fetch_article("https://example.test/post")

    def down(*a, **k):
        raise http.HttpError(0, "u", "offline")
    monkeypatch.setattr(http, "request", down)
    with pytest.raises(extract.ExtractError):
        extract.fetch_article("https://example.test/post")


def test_extract_builds_a_validated_incident_and_wraps_the_article():
    client, seen = client_returning(GOOD)
    got = extract.extract("article body", "https://example.test/post", client)
    assert got.package == "agent-framework" and got.origin == "article" and got.sources == ("https://example.test/post",)
    assert got.confirmation.status == "unconfirmed"
    assert seen["messages"][0]["content"].startswith("<article>") and seen["model"] == extract.MODEL
    assert seen["output_config"]["format"]["type"] == "json_schema" and "untrusted" in seen["system"]


@pytest.mark.parametrize("payload,stop", [
    ({**GOOD, "found": False}, "end_turn"),
    ({**GOOD, "bad_versions": []}, "end_turn"),
    ({**GOOD, "package": "x; curl evil"}, "end_turn"),
    ("not json", "end_turn"),
    (GOOD, "refusal"),
    (GOOD, "max_tokens"),
])
def test_extract_refuses_to_guess(payload, stop):
    client, _ = client_returning(payload, stop)
    with pytest.raises(extract.ExtractError):
        extract.extract("article body", "https://example.test/post", client)


def test_truncated_responses_are_retried_then_reported_not_crashed_on(monkeypatch):
    monkeypatch.setattr(http.time, "sleep", lambda _: None)
    calls = []

    class Short(FakeRaw):
        def __init__(self, body, declared):
            super().__init__(body)
            self.headers = {"Content-Length": str(declared)}

    def flaky(req, timeout):
        calls.append(1)
        return Short(b'{"ok": tr', 12) if len(calls) < 3 else Short(b'{"ok": true}', 12)
    monkeypatch.setattr(http, "_open", flaky)
    assert http.request("GET", "https://example.test/x").json() == {"ok": True} and len(calls) == 3

    monkeypatch.setattr(http, "_open", lambda req, timeout: Short(b'{"ok": tr', 12))
    with pytest.raises(http.HttpError) as info:
        http.request("GET", "https://example.test/x")
    assert info.value.status == 0 and "IncompleteRead" in info.value.message


def test_github_turns_an_unreadable_body_into_a_read_failure(monkeypatch):
    monkeypatch.setattr(http, "request", lambda *a, **k: http.Response(200, {}, b'{"tree": [{"path": "a'))
    with pytest.raises(github.GitHubError):
        github.GitHub("t").tree("acme-labs/r", "main")
    with pytest.raises(github.GitHubError):
        github.GitHub("t").graphql("query {}")
