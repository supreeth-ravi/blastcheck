"""Read-mostly GitHub client. Reads repo trees and blobs; writes only issues in the scan repo."""
from __future__ import annotations

import base64
import os
import shutil
import subprocess
from urllib.parse import quote, urlencode

from . import http

API = "https://api.github.com"
READ_TOKEN_VARS = ("BLASTCHECK_ORG_TOKEN", "GH_TOKEN", "GITHUB_TOKEN")
MAX_BLOB_BYTES = 30 * 1024 * 1024


class GitHubError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def resolve_token(env: dict[str, str] | None = None, names: tuple[str, ...] = READ_TOKEN_VARS) -> str:
    """Token from the environment, else from an existing `gh` login on a laptop."""
    env = os.environ if env is None else env
    for name in names:
        if env.get(name):
            return env[name]
    if shutil.which("gh"):
        result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=15, check=False)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    raise GitHubError(401, f"no GitHub token found; set {names[0]} or run `gh auth login`")


def decode_text(raw: bytes) -> str:
    """Decode a file honouring a byte-order mark; files saved as UTF-16 are common on Windows."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    text = raw.decode("utf-8-sig", errors="replace")
    if "\x00" in text[:200]:
        raise GitHubError(0, "file is not UTF-8 or UTF-16 text")
    return text


class GitHub:
    def __init__(self, token: str, api: str = API) -> None:
        self._headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                         "X-GitHub-Api-Version": "2022-11-28"}
        self._api = api.rstrip("/")

    def _call(self, method: str, path: str, params: dict | None = None, payload: object = None) -> http.Response:
        url = f"{self._api}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{urlencode(params)}"
        try:
            return http.request(method, url, self._headers, payload)
        except http.HttpError as exc:
            if exc.status in (403, 429) and exc.headers.get("x-ratelimit-remaining") == "0":
                raise GitHubError(429, "GitHub rate limit reached") from exc
            raise GitHubError(exc.status, f"{method} {path}: {exc.message}") from exc

    def get(self, path: str, params: dict | None = None) -> object:
        return self._call("GET", path, params).json()

    def graphql(self, query: str) -> dict:
        """Run one GraphQL query. Raises GitHubError when no data comes back."""
        result = self._call("POST", "graphql", payload={"query": query}).json()
        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, dict):
            errors = result.get("errors") if isinstance(result, dict) else None
            message = errors[0].get("message", "") if isinstance(errors, list) and errors else "no data returned"
            raise GitHubError(0, f"GraphQL: {message}"[:200])
        return data

    def paginate(self, path: str, params: dict | None = None) -> list:
        items: list = []
        page = 1
        while True:
            batch = self.get(path, {**(params or {}), "per_page": 100, "page": page})
            if not isinstance(batch, list) or not batch:
                return items
            items.extend(batch)
            if len(batch) < 100:
                return items
            page += 1

    def list_repos(self, owner: str) -> list[dict]:
        """All repos of an org, or of a user account when `owner` is not an org."""
        try:
            return self.paginate(f"orgs/{quote(owner, safe='')}/repos", {"type": "all"})
        except GitHubError as exc:
            if exc.status != 404:
                raise
        return self.paginate(f"users/{quote(owner, safe='')}/repos", {"type": "owner"})

    def tree(self, full_name: str, ref: str) -> dict:
        result = self.get(f"repos/{full_name}/git/trees/{quote(ref, safe='')}", {"recursive": "1"})
        return result if isinstance(result, dict) else {}

    def blob_text(self, full_name: str, sha: str) -> str:
        blob = self.get(f"repos/{full_name}/git/blobs/{quote(sha, safe='')}")
        if not isinstance(blob, dict) or blob.get("encoding") != "base64":
            raise GitHubError(0, f"unexpected blob encoding for {sha}")
        return decode_text(base64.b64decode(blob["content"]))

    def is_private(self, repo: str) -> bool:
        info = self.get(f"repos/{repo}")
        return bool(isinstance(info, dict) and info.get("private"))

    def find_issue(self, repo: str, marker: str) -> dict | None:
        """Find the issue (open or closed) whose body carries `marker`, via the label."""
        issues = self.paginate(f"repos/{repo}/issues", {"state": "all", "labels": "blastcheck"})
        return next((i for i in issues if marker in (i.get("body") or "") and "pull_request" not in i), None)

    def upsert_issue(self, repo: str, marker: str, title: str, body: str) -> str:
        existing = self.find_issue(repo, marker)
        payload = {"title": title, "body": body, "labels": ["blastcheck"]}
        if existing:
            result = self._call("PATCH", f"repos/{repo}/issues/{existing['number']}",
                                payload={**payload, "state": "open"}).json()
        else:
            result = self._call("POST", f"repos/{repo}/issues", payload=payload).json()
        return result["html_url"] if isinstance(result, dict) else ""
