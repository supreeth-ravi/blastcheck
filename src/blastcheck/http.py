"""A tiny JSON-over-HTTPS helper on the standard library, with retries.

Safety rules: https only, redirects are followed only to the same host over https (so an
Authorization header is never forwarded elsewhere), and responses are size-capped.
"""
from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

USER_AGENT = "blastcheck"
RETRY_STATUSES = frozenset({500, 502, 503, 504})
MAX_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> object:
        return json.loads(self.body) if self.body else None


class HttpError(Exception):
    def __init__(self, status: int, url: str, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(f"HTTP {status} for {url}: {message}")
        self.status = status
        self.url = url
        self.message = message
        self.headers = headers or {}


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, D102
        old, new = urlsplit(req.full_url), urlsplit(newurl)
        if new.scheme != "https" or new.hostname != old.hostname:
            raise urllib.error.HTTPError(req.full_url, code, f"refused redirect to {new.scheme}://{new.hostname}",
                                         headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SameHostRedirects)


def _open(req: urllib.request.Request, timeout: float):  # noqa: ANN202 - seam for tests
    return _OPENER.open(req, timeout=timeout)


def request(method: str, url: str, headers: dict[str, str] | None = None, payload: object = None,
            timeout: float = 60.0, attempts: int = 3, max_bytes: int = MAX_BYTES) -> Response:
    """Send one request. Raises HttpError on a 4xx/5xx, or on a network failure (status 0)."""
    if not url.startswith("https://"):
        raise HttpError(0, url, "only https URLs are allowed")
    data = json.dumps(payload).encode() if payload is not None else None
    all_headers = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
    if data is not None:
        all_headers.setdefault("Content-Type", "application/json")

    last: HttpError | None = None
    for attempt in range(attempts):
        req = urllib.request.Request(url, data=data, headers=all_headers, method=method)
        try:
            with _open(req, timeout) as raw:
                body = raw.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise HttpError(0, url, f"response larger than {max_bytes} bytes")
                response_headers = {k.lower(): v for k, v in raw.headers.items()}
                expected = response_headers.get("content-length", "")
                if expected.isdigit() and len(body) < int(expected):
                    raise http.client.IncompleteRead(body)  # connection dropped mid-response: retry
                return Response(raw.status, response_headers, body)
        except urllib.error.HTTPError as exc:
            headers_lower = {k.lower(): v for k, v in (exc.headers or {}).items()}
            detail = exc.read().decode(errors="replace")[:300] if exc.fp else str(exc.reason)
            last = HttpError(exc.code, url, detail, headers_lower)
            if exc.code not in RETRY_STATUSES:
                raise last from exc
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
            last = HttpError(0, url, f"{type(exc).__name__}: {str(exc)[:120]}")
        time.sleep(1.5 * (attempt + 1))
    assert last is not None
    raise last
