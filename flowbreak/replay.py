"""
replay.py

Takes a captured HttpEntry (from har_parser) and actually sends it against a
live target, optionally with specific fields overridden (that's how mutation
techniques tamper with price/quantity/coupon code, etc).

One requests.Session is reused across a whole test so cookies/auth set by
earlier steps (e.g. a session cookie from login) carry forward naturally,
the same way a real browser session would behave.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests

from .har_parser import HttpEntry


@dataclass
class ReplayResult:
    step_name: str
    request_method: str
    request_url: str
    request_headers: dict[str, str]
    request_body: Optional[Any]
    status: int
    response_headers: dict[str, str]
    response_body: Optional[Any]
    error: Optional[str] = None


def _rebase_url(original_url: str, base_url: Optional[str]) -> str:
    if not base_url:
        return original_url
    parsed = urlparse(original_url)
    path_and_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    return urljoin(base_url if base_url.endswith("/") else base_url + "/", path_and_query.lstrip("/"))


def _set_dotted(obj: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = obj
    for p in parts[:-1]:
        if not isinstance(cur.get(p), dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


# Headers that are specific to the exact browser session the HAR was captured
# from and must NOT be blindly replayed byte-for-byte on every request:
#   - host/content-length/connection: requests recalculates these itself
#   - if-none-match/if-modified-since: stale values can trigger unexpected 304s
#   - cookie: CRITICAL. If we resend the HAR's captured Cookie header on every
#     replayed request, we freeze the session to its state at capture time -
#     every "repeat" or "race" attempt would be evaluated against that same
#     frozen snapshot instead of the live session this replay is building up,
#     silently hiding real vulnerabilities (e.g. a coupon-reuse count that
#     never appears to increase because each request re-reads the original
#     capture-time cart). Cookie-based session state must be allowed to
#     evolve naturally via the live requests.Session()'s cookie jar, exactly
#     as it would in a real browser working through the same flow.
_DROP_HEADERS = {"host", "content-length", "if-none-match", "if-modified-since", "connection", "cookie"}


class ReplaySession:
    def __init__(self, base_url: Optional[str] = None, timeout: float = 10.0, extra_headers: Optional[dict] = None):
        self.session = requests.Session()
        self.base_url = base_url
        self.timeout = timeout
        self.extra_headers = extra_headers or {}

    def send(self, entry: HttpEntry, body_overrides: Optional[dict] = None, skip_ssl_verify: bool = False) -> ReplayResult:
        req = entry.clone_request()
        req["url"] = _rebase_url(req["url"], self.base_url)

        headers = {k: v for k, v in req["headers"].items() if k.lower() not in _DROP_HEADERS}
        headers.update(self.extra_headers)

        body = req["json"]
        if body_overrides and isinstance(body, dict):
            body = copy.deepcopy(body)
            for dotted_key, value in body_overrides.items():
                _set_dotted(body, dotted_key, value)

        try:
            resp = self.session.request(
                method=req["method"],
                url=req["url"],
                headers=headers,
                json=body if body is not None else None,
                data=req["data"] if body is None else None,
                timeout=self.timeout,
                verify=not skip_ssl_verify,
            )
        except requests.RequestException as e:
            return ReplayResult(
                step_name="",
                request_method=req["method"],
                request_url=req["url"],
                request_headers=headers,
                request_body=body,
                status=0,
                response_headers={},
                response_body=None,
                error=str(e),
            )

        try:
            response_body = resp.json()
        except ValueError:
            response_body = resp.text

        return ReplayResult(
            step_name="",
            request_method=req["method"],
            request_url=req["url"],
            request_headers=headers,
            request_body=body,
            status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=response_body,
        )
