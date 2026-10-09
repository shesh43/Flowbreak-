"""
har_parser.py

Parses a HAR (HTTP Archive) file - the JSON export you get from Chrome/Firefox
DevTools (Network tab -> right click -> "Save all as HAR") or from Burp Suite's
HAR export - into an ordered list of HttpEntry objects FlowBreak can work with.

A HAR file is just JSON. No special library needed to read it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse, parse_qsl


class HarParseError(Exception):
    """Raised when a HAR file is missing required structure."""


@dataclass
class HttpEntry:
    """A single captured request/response pair, in a normalized form."""

    index: int                     # original order in the HAR, 0-based
    method: str
    url: str
    path: str                      # url path only, e.g. /rest/basket/1/coupon/ABC
    query: dict[str, str]
    request_headers: dict[str, str]
    request_body: Optional[Any]    # parsed JSON if possible, else raw string, else None
    request_body_raw: Optional[str]
    status: int
    response_headers: dict[str, str]
    response_body: Optional[Any]   # parsed JSON if possible, else raw string, else None
    response_body_raw: Optional[str]
    started_at: Optional[str] = None

    def clone_request(self) -> dict:
        """Return a mutable copy of the fields needed to replay this request."""
        return {
            "method": self.method,
            "url": self.url,
            "headers": dict(self.request_headers),
            "json": json.loads(json.dumps(self.request_body)) if isinstance(self.request_body, (dict, list)) else None,
            "data": self.request_body_raw if not isinstance(self.request_body, (dict, list)) else None,
        }


def _headers_to_dict(headers: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for h in headers or []:
        name = h.get("name", "")
        if name.lower() in ("cookie",):
            # Keep cookie as-is; requests handles a raw Cookie header fine.
            out[name] = h.get("value", "")
            continue
        # Skip pseudo-headers some exports include (e.g. ":method")
        if name.startswith(":"):
            continue
        out[name] = h.get("value", "")
    return out


def _try_parse_json(text: Optional[str]) -> Optional[Any]:
    if text is None or text == "":
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def parse_har(path: str) -> list[HttpEntry]:
    """Load a HAR file and return its entries in chronological order."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as e:
        raise HarParseError(f"HAR file not found: {path}") from e
    except PermissionError as e:
        raise HarParseError(f"permission denied reading HAR file: {path}") from e
    except json.JSONDecodeError as e:
        raise HarParseError(f"{path} is not valid JSON: {e}") from e

    try:
        raw_entries = data["log"]["entries"]
    except (KeyError, TypeError) as e:
        raise HarParseError(f"{path} does not look like a HAR file (missing log.entries)") from e

    entries: list[HttpEntry] = []
    skipped = 0
    for i, e in enumerate(raw_entries):
        # A real multi-thousand-entry capture from a live browser session can
        # contain genuinely unpredictable edge cases beyond what's been
        # explicitly tested (a future browser quirk, a non-conformant proxy
        # export, etc). One bad entry must not take down the parse of the
        # other several thousand good ones - skip it and keep going.
        try:
            entries.append(_parse_single_entry(i, e))
        except Exception:  # noqa: BLE001 - deliberately broad; see comment above
            skipped += 1

    if skipped:
        import sys
        print(f"warning: skipped {skipped} malformed HAR entr{'y' if skipped == 1 else 'ies'} out of {len(raw_entries)}", file=sys.stderr)

    if not entries:
        raise HarParseError(f"{path} contains zero usable entries ({skipped} were skipped as malformed)" if skipped else f"{path} contains zero entries")

    return entries


def _parse_single_entry(index: int, e: dict) -> HttpEntry:
    req = e.get("request") or {}
    res = e.get("response") or {}

    url = req.get("url") or ""
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))

    req_post = req.get("postData") or {}
    req_body_raw = req_post.get("text")
    req_body_parsed = _try_parse_json(req_body_raw)

    res_content = res.get("content") or {}
    res_body_raw = res_content.get("text")
    # HAR sometimes base64-encodes response text; we only handle plain text/JSON here.
    if res_content.get("encoding") == "base64" and res_body_raw:
        import base64
        try:
            res_body_raw = base64.b64decode(res_body_raw).decode("utf-8", errors="replace")
        except Exception:
            pass
    res_body_parsed = _try_parse_json(res_body_raw)

    return HttpEntry(
        index=index,
        method=(req.get("method") or "GET").upper(),
        url=url,
        path=parsed.path,
        query=query,
        request_headers=_headers_to_dict(req.get("headers") or []),
        request_body=req_body_parsed,
        request_body_raw=req_body_raw,
        status=res.get("status") or 0,
        response_headers=_headers_to_dict(res.get("headers") or []),
        response_body=res_body_parsed,
        response_body_raw=res_body_raw,
        started_at=e.get("startedDateTime"),
    )


def match_step(entries: list[HttpEntry], method: str, path_contains: str) -> list[HttpEntry]:
    """Return entries whose method matches and whose path contains a substring.

    This is the (deliberately simple) way a workflow YAML identifies which
    captured HAR request corresponds to a named step like "apply_coupon".
    """
    method = method.upper()
    return [
        e for e in entries
        if e.method == method and path_contains in e.path
    ]
