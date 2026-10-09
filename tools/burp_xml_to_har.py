"""
burp_xml_to_har.py

Burp Suite has no built-in HAR export - its native export (Proxy > HTTP
history > select items > right-click > "Save items as XML") produces its
own XML format instead, with each request/response pair stored as raw,
base64-encoded HTTP messages.

This converts that XML into standard HAR JSON, so FlowBreak's existing
HAR tooling (har_parser.py, tools/har_endpoints.py, the CLI itself) works
on a Burp capture completely unchanged - no separate code path needed.

Usage:
    python3 tools/burp_xml_to_har.py burp_export.xml -o capture.har
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from flowbreak._pipe_safety import run_main_safely  # noqa: E402


def _decode_raw(elem: ET.Element | None) -> bytes:
    if elem is None or elem.text is None:
        return b""
    is_b64 = (elem.get("base64") or "false").lower() == "true"
    if is_b64:
        try:
            return base64.b64decode(elem.text)
        except Exception:
            return b""
    return elem.text.encode("utf-8", errors="replace")


def _parse_http_message(raw: bytes) -> tuple[str, list[dict], str]:
    """Split a raw HTTP message (as Burp stores it) into (start_line, headers, body)."""
    if not raw:
        return "", [], ""
    text = raw.decode("utf-8", errors="replace")
    if "\r\n\r\n" in text:
        head, _, body = text.partition("\r\n\r\n")
    elif "\n\n" in text:
        head, _, body = text.partition("\n\n")
    else:
        head, body = text, ""

    lines = head.split("\r\n") if "\r\n" in head else head.split("\n")
    lines = [l for l in lines if l != ""]
    if not lines:
        return "", [], body

    start_line = lines[0]
    headers = []
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            headers.append({"name": name.strip(), "value": value.strip()})
    return start_line, headers, body


def _header_value(headers: list[dict], name: str) -> str | None:
    name = name.lower()
    for h in headers:
        if h["name"].lower() == name:
            return h["value"]
    return None


def _convert_item(item: ET.Element, index: int) -> dict | None:
    url_elem = item.find("url")
    url = (url_elem.text or "").strip() if url_elem is not None else ""
    if not url:
        return None  # nothing usable without a URL

    method_elem = item.find("method")
    method = (method_elem.text or "GET").strip() if method_elem is not None else "GET"

    req_raw = _decode_raw(item.find("request"))
    _, req_headers, req_body = _parse_http_message(req_raw)

    res_raw = _decode_raw(item.find("response"))
    res_start, res_headers, res_body = _parse_http_message(res_raw)

    status_elem = item.find("status")
    status = 0
    if status_elem is not None and status_elem.text and status_elem.text.strip().isdigit():
        status = int(status_elem.text.strip())
    elif res_start:
        # fall back to parsing "HTTP/1.1 200 OK" if the <status> tag is absent
        parts = res_start.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])

    time_elem = item.find("time")
    started = time_elem.text.strip() if time_elem is not None and time_elem.text else None
    if not started:
        started = datetime.now(timezone.utc).isoformat()

    mimetype_elem = item.find("mimetype")
    response_mime = (mimetype_elem.text or "").strip() if mimetype_elem is not None else ""
    if not response_mime:
        response_mime = _header_value(res_headers, "Content-Type") or "application/octet-stream"

    post_data = None
    if req_body:
        content_type = _header_value(req_headers, "Content-Type") or "application/octet-stream"
        post_data = {"mimeType": content_type, "text": req_body}

    return {
        "startedDateTime": started,
        "request": {
            "method": method,
            "url": url,
            "headers": req_headers,
            "postData": post_data,
        },
        "response": {
            "status": status,
            "headers": res_headers,
            "content": {"text": res_body, "mimeType": response_mime},
        },
    }


def convert(xml_path: str) -> dict:
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        raise ValueError(f"{xml_path} is not valid XML: {e}") from e
    except FileNotFoundError as e:
        raise ValueError(f"file not found: {xml_path}") from e

    root = tree.getroot()
    items = root.findall("item")
    if not items:
        raise ValueError(f"{xml_path} has no <item> elements - is this a Burp 'Save items as XML' export?")

    entries = []
    skipped = 0
    for i, item in enumerate(items):
        try:
            converted = _convert_item(item, i)
        except Exception:
            converted = None
        if converted is None:
            skipped += 1
            continue
        entries.append(converted)

    if skipped:
        print(f"warning: skipped {skipped} item(s) that couldn't be converted out of {len(items)}", file=sys.stderr)

    if not entries:
        raise ValueError(f"no usable entries converted from {xml_path}")

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "burp_xml_to_har", "version": "1"},
            "entries": entries,
        }
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("xml_file", help="Burp 'Save items as XML' export")
    ap.add_argument("-o", "--out", default=None, help="Output HAR path (default: same name, .har extension)")
    args = ap.parse_args()

    out_path = args.out or str(Path(args.xml_file).with_suffix(".har"))

    try:
        har = convert(args.xml_file)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(har, f, indent=2)

    print(f"wrote {out_path} with {len(har['log']['entries'])} entries")
    return 0


if __name__ == "__main__":
    sys.exit(run_main_safely(main))
