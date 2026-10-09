"""
generate_demo_har.py

Performs one legitimate checkout flow against the mock server and records
it as a real HAR file - the same format you'd get from Chrome DevTools.
This is only needed for the demo/test; against a real target (Juice Shop
or otherwise) you'd capture the HAR from your actual browser session.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import requests

BASE = "http://localhost:8099"


def _har_entry(resp: requests.Response, started: str) -> dict:
    req = resp.request
    req_headers = [{"name": k, "value": v} for k, v in req.headers.items()]
    res_headers = [{"name": k, "value": v} for k, v in resp.headers.items()]
    post_data = None
    if req.body:
        body_text = req.body if isinstance(req.body, str) else req.body.decode("utf-8")
        post_data = {"mimeType": "application/json", "text": body_text}

    return {
        "startedDateTime": started,
        "request": {
            "method": req.method,
            "url": req.url,
            "headers": req_headers,
            "postData": post_data,
        },
        "response": {
            "status": resp.status_code,
            "headers": res_headers,
            "content": {"text": resp.text, "mimeType": "application/json"},
        },
    }


def main():
    session = requests.Session()
    entries = []

    steps = [
        ("POST", "/cart/add", {"product_id": 1, "quantity": 2}),
        ("POST", "/cart/coupon", {"code": "SAVE5"}),
        ("POST", "/payment/confirm", {}),
        ("POST", "/checkout", {}),
    ]

    for method, path, body in steps:
        started = datetime.now(timezone.utc).isoformat()
        resp = session.request(method, BASE + path, json=body)
        resp.raise_for_status()
        entries.append(_har_entry(resp, started))

    har = {"log": {"version": "1.2", "creator": {"name": "flowbreak-demo", "version": "1"}, "entries": entries}}

    with open("tests/checkout.har", "w", encoding="utf-8") as f:
        json.dump(har, f, indent=2)

    print(f"wrote tests/checkout.har with {len(entries)} entries")


if __name__ == "__main__":
    main()
