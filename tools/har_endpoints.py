"""
har_endpoints.py

A HAR from a real browsing session (login, browsing, basket, checkout) can
easily have hundreds or thousands of entries - way too many to eyeball to
find the handful of requests that matter for a rules.yaml.

This is pure extraction/summarization - it does NOT guess which endpoints
are "the" workflow steps or what the business rules should be (that's
still your call, by design - see README's "What this is NOT" section).
It just turns an unreadable 20,000-line JSON file into a short list of
unique (method, path) pairs you can actually scan.

Usage:
    python3 tools/har_endpoints.py path/to/capture.har
    python3 tools/har_endpoints.py path/to/capture.har --filter basket,coupon,order
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from flowbreak.har_parser import HarParseError, parse_har  # noqa: E402
from flowbreak._pipe_safety import run_main_safely  # noqa: E402

# Paths containing any of these are almost always noise for a business-logic
# workflow capture - static assets, telemetry, etc.
DEFAULT_NOISE = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".ico",
    ".map", "google-analytics", "doubleclick", "gstatic", "favicon",
)

# Paths/keywords that are usually relevant to a checkout-type workflow -
# used only to sort relevant-looking entries to the top, never to filter
# anything out automatically.
LIKELY_RELEVANT = (
    "basket", "cart", "coupon", "voucher", "checkout", "order", "payment",
    "address", "delivery", "login", "auth",
)


# URL schemes that are never a meaningful "workflow step" request - a real
# browser session's HAR commonly includes these (WebSocket polling frames,
# inlined data: images, browser extensions if any are installed) and they
# just add noise.
NON_HTTP_SCHEMES = {"data", "ws", "wss", "blob", "chrome-extension", "about", "chrome"}


def is_noise(path: str, url: str) -> bool:
    scheme = urlparse(url).scheme.lower()
    if scheme in NON_HTTP_SCHEMES:
        return True
    return any(path.lower().endswith(ext) or ext in path.lower() for ext in DEFAULT_NOISE)


def looks_relevant(path: str) -> bool:
    return any(kw in path.lower() for kw in LIKELY_RELEVANT)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("har", help="Path to the HAR file")
    ap.add_argument("--filter", help="Comma-separated keywords - only show paths containing one of these")
    ap.add_argument("--show-noise", action="store_true", help="Also show static assets (.js/.css/images/etc)")
    ap.add_argument("--sample-body", action="store_true", help="Show one example request AND response body per endpoint, if any")
    args = ap.parse_args()

    try:
        entries = parse_har(args.har)
    except HarParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    keywords = [k.strip().lower() for k in args.filter.split(",")] if args.filter else None

    # group by (method, path) -> count, first non-empty body, first status seen
    groups: dict[tuple[str, str], dict] = defaultdict(lambda: {"count": 0, "statuses": set(), "body": None, "response_body": None})
    for e in entries:
        if not args.show_noise and is_noise(e.path, e.url):
            continue
        if keywords and not any(kw in e.path.lower() for kw in keywords):
            continue
        key = (e.method, e.path)
        g = groups[key]
        g["count"] += 1
        g["statuses"].add(e.status)
        if g["body"] is None and e.request_body is not None:
            g["body"] = e.request_body
        # Prefer a successful (2xx) response as the sample shown, since
        # that's the one whose field names matter for writing `extract:`.
        is_success = 200 <= e.status < 300
        have_success_sample = g.get("_resp_is_success", False)
        if e.response_body is not None and (g["response_body"] is None or (is_success and not have_success_sample)):
            g["response_body"] = e.response_body
            g["_resp_is_success"] = is_success

    if not groups:
        print("No matching requests found. Try --show-noise, or check --filter keywords.", file=sys.stderr)
        return 1

    relevant = sorted(k for k in groups if looks_relevant(k[1]))
    other = sorted(k for k in groups if not looks_relevant(k[1]))

    print(f"{len(entries)} total HAR entries -> {len(groups)} unique endpoints shown\n")

    def _print_group(title: str, keys: list[tuple[str, str]]):
        if not keys:
            return
        print(f"--- {title} ---")
        for method, path in keys:
            g = groups[(method, path)]
            statuses = ",".join(str(s) for s in sorted(g["statuses"]))
            count_note = f" (x{g['count']})" if g["count"] > 1 else ""
            display_path = path if path else "(empty/unparseable path - malformed or non-HTTP entry)"
            aborted_note = " [ABORTED/no response]" if g["statuses"] == {0} else ""
            print(f"  {method:6s} {display_path}  [{statuses}]{count_note}{aborted_note}")
            if args.sample_body and g["body"] is not None:
                body_str = json.dumps(g["body"])
                if len(body_str) > 150:
                    body_str = body_str[:150] + "..."
                print(f"         request body:  {body_str}")
            if args.sample_body and g["response_body"] is not None:
                resp_str = json.dumps(g["response_body"])
                if len(resp_str) > 250:
                    resp_str = resp_str[:250] + "..."
                print(f"         response body: {resp_str}")
        print()

    _print_group("Likely relevant to a checkout/business-logic workflow", relevant)
    _print_group("Other endpoints", other)

    print(
        "Tip: pick the method+path for each workflow step, use it as "
        "match.path_contains in your rules YAML. Use --sample-body to see "
        "an example request body for picking extract/field_path values."
    )
    return 0


if __name__ == "__main__":
    sys.exit(run_main_safely(main))
