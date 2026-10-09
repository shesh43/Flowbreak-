"""
evidence.py

FlowBreak deliberately does NOT generate a polished "pentest report" -
that's a separate, much bigger problem (and an easy place to overclaim).
What it does produce: structured, reproducible evidence per test - the
exact request/response pairs that proved (or disproved) a rule violation -
in JSON (for tooling) and Markdown (for a human to read quickly).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from .mutations.base import TestOutcome


def to_json(workflow_name: str, outcomes: list[TestOutcome]) -> str:
    payload = {
        "tool": "FlowBreak",
        "workflow": workflow_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tests": [_outcome_to_dict(o) for o in outcomes],
    }
    return json.dumps(payload, indent=2, default=str)


def _status(o: TestOutcome) -> str:
    if o.skipped_reason:
        return "SKIPPED"
    if o.connection_failed:
        return "INCONCLUSIVE"  # target unreachable - never report as clean
    if o.auth_failed:
        return "INCONCLUSIVE"  # 401/403 - auth broke, never report as clean
    if o.attack_blocked_reason:
        return "NOT_VULNERABLE"  # attack rejected server-side - a clean, confirmed result
    return "VULNERABLE" if o.vulnerable else "NOT_VULNERABLE"


def _outcome_to_dict(o: TestOutcome) -> dict[str, Any]:
    return {
        "technique_id": o.technique_id,
        "description": o.technique_description,
        "status": _status(o),
        "skipped_reason": o.skipped_reason,
        "attack_blocked_reason": o.attack_blocked_reason,
        "vulnerable": o.vulnerable if (o.skipped_reason is None and not o.connection_failed) else None,
        "rules": [
            {
                "id": r.rule.id,
                "assert": r.rule.assert_expr,
                "result": "VIOLATED" if r.passed is False else ("HELD" if r.passed is True else "COULD_NOT_EVALUATE"),
                "error": r.error,
            }
            for r in o.rule_results
        ],
        "evidence": [
            {
                "step": e.step_name,
                "note": e.note,
                "request": {
                    "method": e.replay.request_method,
                    "url": e.replay.request_url,
                    "body": e.replay.request_body,
                },
                "response": {
                    "status": e.replay.status,
                    "body": e.replay.response_body,
                    "error": e.replay.error,
                },
            }
            for e in o.evidence
        ],
    }


def to_markdown(workflow_name: str, outcomes: list[TestOutcome]) -> str:
    lines = [f"# FlowBreak Results - {workflow_name}", ""]
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")

    vulnerable_count = sum(1 for o in outcomes if _status(o) == "VULNERABLE")
    inconclusive_count = sum(1 for o in outcomes if _status(o) == "INCONCLUSIVE")
    lines.append(f"**{vulnerable_count} of {len(outcomes)} techniques found a rule violation.**")
    if inconclusive_count:
        lines.append(
            f"**WARNING: {inconclusive_count} technique(s) could not reach the target at all "
            f"and are INCONCLUSIVE, not clean - see below.**"
        )
    lines.append("")

    for o in outcomes:
        status = _status(o)
        display_status = "NOT VULNERABLE" if status == "NOT_VULNERABLE" else status
        lines.append(f"## [{display_status}] {o.technique_id} - {o.technique_description}")
        lines.append("")

        if o.skipped_reason:
            lines.append(f"_Skipped: {o.skipped_reason}_")
            lines.append("")
            continue

        if o.connection_failed:
            lines.append(
                "_Could not reach the target - connection failed on at least one request. "
                "This result is inconclusive, not a clean pass. Check the target is running "
                "and reachable, then re-run. See evidence below for the connection error(s)._"
            )
            lines.append("")

        if o.attack_blocked_reason:
            lines.append(f"_Attack blocked: {o.attack_blocked_reason}._")
            lines.append("")

        if o.auth_failed and not o.connection_failed:
            lines.append(
                "_At least one request got 401/403 Unauthorized. This result is "
                "inconclusive, not a clean pass - check your `auth:` config in the "
                "rules YAML (or that your credentials/session are still valid) and "
                "re-run. See evidence below for which request failed._"
            )
            lines.append("")

        for r in o.rule_results:
            if r.passed is False:
                mark = "VIOLATED"
            elif r.passed is True:
                mark = "held"
            else:
                mark = f"could not evaluate ({r.error})"
            lines.append(f"- Rule `{r.rule.id}` (`{r.rule.assert_expr}`): **{mark}**")
        lines.append("")

        lines.append("<details><summary>Evidence (request/response chain)</summary>")
        lines.append("")
        for e in o.evidence:
            lines.append(f"**{e.step_name}** — {e.note}")
            lines.append("")
            lines.append("```")
            lines.append(f"{e.replay.request_method} {e.replay.request_url}")
            if e.replay.request_body is not None:
                lines.append(json.dumps(e.replay.request_body, indent=2))
            lines.append("")
            lines.append(f"-> {e.replay.status}")
            if e.replay.response_body is not None:
                lines.append(json.dumps(e.replay.response_body, indent=2)[:2000])
            if e.replay.error:
                lines.append(f"ERROR: {e.replay.error}")
            lines.append("```")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines)
