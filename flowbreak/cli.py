"""
cli.py

    flowbreak run --har checkout.har --rules rules/checkout.yaml \
                   --target http://localhost:3000 \
                   --out results

Runs the configured mutation techniques for a workflow (read from the rules
YAML's `techniques:` section) against a target, using requests captured in
a HAR file as the template, and writes JSON + Markdown evidence.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import map_steps_to_har
from .evidence import to_json, to_markdown
from .har_parser import HarParseError, parse_har
from .mutations import FieldTamperMutation, RepeatAbuseMutation, StepSkipMutation
from .replay import ReplaySession
from .workflow import WorkflowConfigError, load_workflow
from ._pipe_safety import run_main_safely

TECHNIQUE_BUILDERS = {
    "step_skip": lambda cfg, workflow, mapping, session: StepSkipMutation(
        workflow, mapping, session, skip_step=cfg["skip_step"]
    ),
    "repeat_abuse": lambda cfg, workflow, mapping, session: RepeatAbuseMutation(
        workflow, mapping, session, target_step=cfg["target_step"], repeat_count=cfg.get("repeat_count", 3)
    ),
    "field_tamper": lambda cfg, workflow, mapping, session: FieldTamperMutation(
        workflow, mapping, session, target_step=cfg["target_step"],
        field_path=cfg["field_path"], tamper_value=cfg["tamper_value"]
    ),
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="flowbreak",
        description="Business-logic security testing engine for web/API workflows.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run configured techniques against a workflow")
    run.add_argument("--har", required=True, help="Path to a HAR file capturing the workflow")
    run.add_argument("--rules", required=True, help="Path to the workflow/rules YAML file")
    run.add_argument("--target", default=None, help="Base URL to replay against (overrides base_url in the YAML)")
    run.add_argument("--out", default="flowbreak_results", help="Output file prefix (writes .json and .md)")
    run.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds")
    run.add_argument(
        "--header", action="append", default=[], metavar="Name: Value",
        help="Extra header to send on every replayed request (repeatable)",
    )

    return p


def _parse_extra_headers(raw: list[str]) -> dict[str, str]:
    headers = {}
    for item in raw:
        if ":" not in item:
            print(f"warning: ignoring malformed --header '{item}' (expected 'Name: Value')", file=sys.stderr)
            continue
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def cmd_run(args: argparse.Namespace) -> int:
    try:
        entries = parse_har(args.har)
    except HarParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    try:
        workflow = load_workflow(args.rules)
    except WorkflowConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if not workflow.techniques:
        print(f"error: {args.rules} has no 'techniques:' section (or it's empty) - nothing to run", file=sys.stderr)
        return 2

    base_url = args.target or workflow.base_url
    if not base_url:
        print("error: no target base URL given (use --target or set base_url in the YAML)", file=sys.stderr)
        return 2

    mapping = map_steps_to_har(workflow, entries)
    if not mapping:
        print("error: none of the workflow's steps matched any request in the HAR file", file=sys.stderr)
        print("  check the 'match.method' / 'match.path_contains' values against your HAR", file=sys.stderr)
        return 2

    missing = [s.name for s in workflow.steps if s.name not in mapping]
    if missing:
        print(f"warning: no HAR match for step(s): {', '.join(missing)} - affected techniques will be skipped", file=sys.stderr)

    # Validate and prepare the output location BEFORE running anything
    # against the target. Failing here after techniques have already fired
    # live requests would lose that evidence - check this while it's cheap
    # to fail fast instead.
    json_path = Path(f"{args.out}.json")
    md_path = Path(f"{args.out}.md")
    try:
        json_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"error: can't create output directory '{json_path.parent}': {e}", file=sys.stderr)
        return 2
    for p in (json_path, md_path):
        try:
            p.touch(exist_ok=True)
        except OSError as e:
            print(f"error: can't write to '{p}': {e}", file=sys.stderr)
            return 2

    extra_headers = _parse_extra_headers(args.header)

    outcomes = []
    for t_cfg in workflow.techniques:
        kind = t_cfg.get("type")
        builder = TECHNIQUE_BUILDERS.get(kind)
        if builder is None:
            print(f"error: unknown technique type '{kind}' in {args.rules}", file=sys.stderr)
            return 2
        session = ReplaySession(base_url=base_url, timeout=args.timeout, extra_headers=extra_headers)
        try:
            technique = builder(t_cfg, workflow, mapping, session)
        except KeyError as e:
            print(f"error: technique '{kind}' in {args.rules} is missing required field {e}", file=sys.stderr)
            return 2
        except (TypeError, ValueError) as e:
            print(f"error: technique '{kind}' in {args.rules} has an invalid config: {e}", file=sys.stderr)
            return 2
        print(f"-> running {technique.id}: {technique.description}", file=sys.stderr)
        outcomes.append(technique.run())

    json_path.write_text(to_json(workflow.name, outcomes), encoding="utf-8")
    md_path.write_text(to_markdown(workflow.name, outcomes), encoding="utf-8")

    vulnerable = [
        o for o in outcomes
        if o.skipped_reason is None and not o.connection_failed and not o.auth_failed and o.vulnerable
    ]
    inconclusive = [
        o for o in outcomes
        if o.skipped_reason is None and (o.connection_failed or o.auth_failed)
    ]

    print(f"\n{len(vulnerable)} of {len(outcomes)} techniques found a rule violation.", file=sys.stderr)
    for o in vulnerable:
        print(f"  VULNERABLE: {o.technique_id} - {o.technique_description}", file=sys.stderr)
    if inconclusive:
        print(f"\nWARNING: {len(inconclusive)} technique(s) are INCONCLUSIVE, not a clean result:", file=sys.stderr)
        for o in inconclusive:
            reason = "connection failed" if o.connection_failed else "401/403 - auth failed (check your 'auth:' config)"
            print(f"  INCONCLUSIVE ({reason}): {o.technique_id} - {o.technique_description}", file=sys.stderr)
    print(f"\nWrote {json_path} and {md_path}", file=sys.stderr)

    return 3 if inconclusive else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return cmd_run(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(run_main_safely(main))
