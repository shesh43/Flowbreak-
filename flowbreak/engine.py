"""
engine.py

Maps each workflow step (from the YAML) to the captured request in the HAR
that corresponds to it. This mapping is the one thing every mutation
technique needs, so it's computed once, here, and handed to each technique.
"""

from __future__ import annotations

from .har_parser import HttpEntry, match_step
from .workflow import WorkflowConfig


def map_steps_to_har(workflow: WorkflowConfig, entries: list[HttpEntry]) -> dict[str, HttpEntry]:
    """For each step in the workflow, find the matching HAR request.

    Uses the FIRST match in chronological order - if a step appears more
    than once in the HAR (e.g. the tester clicked "apply coupon" twice while
    capturing), only the first is used as the template for replay.

    Steps with no match are simply left out of the mapping; mutation
    techniques report that explicitly (skipped_reason) rather than crashing.
    """
    mapping: dict[str, HttpEntry] = {}
    for step in workflow.steps:
        matches = match_step(entries, step.method, step.path_contains)
        if matches:
            mapping[step.name] = matches[0]
    return mapping
