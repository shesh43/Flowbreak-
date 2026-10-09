from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from ..har_parser import HttpEntry
from ..replay import ReplayResult, ReplaySession
from ..workflow import WorkflowConfig, RuleResult, extract_state, evaluate_rule, _get_path


@dataclass
class EvidenceStep:
    """One request/response pair captured during a test, for the report."""
    step_name: str
    note: str
    replay: ReplayResult


@dataclass
class TestOutcome:
    technique_id: str
    technique_description: str
    rule_results: list[RuleResult]
    evidence: list[EvidenceStep]
    skipped_reason: Optional[str] = None
    attack_blocked_reason: Optional[str] = None

    @property
    def auth_failed(self) -> bool:
        """True if any replayed request came back 401/403.

        This is the same class of problem as connection_failed: if auth is
        broken (expired/stale token, missing login step, wrong credentials),
        every subsequent request fails for a reason that has nothing to do
        with the business-logic rule being tested, and the resulting
        "it didn't violate the rule" is meaningless, not a clean result -
        the requests never got far enough to test anything.
        """
        return any(e.replay.status in (401, 403) for e in self.evidence)

    @property
    def connection_failed(self) -> bool:
        """True if any replayed request in this test never got a response
        from the target at all (DNS/connection/timeout failure - status 0).

        This must be checked and reported BEFORE looking at `vulnerable`:
        if the target was unreachable, every rule will fail to evaluate
        (missing state) and silently look like "NOT VULNERABLE" - which
        would be a false negative on a security tool. A connection failure
        is a distinct, inconclusive outcome, never a clean result.
        """
        return any(e.replay.error is not None for e in self.evidence)

    @property
    def vulnerable(self) -> bool:
        """True if any rule was violated (passed is False). A rule that could
        not be evaluated (passed is None) is NOT counted as a violation -
        it's reported separately so it isn't mistaken for a confirmed finding.

        If the core attack request was itself rejected by the target
        (attack_blocked_reason set), this is unconditionally False. Without
        this check, a blocked attack can still leave the workflow in some
        incidental downstream state (e.g. an empty cart totalling exactly
        $0) that coincidentally trips an unrelated rule - reporting that as
        a finding would be a false positive attributing a real control's
        correct rejection to a vulnerability that didn't happen.
        """
        if self.attack_blocked_reason or self.auth_failed:
            return False
        return any(r.passed is False for r in self.rule_results)


class MutationTechnique(ABC):
    id: str
    description: str

    def __init__(self, workflow: WorkflowConfig, entries_by_step: dict[str, HttpEntry], session: ReplaySession):
        self.workflow = workflow
        self.entries_by_step = entries_by_step
        self.session = session

    def _replay_step(self, step_name: str, state: dict, note: str, body_overrides: Optional[dict] = None) -> EvidenceStep:
        entry = self.entries_by_step.get(step_name)
        if entry is None:
            raise KeyError(f"workflow has no captured HAR request for step '{step_name}'")
        result = self.session.send(entry, body_overrides=body_overrides)
        result.step_name = step_name
        step_def = self.workflow.step_by_name(step_name)
        if result.response_body is not None:
            extract_state(step_def, result.response_body, state)

        # If this was the login step, pick up the fresh token it just
        # issued and apply it to every request from here on - see
        # AuthConfig's docstring for why this matters.
        auth = self.workflow.auth
        if auth and step_name == auth.login_step and result.response_body is not None:
            token = _get_path(result.response_body, auth.token_path)
            if token:
                self.session.extra_headers[auth.header] = f"{auth.prefix}{token}"

        return EvidenceStep(step_name=step_name, note=note, replay=result)

    def _evaluate_all_rules(self, state: dict) -> list[RuleResult]:
        return [evaluate_rule(rule, state) for rule in self.workflow.rules]

    @abstractmethod
    def run(self) -> TestOutcome:
        ...
