from __future__ import annotations

from typing import Any

from .base import MutationTechnique, TestOutcome


class FieldTamperMutation(MutationTechnique):
    """Replays the workflow normally up to a target step, then replays that
    step again with one request-body field overridden to an attacker-chosen
    value (e.g. quantity: -1, price: 0) and checks whether the server
    re-validates it server-side.
    """

    id = "field_tamper"

    def __init__(self, *args, target_step: str, field_path: str, tamper_value: Any, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_step = target_step
        self.field_path = field_path
        self.tamper_value = tamper_value
        self.description = (
            f"Replay step '{target_step}' with {field_path} tampered to {tamper_value!r}"
        )

    def run(self) -> TestOutcome:
        state: dict = {}
        evidence = []

        if self.target_step not in self.entries_by_step:
            return TestOutcome(
                technique_id=self.id,
                technique_description=self.description,
                rule_results=[],
                evidence=[],
                skipped_reason=f"no captured request for step '{self.target_step}'",
            )

        attack_blocked_reason = None

        for step in self.workflow.steps:
            if step.name == self.target_step:
                entry = self.entries_by_step[step.name]
                result = self.session.send(entry, body_overrides={self.field_path: self.tamper_value})
                result.step_name = step.name
                if result.response_body is not None:
                    from ..workflow import extract_state
                    extract_state(step, result.response_body, state)
                from .base import EvidenceStep
                evidence.append(EvidenceStep(step_name=step.name, note="tampered request", replay=result))

                # The server rejected the tampered value outright (4xx/5xx).
                # Stop here: continuing the workflow would run the REST of
                # the steps on whatever incidental state the rejection left
                # behind, and any rule result from that point on would be
                # describing normal/unrelated behavior, not the tamper -
                # misattributing it as a finding would be a false positive.
                if result.status == 0 or result.status >= 400:
                    attack_blocked_reason = (
                        f"server rejected the tampered request with status {result.status} "
                        f"({result.error or 'validation error'}) - field appears to be re-validated server-side"
                    )
                    break
            else:
                evidence.append(self._replay_step(step.name, state, "normal replay"))

        rule_results = self._evaluate_all_rules(state) if attack_blocked_reason is None else []
        return TestOutcome(
            technique_id=self.id,
            technique_description=self.description,
            rule_results=rule_results,
            evidence=evidence,
            attack_blocked_reason=attack_blocked_reason,
        )
