from __future__ import annotations

from .base import MutationTechnique, TestOutcome


class StepSkipMutation(MutationTechnique):
    """Replays the workflow's steps in order, omitting one named step, then
    checks whether the workflow's rules still hold.

    Example: skip "payment_confirm" and see if the server still lets the
    order reach a "complete" state anyway.
    """

    id = "step_skip"

    def __init__(self, *args, skip_step: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.skip_step = skip_step
        self.description = f"Replay workflow with step '{skip_step}' omitted"

    def run(self) -> TestOutcome:
        state: dict = {}
        evidence = []

        if self.skip_step not in self.entries_by_step:
            return TestOutcome(
                technique_id=self.id,
                technique_description=self.description,
                rule_results=[],
                evidence=[],
                skipped_reason=f"no captured request for step '{self.skip_step}'",
            )

        for step in self.workflow.steps:
            if step.name == self.skip_step:
                continue  # the whole point of this technique
            note = "normal replay" if step.name != self.workflow.steps[-1].name else "final step after skip"
            evidence.append(self._replay_step(step.name, state, note))

        rule_results = self._evaluate_all_rules(state)
        return TestOutcome(
            technique_id=self.id,
            technique_description=self.description,
            rule_results=rule_results,
            evidence=evidence,
        )
