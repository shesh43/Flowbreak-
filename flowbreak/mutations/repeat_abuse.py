from __future__ import annotations

from .base import MutationTechnique, TestOutcome


class RepeatAbuseMutation(MutationTechnique):
    """Replays the full workflow up to and including a target step, then
    replays that one step N additional times (e.g. re-applying a coupon
    that should only be usable once) and checks whether the server-side
    state (redemption count, balance, etc) still obeys the rule.
    """

    id = "repeat_abuse"

    def __init__(self, *args, target_step: str, repeat_count: int = 3, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_step = target_step
        self.repeat_count = repeat_count
        self.description = f"Replay step '{target_step}' {repeat_count}x beyond normal flow"

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

        # Run the workflow normally once, up to and including the target step.
        for step in self.workflow.steps:
            evidence.append(self._replay_step(step.name, state, "normal replay"))
            if step.name == self.target_step:
                break

        # Then hammer the target step extra times - this is the actual attack.
        for i in range(self.repeat_count):
            evidence.append(
                self._replay_step(self.target_step, state, f"repeat attempt #{i + 1} (abuse)")
            )

        rule_results = self._evaluate_all_rules(state)
        return TestOutcome(
            technique_id=self.id,
            technique_description=self.description,
            rule_results=rule_results,
            evidence=evidence,
        )
