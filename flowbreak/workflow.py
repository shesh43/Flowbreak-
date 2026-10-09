"""
workflow.py

Loads a workflow definition (YAML): which HAR requests correspond to which
named steps, what values to extract from responses into a "state" dict, and
what rules (assertions) must hold true over that state.

Rules are plain boolean expressions over the extracted state, e.g.:
    coupon.redeemed_count <= 1
    order.status != "complete" or payment.confirmed == true

Evaluated with `simpleeval`, NOT Python's eval() - simpleeval has no access
to builtins, imports, or attribute/dunder traversal, so a malicious or
malformed rule file can't execute arbitrary code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import yaml
from simpleeval import EvalWithCompoundTypes, NameNotDefined


class WorkflowConfigError(Exception):
    pass


@dataclass
class StepDef:
    name: str
    method: str
    path_contains: str
    # dotted-state-key -> JSON path in the response body, e.g.
    #   "coupon.redeemed_count": "data.coupon.uses"
    extract: dict[str, str] = field(default_factory=dict)


@dataclass
class RuleDef:
    id: str
    assert_expr: str
    description: Optional[str] = None


@dataclass
class AuthConfig:
    """Describes how to pick up a fresh auth credential issued during the
    replay itself (e.g. a JWT from a login step) and apply it to every
    request that follows - instead of each step blindly replaying its own
    frozen Authorization header from the original HAR capture.

    Without this, a token-based app (JWT Bearer auth, common in SPAs/REST
    APIs - as opposed to cookie-session auth) would have every step after
    login silently using whatever token happened to be captured in THAT
    step's own HAR entry, which is almost always stale/expired by the time
    you replay it, rather than the fresh token the live login step itself
    just returned.
    """
    login_step: str
    token_path: str            # dotted path into the login response body
    header: str = "Authorization"
    prefix: str = "Bearer "


@dataclass
class WorkflowConfig:
    name: str
    base_url: Optional[str]
    steps: list[StepDef]
    rules: list[RuleDef]
    techniques: list[dict] = field(default_factory=list)
    auth: Optional[AuthConfig] = None

    def step_by_name(self, name: str) -> StepDef:
        for s in self.steps:
            if s.name == name:
                return s
        raise WorkflowConfigError(f"no step named '{name}' in workflow '{self.name}'")


def load_workflow(path: str) -> WorkflowConfig:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise WorkflowConfigError(f"rules file not found: {path}") from e
    except PermissionError as e:
        raise WorkflowConfigError(f"permission denied reading rules file: {path}") from e
    except yaml.YAMLError as e:
        raise WorkflowConfigError(f"{path} is not valid YAML: {e}") from e

    if not isinstance(raw, dict):
        raise WorkflowConfigError(f"{path}: top level must be a mapping")

    for required in ("workflow", "steps", "rules"):
        if required not in raw:
            raise WorkflowConfigError(f"{path}: missing required key '{required}'")

    steps = []
    for s in raw["steps"]:
        if "name" not in s or "match" not in s:
            raise WorkflowConfigError(f"{path}: each step needs 'name' and 'match'")
        match = s["match"]
        if "method" not in match or "path_contains" not in match:
            raise WorkflowConfigError(
                f"{path}: step '{s.get('name')}' match needs 'method' and 'path_contains'"
            )
        steps.append(
            StepDef(
                name=s["name"],
                method=match["method"],
                path_contains=match["path_contains"],
                extract=s.get("extract", {}) or {},
            )
        )

    rules = []
    for r in raw["rules"]:
        if "id" not in r or "assert" not in r:
            raise WorkflowConfigError(f"{path}: each rule needs 'id' and 'assert'")
        rules.append(
            RuleDef(id=r["id"], assert_expr=r["assert"], description=r.get("description"))
        )

    if not steps:
        raise WorkflowConfigError(f"{path}: 'steps' is empty")
    if not rules:
        raise WorkflowConfigError(f"{path}: 'rules' is empty")

    techniques = raw.get("techniques", []) or []
    for t in techniques:
        if "type" not in t:
            raise WorkflowConfigError(f"{path}: each entry in 'techniques' needs a 'type'")

    auth = None
    auth_raw = raw.get("auth")
    if auth_raw:
        if "login_step" not in auth_raw or "token_path" not in auth_raw:
            raise WorkflowConfigError(f"{path}: 'auth' needs 'login_step' and 'token_path'")
        auth = AuthConfig(
            login_step=auth_raw["login_step"],
            token_path=auth_raw["token_path"],
            header=auth_raw.get("header", "Authorization"),
            prefix=auth_raw.get("prefix", "Bearer "),
        )

    return WorkflowConfig(
        name=raw["workflow"],
        base_url=raw.get("base_url"),
        steps=steps,
        rules=rules,
        techniques=techniques,
        auth=auth,
    )


def _get_path(obj: Any, dotted: str) -> Any:
    """Resolve a dotted JSON path like 'data.coupon.uses' against a parsed body."""
    cur = obj
    for part in dotted.split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def extract_state(step: StepDef, response_body: Any, state: dict[str, Any]) -> None:
    """Mutate `state` in place using a step's extract rules against a response body."""
    for state_key, json_path in step.extract.items():
        value = _get_path(response_body, json_path)
        _set_dotted(state, state_key, value)


def _set_dotted(state: dict[str, Any], dotted_key: str, value: Any) -> None:
    parts = dotted_key.split(".")
    cur = state
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def _flatten_for_eval(state: dict[str, Any]) -> dict[str, Any]:
    """simpleeval resolves names, not attribute chains like `coupon.redeemed_count`.

    We give it nested dict-like "names" wrapped so that `coupon.redeemed_count`
    works via simpleeval's compound-type attribute access on a tiny namespace
    object instead of real Python objects (keeps eval sandboxed).
    """
    class _NS(dict):
        def __getattr__(self, item):
            val = self.get(item)
            if isinstance(val, dict) and not isinstance(val, _NS):
                val = _NS(val)
                self[item] = val
            return val

    def wrap(d):
        ns = _NS(d)
        for k, v in list(ns.items()):
            if isinstance(v, dict):
                ns[k] = wrap(v)
        return ns

    return {k: wrap(v) if isinstance(v, dict) else v for k, v in state.items()}


@dataclass
class RuleResult:
    rule: RuleDef
    passed: Optional[bool]   # None = could not evaluate (missing state)
    error: Optional[str] = None


import re

_DOTTED_ROOT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.[A-Za-z_]")


def _ensure_referenced_namespaces_exist(rule: RuleDef, state: dict[str, Any]) -> dict[str, Any]:
    """A step that was skipped (e.g. by step_skip) never populates its
    namespace in `state` at all. Without this, referencing e.g.
    `payment.confirmed` in a rule raises a hard NameNotDefined for `payment`
    itself - which is the wrong failure mode: skipping a step is exactly the
    attack being tested, so the rule must still be evaluable (with the
    missing fields reading as None/falsy), not blow up.

    This scans the rule expression for `name.` prefixes and defaults any
    that aren't already top-level keys in state to an empty dict.
    """
    augmented = dict(state)
    for root in _DOTTED_ROOT_RE.findall(rule.assert_expr):
        augmented.setdefault(root, {})
    return augmented


def evaluate_rule(rule: RuleDef, state: dict[str, Any]) -> RuleResult:
    state = _ensure_referenced_namespaces_exist(rule, state)
    names = _flatten_for_eval(state)
    evaluator = EvalWithCompoundTypes(names=names)
    try:
        result = evaluator.eval(rule.assert_expr)
        return RuleResult(rule=rule, passed=bool(result))
    except NameNotDefined as e:
        return RuleResult(rule=rule, passed=None, error=f"undefined name in state: {e}")
    except TypeError as e:
        # Almost always means the rule compares against a value that was
        # never populated (e.g. order.total when checkout was never reached
        # by this technique) - report it as "not evaluable", not a crash.
        return RuleResult(rule=rule, passed=None, error=f"rule references a value this technique never produced ({e})")
    except Exception as e:  # noqa: BLE001 - surfaced to the user as a rule error, not a crash
        return RuleResult(rule=rule, passed=None, error=f"{type(e).__name__}: {e}")
