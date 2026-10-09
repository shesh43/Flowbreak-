# FlowBreak

A business-logic security testing engine for web/API pentesters.

### Why this exists

Automated scanners catch injection, auth, and known-CVE-class bugs well —
but nothing in a request's shape tells a scanner that a coupon should only
be redeemable once, or that an order shouldn't complete without payment.
Those bugs are provably real but require a human to state the rule; most
testers currently verify them by hand, one request at a time. FlowBreak
automates everything *after* that one human judgment call: reconstructing
the workflow, attacking it several ways, and verifying the result with
real evidence.

### What it does

FlowBreak takes a captured HTTP workflow (a HAR file — the export you get
from Chrome DevTools or Burp) and a small YAML file where you, the tester,
write the business rules that should hold (`coupon.redeemed_count <= 1`,
`order.status != "complete" or payment.confirmed == True`). It then replays
the workflow against a live target with specific mutations — skipping a
required step, replaying a step more times than it should allow, tampering
a field the server shouldn't trust — and tells you, with full request/
response evidence, whether the target actually enforces the rules you wrote.

## What this is NOT

FlowBreak does **not** attempt to automatically discover business rules
from traffic. That's a much harder, largely unsolved problem — nothing
in the request/response shape tells you "a coupon should only be usable
once." You encode the rule; FlowBreak automates the reconstruction,
attack, and verification around it. This is a deliberate scope decision,
not a missing feature — see the discussion that shaped this project for
why.

It also doesn't generate a polished pentest report. It produces
structured, reproducible evidence (JSON + Markdown) — the actual proof —
which you fold into whatever report format you already use.

## See it work

This is real output from `tests/mock_vulnerable_shop.py` (a deliberately
vulnerable checkout API included in this repo) - clone the repo and run
the commands under "Verifying it works" below to reproduce it yourself:

```
$ flowbreak run --har tests/checkout.har --rules rules/checkout.yaml \
    --target http://localhost:8099 --out demo_results

-> running step_skip: Replay workflow with step 'payment_confirm' omitted
-> running repeat_abuse: Replay step 'apply_coupon' 3x beyond normal flow
-> running field_tamper: Replay step 'add_to_cart' with quantity tampered to -5

3 of 3 techniques found a rule violation.
  VULNERABLE: step_skip - Replay workflow with step 'payment_confirm' omitted
  VULNERABLE: repeat_abuse - Replay step 'apply_coupon' 3x beyond normal flow
  VULNERABLE: field_tamper - Replay step 'add_to_cart' with quantity tampered to -5

Wrote demo_results.json and demo_results.md
```

Full evidence (the exact request/response chain proving each finding) is
in [`examples/demo_results.md`](examples/demo_results.md).

## v1 scope

- **One workflow type**: e-commerce checkout (add to cart → apply coupon →
  confirm payment → checkout). The engine itself is generic; this is just
  the first workflow it ships with example config for.
- **Three mutation techniques**:
  - `step_skip` — omit a required step, check if the workflow completes anyway
  - `repeat_abuse` — replay a step (e.g. coupon redemption) more times than
    it should be allowed
  - `field_tamper` — replay a step with one field overridden to an
    attacker-chosen value (negative quantity, zero price, etc.)
- **Input**: a HAR file (standard browser/Burp export — just JSON, nothing
  proprietary)
- **Rules**: a YAML file per workflow, assertions evaluated with
  [`simpleeval`](https://github.com/danthedeckie/simpleeval) — a sandboxed
  expression evaluator, not Python's `eval()`, so a malformed or hostile
  rule file can't execute arbitrary code.

## Install

```bash
pip install .
```

This installs FlowBreak's three runtime dependencies (`requests`, `PyYAML`,
`simpleeval`) and puts a `flowbreak` command on your PATH.

To also run the included mock test targets (see "Verifying it works"
below), install the dev extra instead, which adds Flask:

```bash
pip install -r requirements-dev.txt
```

## Usage

```bash
flowbreak run \
  --har checkout.har \
  --rules rules/checkout.yaml \
  --target http://localhost:3000 \
  --out results
```

Or without installing as a package:

```bash
PYTHONPATH=. python3 -m flowbreak.cli run --har checkout.har --rules rules/checkout.yaml --target http://localhost:3000 --out results
```

This writes `results.json` (structured, for tooling) and `results.md`
(human-readable, with the full request/response evidence per test).

### Getting a HAR file

**From a browser:** Chrome/Firefox DevTools → Network tab → perform the
workflow (add to cart, apply a coupon, pay, checkout) → right-click any
request → "Save all as HAR with content".

**From Burp Suite:** Burp has no native HAR export. Its own export (Proxy
→ HTTP history → select items → right-click → "Save items as XML")
produces Burp's own XML format instead. Convert it first:

```bash
python3 tools/burp_xml_to_har.py burp_export.xml -o capture.har
```

This handles both the base64-encoded and plain-text variants of Burp's
export, and is tested end-to-end against FlowBreak's own replay engine -
not just checked for valid-looking output.

### Finding the right endpoints in a large HAR

A real browsing session capture can easily be thousands of entries - too
many to eyeball. `tools/har_endpoints.py` summarizes a HAR down to its
unique `method + path` combinations (filtering out static assets by
default), so you can quickly find the handful that matter:

```bash
python3 tools/har_endpoints.py captured.har
python3 tools/har_endpoints.py captured.har --filter basket,coupon,order --sample-body
```

This is extraction only - it does not guess which endpoints are workflow
steps or infer any business rule; you still decide that (see "What this
is NOT" above). It just makes the raw HAR readable.

### Writing a rules file

See `rules/checkout.yaml` for a full worked example. The shape:

```yaml
workflow: ecommerce_checkout
base_url: http://localhost:3000   # optional; --target overrides this

steps:
  - name: apply_coupon
    match:
      method: POST
      path_contains: /cart/coupon   # just needs to uniquely identify the
                                     # request within your HAR capture
    extract:
      coupon.redeemed_count: redeemed_count   # state_key: json_path_in_response

rules:
  - id: coupon_single_use
    assert: coupon.redeemed_count <= 1

techniques:
  - type: repeat_abuse
    target_step: apply_coupon
    repeat_count: 3
```

**`match.path_contains`** only needs to be a unique substring of the
request's URL path within your HAR — adjust it to whatever your actual
target's endpoints look like. The example file's paths match the demo
mock server in `tests/`, not a real app; point it at your own capture.

### Token-based auth (JWT/Bearer) - important for apps like Juice Shop

If the target uses `Authorization: Bearer <token>` auth (rather than
cookie-session auth), add an `auth:` block so every step uses the
**fresh** token your login step just got back, instead of each step
replaying its own stale, frozen-at-capture-time token (which is almost
always expired or already invalidated by the time you run FlowBreak):

```yaml
auth:
  login_step: login                  # the step name that logs in
  token_path: authentication.token   # dotted path to the token in its response body
  header: Authorization              # default shown
  prefix: "Bearer "                  # default shown
```

See `rules/checkout_jwt.yaml` for a full working example, verified against
`tests/mock_jwt_shop.py`. Without `auth:` configured against a token-based
app, every step after login will 401/403 using the HAR's stale token, and
FlowBreak correctly reports that as **INCONCLUSIVE** (not a clean/secure
result - see "Result statuses" below) with a warning pointing at this config.

## Verifying it works (no live target needed)

`tests/` includes two minimal mock checkout APIs used to prove the engine
is sound, since this environment couldn't reach a real target like OWASP
Juice Shop over the network during development:

- `mock_vulnerable_shop.py` — deliberately has all three flaws FlowBreak's
  v1 techniques target (port 8099)
- `mock_secure_shop.py` — the same API with all three flaws fixed
  server-side (port 8098), used to confirm FlowBreak does **not** false-positive
  on a target that's actually secure

```bash
pip install -r requirements-dev.txt

# terminal 1
python3 tests/mock_vulnerable_shop.py

# terminal 2
python3 tests/generate_demo_har.py      # captures a legit checkout as a HAR
flowbreak run --har tests/checkout.har \
  --rules rules/checkout.yaml --target http://localhost:8099 --out /tmp/demo
# -> 3 of 3 techniques find a rule violation, with full evidence
```

Swap in `mock_secure_shop.py` (port 8098) and
`generate_demo_har_secure.py` to confirm the inverse: 0 of 3.

To point FlowBreak at a real target (Juice Shop or otherwise): run the
target, capture a HAR of a real checkout flow through it, adjust
`rules/checkout.yaml`'s `match.path_contains` values to that target's
actual endpoints and response field names, then run as above with
`--target` pointed at it.

## Result statuses

Every technique resolves to exactly one of:

- **VULNERABLE** — a rule was violated with confirmed evidence
- **NOT VULNERABLE** — the workflow's rules held, including when an attack
  request was explicitly rejected by the server (the rejection itself is
  recorded as the evidence)
- **INCONCLUSIVE** — the target could not be reached at all, or a request
  came back 401/403 (likely a stale/missing auth token - see "Token-based
  auth" above); never reported as clean, since that would be a false negative
- **SKIPPED** — a workflow step had no matching request in the HAR, so
  the technique couldn't run

## Design notes (things that bit us during development and why they're handled)

- **Cookies are never replayed verbatim from the HAR.** Doing so freezes
  a session to its state at capture time, which silently hides anything
  depending on session state evolving across requests (e.g. a coupon
  redemption counter that would otherwise appear frozen at the HAR's
  original value). Cookie-based session state is instead carried forward
  live, via the replay session's own cookie jar — exactly how a browser
  would behave working through the same flow.
- **A blocked attack request halts that test**, rather than continuing
  the workflow on whatever incidental state the rejection left behind.
  Otherwise an unrelated downstream value can coincidentally trip a rule
  (e.g. a correctly-rejected negative-quantity cart add leaving the cart
  empty, where the resulting $0 total gets misattributed as a "negative
  total" finding that never actually happened).
- **An unreachable target, or one returning 401/403 due to a stale auth
  token, is never reported as "not vulnerable."** Every rule failing to
  evaluate due to missing state would otherwise look identical to a clean
  result — the dangerous kind of false negative for a security tool. Both
  are surfaced as their own INCONCLUSIVE status instead.
- **A fresh login token is carried forward automatically** (via `auth:` in
  the rules YAML) rather than each step replaying its own frozen,
  capture-time Authorization header - otherwise a token-based app (JWT
  Bearer auth, like Juice Shop) would 401 on every step after login the
  moment the original token expires.

## Project layout

```
pyproject.toml        - packaging; 'pip install .' creates the 'flowbreak' command
requirements.txt       - core runtime deps only
requirements-dev.txt    - adds Flask, for running tests/mock_*_shop.py
flowbreak/
  har_parser.py     - loads a HAR file into ordered request/response entries
  workflow.py        - loads the rules YAML; sandboxed rule evaluation
  replay.py          - replays a captured request against a live target
  engine.py           - maps workflow steps to their HAR request
  evidence.py         - JSON/Markdown report generation
  cli.py              - command-line entrypoint
  mutations/
    base.py           - shared MutationTechnique interface
    step_skip.py
    repeat_abuse.py
    field_tamper.py
examples/
  demo_results.md/.json - real, reproducible output from the demo below
rules/
  checkout.yaml        - example e-commerce checkout workflow (cookie auth)
  checkout_jwt.yaml     - same, but for a Bearer-token-auth target
tests/
  mock_vulnerable_shop.py
  mock_secure_shop.py
  mock_jwt_shop.py      - Bearer-token-auth target, for testing auth: refresh
  generate_demo_har.py
  generate_demo_har_secure.py
tools/
  har_endpoints.py     - summarizes a large HAR into unique endpoints
  burp_xml_to_har.py    - converts Burp's native XML export into HAR
```

## Roadmap (not in v1, deliberately deferred)

- Additional mutation techniques: race conditions (concurrent replay),
  privilege/ownership swapping across two sessions
- Burp Suite project file as an alternate input format
- Additional workflow types beyond checkout (booking, subscription billing)

## License

MIT - see [LICENSE](LICENSE).
