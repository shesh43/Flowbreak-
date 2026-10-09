"""
mock_jwt_shop.py

Same deliberately-vulnerable checkout flow as mock_vulnerable_shop.py, but
authenticated via Bearer token in the Authorization header (like Juice
Shop's real JWT auth) instead of a cookie session. Used specifically to
prove FlowBreak's auth-token-refresh (AuthConfig) actually works: each
login issues a BRAND NEW random token, and any request using a stale/old
token is rejected with 401 - so if FlowBreak were still replaying frozen
HAR-captured tokens, every step after login would fail here.

Listens on http://localhost:8097
"""

from __future__ import annotations

import secrets

from flask import Flask, jsonify, request

app = Flask(__name__)

UNIT_PRICE = 10.0
COUPON_DISCOUNT = 5.0

# token -> cart state. A fresh token is issued on every login, and old
# tokens are simply not in this dict anymore once a new one is issued for
# that session, so reusing a stale token is rejected with 401 - exactly
# the failure mode a real expired/rotated JWT would produce.
SESSIONS: dict[str, dict] = {}


def _authed_cart():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):]
    return SESSIONS.get(token)


@app.post("/login")
def login():
    token = secrets.token_hex(16)
    SESSIONS[token] = {
        "total": 0.0, "item_count": 0, "redeemed_count": 0,
        "confirmed": False, "status": "open",
    }
    return jsonify(authentication={"token": token})


@app.post("/cart/add")
def cart_add():
    cart = _authed_cart()
    if cart is None:
        return jsonify(error="unauthorized"), 401
    body = request.get_json(force=True, silent=True) or {}
    quantity = body.get("quantity", 1)
    cart["item_count"] += quantity
    cart["total"] += quantity * UNIT_PRICE
    return jsonify(total=cart["total"], item_count=cart["item_count"])


@app.post("/cart/coupon")
def cart_coupon():
    cart = _authed_cart()
    if cart is None:
        return jsonify(error="unauthorized"), 401
    cart["redeemed_count"] += 1
    cart["total"] = max(0.0, cart["total"] - COUPON_DISCOUNT)
    return jsonify(total=cart["total"], redeemed_count=cart["redeemed_count"])


@app.post("/payment/confirm")
def payment_confirm():
    cart = _authed_cart()
    if cart is None:
        return jsonify(error="unauthorized"), 401
    cart["confirmed"] = True
    return jsonify(confirmed=True)


@app.post("/checkout")
def checkout():
    cart = _authed_cart()
    if cart is None:
        return jsonify(error="unauthorized"), 401
    cart["status"] = "complete"
    return jsonify(status=cart["status"], total=cart["total"])


@app.get("/health")
def health():
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8097)
