"""
mock_secure_shop.py

Same API shape as mock_vulnerable_shop.py, but with all three flaws fixed
server-side. Used to prove FlowBreak does NOT falsely flag a secure
target - i.e. no false positives, not just true positives.

Run on a different port so it can coexist with the vulnerable one.
Listens on http://localhost:8098
"""

from __future__ import annotations

from flask import Flask, jsonify, request, session

app = Flask(__name__)
app.secret_key = "flowbreak-test-only-not-a-real-secret"

UNIT_PRICE = 10.0
COUPON_DISCOUNT = 5.0


def _cart():
    if "total" not in session:
        session["total"] = 0.0
        session["item_count"] = 0
        session["redeemed_count"] = 0
        session["confirmed"] = False
        session["status"] = "open"
        session["coupon_codes_used"] = []
    return session


@app.post("/cart/add")
def cart_add():
    cart = _cart()
    body = request.get_json(force=True, silent=True) or {}
    quantity = body.get("quantity", 1)
    # FIX: reject non-positive quantity server-side.
    if not isinstance(quantity, int) or quantity <= 0:
        return jsonify(error="quantity must be a positive integer"), 400
    cart["item_count"] = cart.get("item_count", 0) + quantity
    cart["total"] = cart.get("total", 0.0) + quantity * UNIT_PRICE
    session.modified = True
    return jsonify(total=cart["total"], item_count=cart["item_count"])


@app.post("/cart/coupon")
def cart_coupon():
    cart = _cart()
    body = request.get_json(force=True, silent=True) or {}
    code = body.get("code")
    used = cart.get("coupon_codes_used", [])
    # FIX: reject a coupon code that's already been redeemed this session.
    if code in used:
        return jsonify(error="coupon already redeemed", redeemed_count=cart.get("redeemed_count", 0), total=cart.get("total", 0.0)), 409
    used.append(code)
    cart["coupon_codes_used"] = used
    cart["redeemed_count"] = cart.get("redeemed_count", 0) + 1
    cart["total"] = max(0.0, cart.get("total", 0.0) - COUPON_DISCOUNT)
    session.modified = True
    return jsonify(total=cart["total"], redeemed_count=cart["redeemed_count"])


@app.post("/payment/confirm")
def payment_confirm():
    cart = _cart()
    cart["confirmed"] = True
    session.modified = True
    return jsonify(confirmed=True)


@app.post("/checkout")
def checkout():
    cart = _cart()
    # FIX: refuse to complete the order unless payment was actually confirmed.
    if not cart.get("confirmed", False):
        return jsonify(error="payment not confirmed", status="pending"), 402
    cart["status"] = "complete"
    session.modified = True
    return jsonify(status=cart["status"], total=cart.get("total", 0.0))


@app.get("/health")
def health():
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8098)
