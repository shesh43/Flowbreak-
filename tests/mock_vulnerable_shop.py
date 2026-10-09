"""
mock_vulnerable_shop.py

A tiny, deliberately vulnerable e-commerce checkout API, standing in for a
real target like OWASP Juice Shop so FlowBreak's logic can be proven
end-to-end inside this sandbox (which has no outbound network access to a
real Juice Shop instance).

It implements the same three classes of business-logic flaw Juice Shop is
known for in its checkout flow:
  1. Checkout completes even if payment was never confirmed (step-skip)
  2. A coupon can be redeemed more than once (repeat/quota abuse)
  3. Quantity is not re-validated server-side, so negative quantity reduces
     the order total below zero (field tampering)

Run:  python mock_vulnerable_shop.py
Listens on http://localhost:8099
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
    return session


@app.post("/cart/add")
def cart_add():
    cart = _cart()
    body = request.get_json(force=True, silent=True) or {}
    quantity = body.get("quantity", 1)
    # VULNERABILITY: no server-side validation that quantity > 0.
    cart["item_count"] = cart.get("item_count", 0) + quantity
    cart["total"] = cart.get("total", 0.0) + quantity * UNIT_PRICE
    session.modified = True
    return jsonify(total=cart["total"], item_count=cart["item_count"])


@app.post("/cart/coupon")
def cart_coupon():
    cart = _cart()
    # VULNERABILITY: no check for whether this coupon was already redeemed
    # in this session - it's simply applied again every time it's called.
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
    # VULNERABILITY: order is marked complete regardless of whether
    # payment.confirmed was ever set to True.
    cart["status"] = "complete"
    session.modified = True
    return jsonify(status=cart["status"], total=cart.get("total", 0.0))


@app.get("/health")
def health():
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8099)
