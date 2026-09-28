import os
import uuid
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from flask import Flask, redirect, render_template, request

ddb = boto3.resource("dynamodb")
products = ddb.Table(os.environ["PRODUCTS_TABLE"])
orders = ddb.Table(os.environ["ORDERS_TABLE"])

app = Flask(__name__)


@app.get("/")
def index():
    items = sorted(products.scan()["Items"], key=lambda p: p["sku"])
    recent = sorted(orders.scan()["Items"], key=lambda o: o["created_at"], reverse=True)
    return render_template("index.html", products=items, orders=recent[:20])


@app.post("/order")
def order():
    product = products.get_item(Key={"sku": request.form["sku"]}).get("Item")
    if not product:
        return "Unknown product", 400
    qty = max(1, int(request.form["qty"]))
    orders.put_item(Item={
        "order_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "customer": request.form["customer"][:50],
        "sku": product["sku"],
        "name": product["name"],
        "qty": qty,
        "total": product["price"] * Decimal(qty),
    })
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
