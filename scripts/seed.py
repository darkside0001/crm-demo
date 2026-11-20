"""Create the first admin and some fictional demo data.

    CRM_ADMIN_EMAIL=admin@example.com CRM_ADMIN_PASSWORD='...' python -m scripts.seed

All names, phones and products are made up. No real client data is used.
"""

import os
import sys

from sqlalchemy import select

from app.config import get_settings
from app.db import Database
from app.models import Customer, Product, Role, User
from app.security import hash_password, password_problems

PRODUCTS = [
    ("SH-OX-WHT-M", "Oxford shirt, white", "Shirts", "M", 289_000, 24),
    ("SH-OX-BLU-L", "Oxford shirt, blue", "Shirts", "L", 289_000, 18),
    ("JN-SLM-IND-32", "Slim jeans, indigo", "Jeans", "32", 459_000, 15),
    ("JK-BMB-BLK-L", "Bomber jacket, black", "Jackets", "L", 899_000, 6),
    ("SU-WOL-GRY-50", "Wool suit, grey", "Suits", "50", 2_450_000, 4),
    ("BL-LTH-BRN", "Leather belt, brown", "Accessories", None, 149_000, 40),
]

CUSTOMERS = [
    ("Demo Customer One", "+998900000001"),
    ("Demo Customer Two", "+998900000002"),
    ("Demo Customer Three", "+998900000003"),
]


def main() -> int:
    email = os.environ.get("CRM_ADMIN_EMAIL", "").lower()
    password = os.environ.get("CRM_ADMIN_PASSWORD", "")
    if not email or not password:
        print("Set CRM_ADMIN_EMAIL and CRM_ADMIN_PASSWORD", file=sys.stderr)
        return 1
    problems = password_problems(password, email)
    if problems:
        print("Admin password " + "; ".join(problems), file=sys.stderr)
        return 1

    db_ = Database(get_settings().database_url)
    db_.create_all()
    with db_.SessionLocal() as db:
        admin = db.scalar(select(User).where(User.email == email))
        if admin is None:
            admin = User(email=email, full_name="Store Admin", role=Role.admin, password_hash=hash_password(password))
            db.add(admin)
            db.flush()
            print(f"created admin {email}")
        for sku, name, cat, size, price, stock in PRODUCTS:
            if not db.scalar(select(Product.id).where(Product.sku == sku)):
                db.add(Product(sku=sku, name=name, category=cat, size=size, price=price, stock=stock))
        for name, phone in CUSTOMERS:
            if not db.scalar(select(Customer.id).where(Customer.phone == phone)):
                db.add(Customer(full_name=name, phone=phone, created_by_id=admin.id))
        db.commit()
    print("seed done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
