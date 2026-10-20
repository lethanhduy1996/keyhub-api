"""Run: ADMIN_EMAIL=... ADMIN_PASSWORD=... python -m app.bootstrap_admin

Only promotes/creates an explicitly named admin; does not reset an existing password.
"""
import os

from sqlalchemy import select

from .db import SessionLocal, init_db
from .models import User
from .security import hash_password


def main() -> None:
    email = os.environ.get('ADMIN_EMAIL', '').strip().lower()
    password = os.environ.get('ADMIN_PASSWORD', '')
    if '@' not in email or len(password) < 12:
        raise SystemExit('Set ADMIN_EMAIL and ADMIN_PASSWORD (at least 12 chars).')
    init_db()
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            db.add(User(email=email, password_hash=hash_password(password), is_admin=True))
        else:
            user.is_admin = True
        db.commit()
    print('Admin account configured (password unchanged if existing).')


if __name__ == '__main__':
    main()
