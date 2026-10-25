import os

from dotenv import load_dotenv
from sqlalchemy import or_

load_dotenv()

from app.database import Base, SessionLocal, engine
from app.models import Role, User
from app.security import hash_password


DEMO_ACCOUNTS = (
    ("DEMO_ADMIN_PASSWORD", "demo-admin", "admin@example.test", Role.ADMINISTRATOR),
    ("DEMO_OWNER_PASSWORD", "demo-owner", "owner@example.test", Role.OWNER),
    ("DEMO_VIEWER_PASSWORD", "demo-viewer", "viewer@example.test", Role.VIEWER),
)


def seed_demo_accounts() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        for password_variable, username, email, role in DEMO_ACCOUNTS:
            existing_user = (
                db.query(User)
                .filter(or_(User.username == username, User.email == email))
                .first()
            )
            if existing_user is not None:
                print(f"Skipped existing demo account for role: {role.value}")
                continue

            password = os.getenv(password_variable, "")
            if len(password) < 12:
                raise RuntimeError(
                    f"{password_variable} must contain at least 12 characters."
                )

            db.add(
                User(
                    username=username,
                    email=email,
                    password_hash=hash_password(password),
                    role=role,
                    is_active=True,
                )
            )
            db.commit()
            print(f"Created demo account for role: {role.value}")


if __name__ == "__main__":
    seed_demo_accounts()
