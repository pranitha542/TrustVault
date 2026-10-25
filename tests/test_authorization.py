from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.dependencies import SESSION_COOKIE_NAME
from app.database import create_database_engine
from app.main import create_app
from app.models import Role, User, UserSession, utc_now
from app.security import hash_password, token_digest, verify_password


TEST_PASSWORD = "test-password-for-trustvault"
TEST_SESSION_SECRET = "test-session-secret-with-at-least-32-bytes"
TEST_AUDIT_KEY = "test-audit-hmac-key-with-at-least-32-bytes"


@pytest.fixture
def client_and_factory(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SESSION_SECRET", TEST_SESSION_SECRET)
    monkeypatch.setenv("AUDIT_HMAC_KEY", TEST_AUDIT_KEY)
    engine = create_database_engine("sqlite://")
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    app = create_app(database_engine=engine, cookie_secure=False)

    with TestClient(app) as test_client:
        yield test_client, session_factory

    engine.dispose()


@pytest.fixture
def user(client_and_factory):
    _, session_factory = client_and_factory
    with session_factory() as db:
        account = User(
            username="demo-owner",
            email="owner@example.test",
            password_hash=hash_password(TEST_PASSWORD),
            role=Role.OWNER,
            is_active=True,
        )
        db.add(account)
        db.commit()
        db.refresh(account)
        return account.id


def login(client: TestClient, identifier: str = "demo-owner"):
    return client.post(
        "/auth/login",
        json={"username_or_email": identifier, "password": TEST_PASSWORD},
    )


def test_health_endpoint(client_and_factory):
    client, _ = client_and_factory
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_login_with_valid_credentials(client_and_factory, user):
    client, session_factory = client_and_factory
    response = login(client)
    assert response.status_code == 200
    assert response.json()["username"] == "demo-owner"
    assert "password_hash" not in response.json()
    assert client.cookies.get(SESSION_COOKIE_NAME)
    assert "HttpOnly" in response.headers.get("set-cookie", "")

    raw_token = client.cookies.get(SESSION_COOKIE_NAME)
    with session_factory() as db:
        stored_session = db.query(UserSession).one()
        assert stored_session.token_hash != raw_token
        assert stored_session.token_hash == token_digest(raw_token)


@pytest.mark.parametrize("identifier", ["demo-owner", "missing-user"])
def test_login_with_invalid_credentials_is_generic(client_and_factory, user, identifier):
    client, _ = client_and_factory
    response = client.post(
        "/auth/login",
        json={"username_or_email": identifier, "password": "incorrect-password"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username/email or password"


def test_me_without_authentication_is_rejected(client_and_factory):
    client, _ = client_and_factory
    response = client.get("/auth/me")
    assert response.status_code == 401


def test_me_after_login_returns_safe_profile(client_and_factory, user):
    client, _ = client_and_factory
    assert login(client).status_code == 200
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["email"] == "owner@example.test"
    assert "password_hash" not in response.json()


def test_logout_revokes_session(client_and_factory, user):
    client, session_factory = client_and_factory
    assert login(client).status_code == 200
    csrf_token = client.cookies.get("trustvault_csrf")

    response = client.post(
        "/auth/logout",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert response.status_code == 200
    assert client.get("/auth/me").status_code == 401

    with session_factory() as db:
        stored_session = db.query(UserSession).one()
        assert stored_session.revoked_at is not None


def test_logout_requires_csrf_token(client_and_factory, user):
    client, _ = client_and_factory
    assert login(client).status_code == 200

    response = client.post("/auth/logout")
    assert response.status_code == 403
    assert client.get("/auth/me").status_code == 200


@pytest.mark.parametrize("session_state", ["expired", "inactive"])
def test_expired_or_inactive_session_is_rejected(
    client_and_factory, user, session_state
):
    client, session_factory = client_and_factory
    assert login(client).status_code == 200

    with session_factory() as db:
        account = db.get(User, user)
        stored_session = db.query(UserSession).one()
        if session_state == "expired":
            stored_session.expires_at = utc_now() - timedelta(seconds=1)
        else:
            account.is_active = False
        db.commit()

    assert client.get("/auth/me").status_code == 401


def test_password_is_stored_as_hash(client_and_factory, user):
    _, session_factory = client_and_factory
    with session_factory() as db:
        account = db.get(User, user)
        assert account.password_hash != TEST_PASSWORD
        assert verify_password(TEST_PASSWORD, account.password_hash)