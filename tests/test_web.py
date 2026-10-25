from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.database import create_database_engine
from app.dependencies import CSRF_COOKIE_NAME
from app.main import create_app
from app.models import Role, User
from app.security import hash_password


PASSWORD = "trustvault-browser-tests"


@pytest.fixture
def web_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SESSION_SECRET", "browser-session-secret-at-least-32-characters")
    monkeypatch.setenv("AUDIT_HMAC_KEY", "browser-audit-key-at-least-32-characters")
    engine = create_database_engine("sqlite://")
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    app = create_app(engine, cookie_secure=False, upload_dir=tmp_path / "uploads")
    with TestClient(app, follow_redirects=False) as client:
        with factory() as db:
            password_hash = hash_password(PASSWORD)
            db.add_all(
                [
                    User(
                        username="web-owner",
                        email="owner@example.test",
                        password_hash=password_hash,
                        role=Role.OWNER,
                    ),
                    User(
                        username="web-viewer",
                        email="viewer@example.test",
                        password_hash=password_hash,
                        role=Role.VIEWER,
                    ),
                    User(
                        username="web-admin",
                        email="admin@example.test",
                        password_hash=password_hash,
                        role=Role.ADMINISTRATOR,
                    ),
                ]
            )
            db.commit()
        yield client
    engine.dispose()


def sign_in(client: TestClient, username: str) -> None:
    response = client.post(
        "/auth/login",
        json={"username_or_email": username, "password": PASSWORD},
    )
    assert response.status_code == 200


def csrf_headers(client: TestClient) -> dict[str, str]:
    token = client.cookies.get(CSRF_COOKIE_NAME)
    assert token
    return {"X-CSRF-Token": token}


def upload_note(client: TestClient, title: str):
    return client.post(
        "/documents",
        data={"title": title, "category": "web"},
        files={"file": ("note.txt", b"browser test text", "text/plain")},
        headers=csrf_headers(client),
    )


def test_root_redirects_to_dashboard_and_login_page_is_rendered(web_workspace):
    client = web_workspace
    assert client.get("/").headers["location"] == "/dashboard"
    assert client.get("/dashboard").status_code == 303
    login_page = client.get("/login")
    assert login_page.status_code == 200
    assert 'id="username_or_email"' in login_page.text
    assert 'id="password"' in login_page.text


def test_owner_dashboard_shows_upload_edit_sharing_and_logout_controls(web_workspace):
    client = web_workspace
    sign_in(client, "web-owner")
    upload_note(client, "Owner document")
    page = client.get("/dashboard")
    assert page.status_code == 200
    assert "web-owner" in page.text
    assert "Owner document" in page.text
    assert 'id="upload-form"' in page.text
    assert "Edit details" in page.text
    assert "Sharing" in page.text
    assert "Log out" in page.text


def test_dashboard_search_filters_results_and_returns_html(web_workspace):
    client = web_workspace
    sign_in(client, "web-owner")
    upload_note(client, "Quarterly budget")
    upload_note(client, "Project notes")

    response = client.get("/dashboard", params={"search": "budget"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Quarterly budget" in response.text
    assert "Project notes" not in response.text


def test_dashboard_search_accepts_blank_date_filters(web_workspace):
    client = web_workspace
    sign_in(client, "web-owner")
    upload_note(client, "Private Test Document")

    response = client.get(
        "/dashboard",
        params={
            "search": "Private Test Document",
            "owner": "",
            "category": "",
            "date_from": "   ",
            "date_to": "",
        },
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Private Test Document" in response.text


def test_dashboard_search_accepts_valid_iso_date_filters(web_workspace):
    client = web_workspace
    sign_in(client, "web-owner")
    upload_note(client, "Dated document")

    response = client.get(
        "/dashboard",
        params={"date_from": "2020-01-01", "date_to": "2099-12-31"},
    )

    assert response.status_code == 200
    assert "Dated document" in response.text


def test_dashboard_search_rejects_invalid_nonblank_date(web_workspace):
    client = web_workspace
    sign_in(client, "web-owner")

    response = client.get("/dashboard", params={"date_from": "not-a-date"})

    assert response.status_code == 422
    assert response.json()["detail"] == (
        "date_from must be a valid date in YYYY-MM-DD format."
    )


def test_viewer_sees_only_granted_documents_without_owner_controls(web_workspace):
    client = web_workspace
    sign_in(client, "web-owner")
    owned = upload_note(client, "Shared for viewer").json()
    upload_note(client, "Private owner file")
    csrf = csrf_headers(client)
    granted = client.post(
        f"/documents/{owned['id']}/permissions",
        json={"username_or_email": "web-viewer", "permission": "read"},
        headers=csrf,
    )
    assert granted.status_code == 201

    viewer = TestClient(client.app, follow_redirects=False)
    sign_in(viewer, "web-viewer")
    page = viewer.get("/dashboard")
    assert page.status_code == 200
    assert "Shared for viewer" in page.text
    assert "Private owner file" not in page.text
    assert "Download" in page.text
    assert "Upload a document" not in page.text
    assert "Sharing" not in page.text
    assert "Delete" not in page.text
    assert "Read only" in page.text


def test_admin_has_audit_page_but_no_implicit_document_access(web_workspace):
    client = web_workspace
    sign_in(client, "web-owner")
    upload_note(client, "Owner private record")

    admin = TestClient(client.app, follow_redirects=False)
    sign_in(admin, "web-admin")
    page = admin.get("/audit")
    assert page.status_code == 200
    assert "Audit events" in page.text
    assert "Owner private record" not in page.text
    dashboard = admin.get("/dashboard")
    assert "Owner private record" not in dashboard.text
    assert "Upload a document" not in dashboard.text


def test_browser_upload_requires_csrf_and_valid_csrf_upload_succeeds(web_workspace):
    client = web_workspace
    sign_in(client, "web-owner")
    rejected = client.post(
        "/documents",
        data={"title": "Missing CSRF", "category": "test"},
        files={"file": ("note.txt", b"some text", "text/plain")},
    )
    assert rejected.status_code == 403

    accepted = upload_note(client, "CSRF protected upload")
    assert accepted.status_code == 201


def test_viewer_and_non_admin_are_redirected_from_role_pages(web_workspace):
    client = web_workspace
    sign_in(client, "web-viewer")
    assert client.get("/audit").status_code == 303
    assert client.get("/audit").headers["location"] == "/dashboard"
