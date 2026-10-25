from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.audit import verify_audit_chain
from app.database import create_database_engine
from app.dependencies import CSRF_COOKIE_NAME
from app.main import create_app
from app.models import AuditEvent, Document, DocumentPermission, Role, User
from app.security import hash_password


TEST_PASSWORD = "stage-three-test-password"
TEST_SESSION_SECRET = "stage-three-session-secret-with-more-than-32-bytes"
TEST_AUDIT_KEY = "stage-three-audit-hmac-key-with-more-than-32-bytes"
TEXT_FILE = ("note.txt", b"TrustVault test document.\n", "text/plain")


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SESSION_SECRET", TEST_SESSION_SECRET)
    monkeypatch.setenv("AUDIT_HMAC_KEY", TEST_AUDIT_KEY)
    engine = create_database_engine("sqlite://")
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    upload_dir = tmp_path / "private_uploads"
    app = create_app(engine, cookie_secure=False, upload_dir=upload_dir)

    with TestClient(app) as client:
        with session_factory() as db:
            password_hash = hash_password(TEST_PASSWORD)
            users = {
                "owner": User(
                    username="owner",
                    email="owner@example.test",
                    password_hash=password_hash,
                    role=Role.OWNER,
                ),
                "viewer": User(
                    username="viewer",
                    email="viewer@example.test",
                    password_hash=password_hash,
                    role=Role.VIEWER,
                ),
                "editor": User(
                    username="editor",
                    email="editor@example.test",
                    password_hash=password_hash,
                    role=Role.VIEWER,
                ),
                "outsider": User(
                    username="outsider",
                    email="outsider@example.test",
                    password_hash=password_hash,
                    role=Role.VIEWER,
                ),
                "administrator": User(
                    username="administrator",
                    email="admin@example.test",
                    password_hash=password_hash,
                    role=Role.ADMINISTRATOR,
                ),
            }
            db.add_all(users.values())
            db.commit()
            ids = {name: user.id for name, user in users.items()}
        yield client, session_factory, upload_dir, ids
    engine.dispose()


def signed_in_client(workspace, username: str) -> TestClient:
    client, _, _, _ = workspace
    signed_in = TestClient(client.app)
    response = signed_in.post(
        "/auth/login",
        json={"username_or_email": username, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200
    return signed_in


def csrf_headers(client: TestClient) -> dict[str, str]:
    token = client.cookies.get(CSRF_COOKIE_NAME)
    assert token
    return {"X-CSRF-Token": token}


def upload_document(client: TestClient, file=TEXT_FILE):
    return client.post(
        "/documents",
        data={"title": "Test note", "category": "general"},
        files={"file": file},
        headers=csrf_headers(client),
    )


def grant_permission(
    client: TestClient,
    document_id: str,
    username: str,
    permission: str = "read",
):
    return client.post(
        f"/documents/{document_id}/permissions",
        json={"username_or_email": username, "permission": permission},
        headers=csrf_headers(client),
    )


def test_owner_can_upload_list_download_edit_and_soft_delete(workspace):
    client, session_factory, upload_dir, _ = workspace
    owner = signed_in_client(workspace, "owner")
    response = upload_document(owner)
    assert response.status_code == 201
    document = response.json()
    assert "stored_filename" not in document
    assert "private_uploads" not in response.text
    assert list(upload_dir.iterdir())

    listing = owner.get("/documents")
    assert [item["id"] for item in listing.json()] == [document["id"]]
    download = owner.get(f"/documents/{document['id']}/download")
    assert download.status_code == 200
    assert download.content == TEXT_FILE[1]
    assert owner.get(f"/documents/{document['id']}").status_code == 200

    edited = owner.patch(
        f"/documents/{document['id']}",
        json={"title": "Updated title", "category": "records"},
        headers=csrf_headers(owner),
    )
    assert edited.status_code == 200
    assert edited.json()["title"] == "Updated title"

    deleted = owner.delete(
        f"/documents/{document['id']}", headers=csrf_headers(owner)
    )
    assert deleted.status_code == 204
    assert owner.get(f"/documents/{document['id']}").status_code == 404
    assert owner.get("/documents").json() == []
    with session_factory() as db:
        stored = db.get(Document, document["id"])
        assert stored.deleted_at is not None


def test_read_grant_allows_metadata_and_download_only(workspace):
    owner = signed_in_client(workspace, "owner")
    viewer = signed_in_client(workspace, "viewer")
    document = upload_document(owner).json()
    grant = grant_permission(owner, document["id"], "viewer", "read")
    assert grant.status_code == 201

    assert viewer.get(f"/documents/{document['id']}").status_code == 200
    assert viewer.get(f"/documents/{document['id']}/download").content == TEXT_FILE[1]
    assert viewer.get("/documents").json()[0]["id"] == document["id"]
    assert viewer.patch(
        f"/documents/{document['id']}",
        json={"title": "Not allowed"},
        headers=csrf_headers(viewer),
    ).status_code == 403
    assert viewer.delete(
        f"/documents/{document['id']}", headers=csrf_headers(viewer)
    ).status_code == 403
    assert grant_permission(viewer, document["id"], "outsider").status_code == 403


def test_edit_grant_can_edit_metadata_but_not_delete_or_share(workspace):
    owner = signed_in_client(workspace, "owner")
    editor = signed_in_client(workspace, "editor")
    document = upload_document(owner).json()
    assert grant_permission(owner, document["id"], "editor", "edit").status_code == 201

    assert editor.patch(
        f"/documents/{document['id']}",
        json={"title": "Edited"},
        headers=csrf_headers(editor),
    ).status_code == 200
    assert editor.delete(
        f"/documents/{document['id']}", headers=csrf_headers(editor)
    ).status_code == 403
    assert grant_permission(editor, document["id"], "outsider").status_code == 403


def test_ungranted_user_cannot_read_download_edit_or_delete_and_is_audited(workspace):
    owner = signed_in_client(workspace, "owner")
    outsider = signed_in_client(workspace, "outsider")
    document = upload_document(owner).json()

    assert outsider.get(f"/documents/{document['id']}").status_code == 404
    assert outsider.get(f"/documents/{document['id']}/download").status_code == 404
    assert outsider.patch(
        f"/documents/{document['id']}",
        json={"title": "Unauthorized"},
        headers=csrf_headers(outsider),
    ).status_code == 404
    assert outsider.delete(
        f"/documents/{document['id']}", headers=csrf_headers(outsider)
    ).status_code == 404

    _, session_factory, _, _ = workspace
    with session_factory() as db:
        denied_actions = db.scalars(
            select(AuditEvent.action).where(
                AuditEvent.actor_user_id.is_not(None),
                AuditEvent.outcome == "denied",
            )
        ).all()
        assert {"read", "download", "edit", "delete"}.issubset(denied_actions)


def test_unauthenticated_document_attempt_is_audited(workspace):
    client, session_factory, _, _ = workspace
    response = client.get("/documents/guessed-document-id/download")
    assert response.status_code == 401

    with session_factory() as db:
        event = db.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.actor_user_id.is_(None),
                AuditEvent.action == "download",
                AuditEvent.outcome == "denied",
            )
            .limit(1)
        )
        assert event is not None
        assert event.document_id is None


def test_state_change_with_invalid_csrf_is_audited(workspace):
    owner = signed_in_client(workspace, "owner")
    document = upload_document(owner).json()
    response = owner.patch(
        f"/documents/{document['id']}",
        json={"title": "Should fail"},
        headers={"X-CSRF-Token": "wrong-token"},
    )
    assert response.status_code == 403

    _, session_factory, _, _ = workspace
    with session_factory() as db:
        event = db.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.action == "edit",
                AuditEvent.outcome == "denied",
            )
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        assert event.details == '{"reason":"csrf_validation_failed"}'


def test_administrator_role_does_not_grant_document_access(workspace):
    owner = signed_in_client(workspace, "owner")
    administrator = signed_in_client(workspace, "administrator")
    document = upload_document(owner).json()
    assert administrator.get(
        f"/documents/{document['id']}/download"
    ).status_code == 404
    assert grant_permission(administrator, document["id"], "outsider").status_code == 404
    assert administrator.get("/admin/audit").status_code == 200


def test_owner_can_list_grants_revoke_and_revocation_takes_effect_immediately(workspace):
    owner = signed_in_client(workspace, "owner")
    viewer = signed_in_client(workspace, "viewer")
    document = upload_document(owner).json()
    grant = grant_permission(owner, document["id"], "viewer", "read").json()
    assert viewer.get(f"/documents/{document['id']}").status_code == 200

    grants = owner.get(f"/documents/{document['id']}/permissions")
    assert grants.status_code == 200
    assert grants.json()[0]["username"] == "viewer"
    revoked = owner.delete(
        f"/documents/{document['id']}/permissions/{grant['id']}",
        headers=csrf_headers(owner),
    )
    assert revoked.status_code == 204
    assert viewer.get(f"/documents/{document['id']}").status_code == 404
    assert viewer.get(f"/documents/{document['id']}/download").status_code == 404

    replacement = grant_permission(owner, document["id"], "viewer", "edit")
    assert replacement.status_code == 201


@pytest.mark.parametrize(
    ("file", "expected_status"),
    [
        (("payload.exe", b"not allowed", "application/octet-stream"), 415),
        (("fake.pdf", b"not a pdf", "application/pdf"), 415),
        (("empty.txt", b"", "text/plain"), 400),
        (("large.txt", b"x" * (5 * 1024 * 1024 + 1), "text/plain"), 413),
    ],
)
def test_upload_rejects_invalid_files(workspace, file, expected_status):
    owner = signed_in_client(workspace, "owner")
    response = upload_document(owner, file)
    assert response.status_code == expected_status


def test_upload_rejects_mismatched_content_type(workspace):
    owner = signed_in_client(workspace, "owner")
    response = upload_document(
        owner, ("note.txt", b"valid text", "application/pdf")
    )
    assert response.status_code == 415


def test_search_does_not_return_inaccessible_documents(workspace):
    owner = signed_in_client(workspace, "owner")
    viewer = signed_in_client(workspace, "viewer")
    outsider = signed_in_client(workspace, "outsider")
    first = upload_document(owner).json()
    second = owner.post(
        "/documents",
        data={"title": "Other private file", "category": "private"},
        files={"file": ("private.txt", b"private text", "text/plain")},
        headers=csrf_headers(owner),
    ).json()
    grant_permission(owner, first["id"], "viewer")

    assert [item["id"] for item in viewer.get("/documents").json()] == [first["id"]]
    assert outsider.get("/documents", params={"search": "Test"}).json() == []
    assert second["id"] not in [item["id"] for item in viewer.get("/documents").json()]


def test_audit_chain_verification_detects_modified_event(workspace):
    client, session_factory, _, _ = workspace
    owner = signed_in_client(workspace, "owner")
    upload_document(owner)

    with session_factory() as db:
        assert verify_audit_chain(db)
        event = db.scalar(select(AuditEvent).limit(1))
        event.details = '{"modified":"true"}'
        db.commit()
        assert not verify_audit_chain(db)


def test_admin_can_read_audit_but_not_document_metadata_or_contents(workspace):
    owner = signed_in_client(workspace, "owner")
    administrator = signed_in_client(workspace, "administrator")
    document = upload_document(owner).json()
    assert administrator.get(f"/documents/{document['id']}").status_code == 404
    assert administrator.get(f"/documents/{document['id']}/download").status_code == 404
    response = administrator.get("/admin/audit")
    assert response.status_code == 200
    assert response.json()["chain_valid"] is True


def test_document_upload_stores_server_generated_filename(workspace):
    client, session_factory, upload_dir, _ = workspace
    owner = signed_in_client(workspace, "owner")
    response = upload_document(
        owner, ("../../sensitive.txt", b"safe text", "text/plain")
    )
    assert response.status_code == 201
    with session_factory() as db:
        document = db.get(Document, response.json()["id"])
        assert Path(document.stored_filename).name == document.stored_filename
        assert document.stored_filename != document.original_filename
        assert (upload_dir / document.stored_filename).is_file()


def test_failed_grant_attempt_is_audited(workspace):
    owner = signed_in_client(workspace, "owner")
    document = upload_document(owner).json()
    assert grant_permission(owner, document["id"], "owner").status_code == 400
    _, session_factory, _, _ = workspace
    with session_factory() as db:
        event = db.scalar(
            select(AuditEvent)
            .where(AuditEvent.action == "grant", AuditEvent.outcome == "denied")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
        assert event is not None
        assert "password" not in event.details.lower()
