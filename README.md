# TrustVault

TrustVault is a secure document-sharing application built with Python, FastAPI, SQLite, SQLAlchemy, Jinja2, and Bootstrap. It provides session-based authentication, role-based access, document-level permissions, private document storage, and a tamper-evident audit chain.

## Live Demo

- **Live Application:** https://trustvault-4pd2.onrender.com
- **GitHub Repository:** https://github.com/pranitha542/TrustVault

### Evaluator Login Accounts

| Role | Username |
|---|---|
| Administrator | `demo-admin` |
| Document Owner | `demo-owner` |
| Viewer | `demo-viewer` |

**Demo passwords:** Shared separately through the official project submission channel.

**Note:** The application is hosted on Render's free tier and may take a short time to start after inactivity.

## Features

- Session-based authentication and role-based access control.
- Three roles: Administrator, Document Owner, and Viewer.
- Document upload, listing, search, metadata editing, and soft deletion.
- Document-level read and edit permissions for named users.
- Permission granting and revocation by document owners.
- Private file storage using randomly generated storage names.
- Upload validation for supported file types and size limits.
- HMAC-SHA256 audit chain for document and permission-related events.
- Administrator audit interface for reviewing activity.
- CSRF protection on authenticated state-changing routes.
- Automated tests for authentication, permissions, and unauthorized access.

## Technology Stack

- **Backend:** Python, FastAPI
- **Database:** SQLite, SQLAlchemy
- **Templates:** Jinja2, Bootstrap 5.3.3
- **Authentication:** Session-based authentication, Argon2 password hashing
- **Audit Integrity:** HMAC-SHA256
- **Testing:** pytest

## Local Setup

Use Python 3.11 or a compatible newer version. In PowerShell, open the project directory and run:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and replace the secret placeholders with independent, random values of at least 32 characters.

Generate a random value with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Run the command twice and use one value for `SESSION_SECRET` and the other for `AUDIT_HMAC_KEY`. Keep `.env` private and never commit it to GitHub.

Set `COOKIE_SECURE=false` for local HTTP development. Set it to `true` when serving over HTTPS.

## Seed Demo Users

Set the following variables in `.env` to distinct demo-only passwords of at least 12 characters:

```dotenv
DEMO_ADMIN_PASSWORD=your_admin_demo_password
DEMO_OWNER_PASSWORD=your_owner_demo_password
DEMO_VIEWER_PASSWORD=your_viewer_demo_password
```

Replace these example values with your own strong passwords.

Run:

```powershell
python -m scripts.seed_demo
```

The seed script creates each demo account only if neither its username nor its email already exists. It does not reset the password of an existing account.

For the Render deployment, the demo password variables are configured in the service's Environment settings, and the configured start command runs the seed script before starting the application.

## Start the Application

Run the following command locally:

```powershell
uvicorn app.main:app --reload
```

Open the browser at:

http://127.0.0.1:8000/

The application creates its configured SQLite tables at startup. By default, the database URL is:

```text
sqlite:///./trustvault.db
```

Set `DATABASE_URL` in `.env` to use a different database.

Uploaded files are stored under `private_uploads/`, outside `app/static/`. Files are served through authorized download routes rather than public static URLs.

## Browser Interface

After opening the application, sign in through the login page.

- **Document Owners** can upload documents, edit metadata, soft-delete their documents, and manage access grants.
- **Viewers** can access documents shared with them according to their permissions.
- **Administrators** can review audit activity but do not automatically receive access to document contents.

The dashboard displays documents returned by the server-side authorization checks. State-changing browser requests use CSRF protection with the CSRF cookie and `X-CSRF-Token` header.

Bootstrap CSS and JavaScript are loaded from jsDelivr, so those resources require network access in the browser. Custom styles and scripts are served locally from `/static/`.

## Documents and Permissions

Uploads are limited to 5 MiB. Supported file types are:

- PDF
- UTF-8 plain text
- PNG
- JPEG
- DOCX

The application validates file extensions and contents, generates random storage names, and avoids exposing physical file paths.

Documents use soft deletion.

### Permission Model

- Only a document's owner can share or delete it.
- A **read grant** permits document metadata viewing and downloading.
- An **edit grant** additionally permits title and category changes.
- Edit permission does not grant deletion or sharing rights.
- Administrator role alone does not grant access to document metadata or content.

All state-changing authenticated routes require the CSRF cookie value in the `X-CSRF-Token` header.

For endpoint details, see [API.md](./API.md). For security boundaries and limitations, see [THREATS.md](./THREATS.md).

## Audit Chain

Document operations are recorded in an HMAC-SHA256 hash chain using `AUDIT_HMAC_KEY`.

Administrators can inspect audit events through the audit interface. The audit endpoint is `GET /admin/audit`.

The chain is tamper-evident, not an immutable external log. An attacker who controls both the database and the HMAC key may be able to alter or regenerate the chain.

## Tests

Run the automated tests with:

```powershell
pytest -q tests
```

The tests use isolated in-memory SQLite databases and temporary upload directories rather than real user data.

## Deployment

The application is deployed on Render:

https://trustvault-4pd2.onrender.com

The configured start command is:

```bash
python -m scripts.seed_demo && uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

The seed script runs before the web server starts. It creates missing demo accounts using the configured environment variables.

The deployment uses `SESSION_SECRET`, `AUDIT_HMAC_KEY`, and the three demo password variables in Render's Environment settings. Secret values are not stored in the public repository.

## Known Limitations

- The audit chain is not stored in an independent immutable logging service.
- Malware scanning is not implemented.
- Login rate limiting is not implemented.
- Soft-deleted files may remain on disk.
- SQLite storage on a free hosting instance may not persist across all restarts or redeployments.
- External audit storage and multi-process audit coordination are not implemented.

