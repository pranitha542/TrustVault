# TrustVault

TrustVault is a Python 3.11+ document-sharing application built with FastAPI, SQLite, SQLAlchemy, Jinja2, and Bootstrap. It provides session authentication, role-aware administration, private document storage, document-level permissions, a tamper-evident audit chain, and responsive browser pages.

## Local setup

In PowerShell, from the project directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and replace both secret placeholders with independent, random values of at least 32 characters. For example, generate values locally with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Run the command twice and put one result in `SESSION_SECRET` and the other in `AUDIT_HMAC_KEY`. Keep `.env` private. Set `COOKIE_SECURE=true` when serving over HTTPS; leave it `false` for local HTTP development.

## Seed local demo users

Set `DEMO_ADMIN_PASSWORD`, `DEMO_OWNER_PASSWORD`, and `DEMO_VIEWER_PASSWORD` in `.env` to distinct values of at least 12 characters. Then run:

```powershell
python -m scripts.seed_demo
```

The seed script creates each demo role only if neither its username nor its email already exists. It is a manual local-development task and does not run when the application starts.

## Start the application

```powershell
uvicorn app.main:app --reload
```

The app creates its configured SQLite tables at startup. By default, it uses `sqlite:///./trustvault.db`; set `DATABASE_URL` in `.env` to change that. Uploads are written under `private_uploads/`, outside `app/static/`; files are returned only through authorized download routes and are never exposed as static URLs.

## Browser interface

Open `http://127.0.0.1:8000/` and sign in at the login page. The dashboard shows only documents returned by the current user's authorized server-side listing. Owners can upload, edit metadata, soft-delete, and manage grants; viewers and edit-granted users see only actions their current grant allows. Administrators can review safe audit summaries at `/audit`, but their role does not grant document access. Browser state changes use the existing CSRF cookie and `X-CSRF-Token` header.

The templates load Bootstrap 5.3.3 CSS and JavaScript from jsDelivr, so those styles require network access in the browser. Custom responsive styles and page scripts are served locally from `/static/`.

## Documents and permissions

Uploads are limited to 5 MiB and support PDF, UTF-8 plain text, PNG, JPEG, and DOCX. The application checks both the extension and file contents, assigns a random storage name, and does not return that name or physical path. Documents are soft-deleted.

Only a document's owner can share or delete it. A read grant permits metadata viewing and download. An edit grant additionally permits title/category edits, but not deletion or sharing. Administrators can inspect audit events, but administrator role alone never grants access to document metadata or content.

All state-changing authenticated routes require the CSRF cookie value in the `X-CSRF-Token` header. See [API.md](./API.md) for route details and [THREATS.md](./THREATS.md) for security boundaries and limitations.

## Audit chain

Document operations are recorded in an HMAC-SHA256 hash chain using `AUDIT_HMAC_KEY`. Administrators can inspect events and verify the chain at `GET /admin/audit`. The chain can reveal modifications but is not an immutable external log; an attacker controlling both the database and HMAC key can alter or regenerate it.

## Tests

```powershell
pytest -q tests
```

The tests use isolated in-memory SQLite databases and temporary upload directories. They do not use real user data.
