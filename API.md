# TrustVault API

The service runs locally at `http://127.0.0.1:8000` when started with Uvicorn.

## `GET /health`

Returns `200 OK` with `{"status":"ok"}`.

## `GET /`

Redirects to `/dashboard`. Unauthenticated visitors are redirected to `/login`.

## Browser pages

- `GET /login`: renders the login form. The page posts JSON to the existing `/auth/login` route.
- `GET /dashboard`: authenticated document workspace with authorized search results, upload, metadata, sharing, and delete controls depending on the current user's relationship to each document. Unauthenticated visitors are redirected to `/login`.
- `GET /audit`: administrator-only HTML audit summary with action, outcome, and date filters. Non-administrators are redirected to `/dashboard`; unauthenticated visitors are redirected to `/login`. Sensitive event details and hashes are not rendered on this page.

The shared navigation shows the signed-in username and role. Logout calls `POST /auth/logout` with the CSRF header. Browser actions call the existing authorized document and permission API endpoints; hiding an action in a template does not replace server-side checks.

Static browser assets are mounted only from `app/static/`. `private_uploads/` is not mounted as a public static directory.

## `POST /auth/login`

Accepts JSON:

```json
{
  "username_or_email": "demo-owner",
  "password": "your-local-demo-password"
}
```

On success, returns the authenticated user's safe profile and sets an HttpOnly session cookie plus a CSRF token cookie. Invalid usernames, email addresses, passwords, and inactive accounts all return the same `401` error message.

## `GET /auth/me`

Returns the current user's safe profile when the session cookie is valid. Missing, revoked, expired, or inactive-user sessions return `401 Unauthorized`.

## `POST /auth/logout`

Revokes the current session and clears the cookies. Send the CSRF cookie value in the `X-CSRF-Token` request header. Missing or mismatched CSRF tokens return `403 Forbidden`.

## Safe user profile

Successful login and `/auth/me` responses include `id`, `username`, `email`, `role`, `is_active`, and `created_at`. Password hashes and session tokens are never returned.

## Document routes

All document routes require an authenticated session. Every state-changing route also requires the CSRF cookie value in `X-CSRF-Token`. Unknown and inaccessible documents both return `404` to avoid exposing their existence. A user who can read a document but lacks the requested write permission receives `403`.

### `POST /documents`

Multipart form fields: `file`, `title`, and `category`. Returns `201 Created` with document metadata. Maximum file size is 5 MiB. Accepted types are PDF, UTF-8 plain text, PNG, JPEG, and DOCX. The extension and content are validated. Empty, oversized, mismatched, and unsupported files are rejected.

### `GET /documents`

Lists only documents owned by the current user or with an active permission grant. Optional query parameters:

- `search`: searches title and original filename.
- `owner`: filters by owner's username or email.
- `category`: exact category filter.
- `date_from` and `date_to`: ISO date/time bounds for creation time.

Filters never expand the caller's authorized document set.

### `GET /documents/{document_id}`

Returns document metadata when the caller is the owner or has read/edit permission.

### `GET /documents/{document_id}/download`

Downloads the private file when the caller is the owner or has read/edit permission. Physical storage names and paths are not returned.

### `PATCH /documents/{document_id}`

Owner or edit-granted user may update `title` and/or `category`. Original filename, owner, file path, and permission fields are not editable through this route.

### `DELETE /documents/{document_id}`

Owner-only soft deletion. The document is immediately removed from listing and inaccessible through metadata, download, and sharing routes. The underlying file is retained for now.

## Permission routes

Only the document owner may manage grants; administrator status is not an exception.

- `POST /documents/{document_id}/permissions`: JSON body `{"username_or_email":"viewer","permission":"read"}` or `"edit"`. Requires CSRF. Active duplicate grants are rejected.
- `GET /documents/{document_id}/permissions`: lists active grants for the owner.
- `DELETE /documents/{document_id}/permissions/{permission_id}`: revokes a grant immediately; requires CSRF.

## Administrator audit route

### `GET /admin/audit?limit=100`

Administrator-only. Returns audit events and a `chain_valid` result. `limit` is between 1 and 500. This route does not grant access to documents or their contents.

## Permission matrix

| Operation | Owner | Read grant | Edit grant | Administrator only |
|---|---:|---:|---:|---:|
| List/search authorized documents | Yes | Yes | Yes | No |
| View metadata / download | Yes | Yes | Yes | No |
| Edit title/category | Yes | No | Yes | No |
| Delete document | Yes | No | No | No |
| List/grant/revoke permissions | Yes | No | No | No |
| View audit events | No | No | No | Yes |