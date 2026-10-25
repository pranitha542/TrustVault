# TrustVault threat model notes

## Authentication and authorization

- Passwords are hashed with Argon2 through `pwdlib`. Session cookies contain random high-entropy tokens; only keyed HMAC digests are stored in SQLite. Session expiry, revocation, and current user activity are rechecked on each authenticated request.
- State-changing authenticated routes require a synchronizer CSRF token in a separate cookie and the `X-CSRF-Token` header. Keep browser use same-origin and do not enable permissive cross-origin access.
- `COOKIE_SECURE=true` is required behind HTTPS. `SESSION_SECRET` and `AUDIT_HMAC_KEY` must be independent, random secrets configured outside source control.
- Document access is checked on the server for each request against ownership and currently active grants. Administrator role alone does not grant document access or download access. Permission revocation takes effect immediately.
- Inaccessible document identifiers return `404` to reduce existence disclosure; insufficient permissions on a document the user can otherwise read return `403`.

## Upload and storage

- Files are limited to 5 MiB; supported formats are PDF, UTF-8 text, PNG, JPEG, and DOCX. Extension and content checks are applied, and storage names are randomly generated.
- Files are stored under `private_uploads/`, outside `app/static/`. The application does not mount this directory publicly and serves downloads only after authorization.
- Soft deletion blocks future access but currently retains the physical file. There is no retention/garbage-collection policy yet.
- File signature checks are format-specific sanity checks, not full semantic or malware scanning. No antivirus, content-disarm/reconstruction, or image/document sanitization is implemented.
- Upload size is checked in the route after multipart parsing. Production deployments should also enforce request-body limits at the reverse proxy/ASGI edge to limit buffering and resource exhaustion.

## Audit chain

- Successful and denied upload, read, download, edit, delete, grant, and revoke operations are recorded through one helper. Events contain controlled safe details, not credentials, session tokens, file contents, or physical paths.
- Each event hash is HMAC-SHA256 over its canonical fields and the previous event hash, using `AUDIT_HMAC_KEY`. The administrator audit endpoint reports whether the full stored chain verifies.
- This is tamper-evident, not tamper-proof. An attacker able to modify the database may delete or reorder rows and cause verification to fail; an attacker who controls both the database and the HMAC key can rewrite the chain. There is no external append-only log, key rotation/versioning, or independent timestamping.

## Remaining limitations

- SQLite table creation at startup is for development; production schema migrations, backups, database hardening, and multi-process audit-chain serialization need attention.
- Login throttling, MFA, password reset/change, account-wide session revocation, and user lifecycle workflows are not implemented.
- The application has no malware scanning, quota/rate limiting, external audit sink, or operational alerting.
- Soft-deleted files are not physically removed. Storage and audit retention policies must be defined before production use.