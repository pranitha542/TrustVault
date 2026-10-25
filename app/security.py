import hashlib
import hmac
import os
import secrets
from datetime import UTC, datetime

from dotenv import load_dotenv
from pwdlib import PasswordHash


load_dotenv()

password_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    return password_hasher.verify(password, stored_hash)


def _configured_key(name: str) -> bytes:
    value = os.getenv(name, "")
    if len(value.encode("utf-8")) < 32 or value.startswith("replace-with-"):
        raise RuntimeError(
            f"{name} must be set to a random value containing at least 32 characters."
        )
    return value.encode("utf-8")


def validate_secret_configuration() -> None:
    _configured_key("SESSION_SECRET")
    _configured_key("AUDIT_HMAC_KEY")


def get_audit_hmac_key() -> bytes:
    return _configured_key("AUDIT_HMAC_KEY")


def create_session_token() -> str:
    return secrets.token_urlsafe(32)


def create_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def token_digest(token: str) -> str:
    return hmac.new(
        _configured_key("SESSION_SECRET"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def is_token_digest_valid(token: str, stored_digest: str) -> bool:
    return hmac.compare_digest(token_digest(token), stored_digest)


def is_expired(expires_at: datetime, now: datetime | None = None) -> bool:
    current_time = now or datetime.now(UTC)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at <= current_time