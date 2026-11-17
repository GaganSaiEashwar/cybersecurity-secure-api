import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from app.config import settings

def create_token() -> str:
    return secrets.token_urlsafe(32)

def digest_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def session_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=settings.session_expire_minutes)
