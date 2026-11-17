from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from app.config import settings

_hasher = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost,
    parallelism=settings.argon2_parallelism,
    hash_len=32,
    salt_len=16,
)

def hash_password(password: str) -> str:
    return _hasher.hash(password)

def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        return _hasher.verify(encoded_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False

def needs_rehash(encoded_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(encoded_hash)
    except (VerificationError, InvalidHashError):
        return True
