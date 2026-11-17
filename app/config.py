import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./cybersecurity_secure_api.db")
    session_expire_minutes: int = int(os.getenv("SESSION_EXPIRE_MINUTES", "30"))
    lockout_threshold: int = int(os.getenv("LOCKOUT_THRESHOLD", "5"))
    lockout_minutes: int = int(os.getenv("LOCKOUT_MINUTES", "15"))
    max_body_bytes: int = int(os.getenv("MAX_BODY_BYTES", "16384"))
    argon2_time_cost: int = int(os.getenv("ARGON2_TIME_COST", "3"))
    argon2_memory_cost: int = int(os.getenv("ARGON2_MEMORY_COST", "65536"))
    argon2_parallelism: int = int(os.getenv("ARGON2_PARALLELISM", "2"))
    enable_docs: bool = os.getenv("ENABLE_DOCS", "true").lower() == "true"

settings = Settings()
