import logging
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, update, func, case
from sqlalchemy.orm import Session as DBSession
from app.database import get_db
from app.models import User, Session
from app.schemas import RegisterRequest, RegisterResponse, UserResponse, LoginRequest, LoginResponse
from app.security.passwords import hash_password, verify_password
from app.security.sessions import create_token, digest_token, session_expiry
from app.config import settings
from app.auth_dependencies import get_authenticated_user

router = APIRouter(tags=["Authentication"])
logger = logging.getLogger("cybersecurity_secure_api.audit")

@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(payload: RegisterRequest, request: Request, db: DBSession = Depends(get_db)):
    username = payload.username.lower()
    existing = db.scalar(select(User).where(func.lower(User.username) == username))
    if existing:
        raise HTTPException(status_code=409, detail="Username is already registered")
    user = User(username=username, password_hash=hash_password(payload.password), role="user")
    db.add(user)
    try:
        db.commit()
    except Exception:
        db.rollback()
        # Covers a concurrent duplicate registration.
        raise HTTPException(status_code=409, detail="Username is already registered")
    db.refresh(user)
    logger.info("event=registration_success user_id=%s request_id=%s", user.id, request.state.request_id)
    return {"user": UserResponse(id=user.id, username=user.username, role=user.role)}

@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, db: DBSession = Depends(get_db)):
    username = payload.username.lower()
    user = db.scalar(select(User).where(func.lower(User.username) == username))
    now = datetime.now(timezone.utc)

    if user is None:
        # Keep the response generic. A dummy Argon2 hash is intentionally not generated per request.
        raise HTTPException(status_code=401, detail="Invalid username or password")

    locked_until = user.locked_until
    if locked_until and locked_until.replace(tzinfo=timezone.utc) > now:
        logger.warning("event=login_locked user_id=%s request_id=%s", user.id, request.state.request_id)
        raise HTTPException(status_code=429, detail="Account temporarily locked")

    if not verify_password(payload.password, user.password_hash):
        # SQL expression increments in the database, avoiding lost updates from concurrent attempts.
        lock_time = now + timedelta(minutes=settings.lockout_minutes)
        stmt = (
            update(User)
            .where(User.id == user.id)
            .values(
                failed_attempts=User.failed_attempts + 1,
                locked_until=case(
                    (User.failed_attempts + 1 >= settings.lockout_threshold, lock_time),
                    else_=User.locked_until,
                ),
            )
        )
        db.execute(stmt)
        db.commit()
        refreshed = db.get(User, user.id)
        logger.warning("event=login_failed user_id=%s request_id=%s", user.id, request.state.request_id)
        if refreshed and refreshed.failed_attempts >= settings.lockout_threshold:
            raise HTTPException(status_code=429, detail="Account temporarily locked")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    db.execute(update(User).where(User.id == user.id).values(failed_attempts=0, locked_until=None))
    raw_token = create_token()
    db.add(Session(token_hash=digest_token(raw_token), user_id=user.id, expires_at=session_expiry()))
    db.commit()
    logger.info("event=login_success user_id=%s request_id=%s", user.id, request.state.request_id)
    return LoginResponse(access_token=raw_token, expires_in=settings.session_expire_minutes * 60)

@router.post("/logout", status_code=204)
def logout(request: Request, user: User = Depends(get_authenticated_user), db: DBSession = Depends(get_db)):
    token = request.state.bearer_token
    db.query(Session).filter(Session.token_hash == digest_token(token)).delete(synchronize_session=False)
    db.commit()
    logger.info("event=logout user_id=%s request_id=%s", request.state.current_user.id, request.state.request_id)
    return None
