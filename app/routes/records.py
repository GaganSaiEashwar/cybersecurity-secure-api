import logging
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession
from app.database import get_db
from app.models import Record, User
from app.schemas import RecordCreate, RecordResponse
from app.security.permissions import require_owner_or_admin
from app.auth_dependencies import get_authenticated_user

router = APIRouter(prefix="/records", tags=["Records"])
logger = logging.getLogger("cybersecurity_secure_api.audit")

@router.post("", response_model=RecordResponse, status_code=201)
def create_record(payload: RecordCreate, request: Request, user: User = Depends(get_authenticated_user), db: DBSession = Depends(get_db)):
    user: User = request.state.current_user
    record = Record(owner_id=user.id, title=payload.title, body=payload.body)
    db.add(record)
    db.commit()
    db.refresh(record)
    logger.info("event=record_created user_id=%s record_id=%s request_id=%s", user.id, record.id, request.state.request_id)
    return RecordResponse(id=record.id, title=record.title, body=record.body, owner_id=record.owner_id)

@router.get("/{record_id}", response_model=RecordResponse)
def get_record(record_id: int, request: Request, user: User = Depends(get_authenticated_user), db: DBSession = Depends(get_db)):
    user: User = request.state.current_user
    record = db.scalar(select(Record).where(Record.id == record_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Record not found")
    try:
        require_owner_or_admin(record, user)
    except HTTPException:
        logger.warning("event=record_access_denied user_id=%s record_id=%s request_id=%s", user.id, record_id, request.state.request_id)
        raise
    if user.role == "admin" and record.owner_id != user.id:
        logger.info("event=admin_record_read admin_id=%s record_id=%s request_id=%s", user.id, record.id, request.state.request_id)
    return RecordResponse(id=record.id, title=record.title, body=record.body, owner_id=record.owner_id)
