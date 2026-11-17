from fastapi import HTTPException, status
from app.models import User

def require_owner_or_admin(record, user: User):
    if record.owner_id != user.id and user.role != "admin":
        # Same response as a missing record to reduce record enumeration.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Record not found")
