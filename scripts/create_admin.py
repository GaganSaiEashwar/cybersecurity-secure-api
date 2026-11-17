import getpass
from sqlalchemy import select
from app.database import Base, engine, SessionLocal
from app.models import User
from app.security.passwords import hash_password

def main():
    Base.metadata.create_all(bind=engine)
    username = input("Admin username (3-32 characters): ").strip().lower()
    password = getpass.getpass("Admin password (10-128 characters): ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords do not match.")
    if not (3 <= len(username) <= 32 and username.replace("_", "").replace("-", "").replace(".", "").isalnum()):
        raise SystemExit("Invalid username.")
    if not (10 <= len(password) <= 128):
        raise SystemExit("Password must be 10-128 characters.")
    db = SessionLocal()
    try:
        user = db.scalar(select(User).where(User.username == username))
        if user:
            user.role = "admin"
            user.password_hash = hash_password(password)
            user.failed_attempts = 0
            user.locked_until = None
        else:
            user = User(username=username, password_hash=hash_password(password), role="admin")
            db.add(user)
        db.commit()
        print(f"Administrator '{username}' created/updated.")
    finally:
        db.close()

if __name__ == "__main__":
    main()
