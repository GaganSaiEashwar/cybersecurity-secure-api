import json
import logging
import uuid
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import settings
from app.database import Base, engine
from app.routes import auth, records

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied[:64] if supplied and all(c.isalnum() or c in "-_" for c in supplied[:64]) else str(uuid.uuid4())
        request.state.request_id = request_id
        request.state.bearer_token = ""
        request.state.current_user = None
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

class BodyLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        length = None
        for key, value in scope.get("headers", []):
            if key.lower() == b"content-length":
                try:
                    length = int(value)
                except ValueError:
                    length = self.max_bytes + 1
        if length is not None and length > self.max_bytes:
            response = JSONResponse({"detail": "Request body too large"}, status_code=413)
            await response(scope, receive, send)
            return
        body = bytearray()
        too_large = False
        more = True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                too_large = True
                break
            more = message.get("more_body", False)
        if too_large:
            response = JSONResponse({"detail": "Request body too large"}, status_code=413)
            await response(scope, receive, send)
            return
        sent = False
        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}
        await self.app(scope, replay, send)

def create_app():
    Base.metadata.create_all(bind=engine)
    app = FastAPI(
        title="Cybersecurity Secure API",
        version="1.0.0",
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)

    @app.exception_handler(413)
    async def too_large_handler(request: Request, exc):
        return JSONResponse({"detail": "Request body too large"}, status_code=413,
                            headers={"X-Request-ID": getattr(request.state, "request_id", str(uuid.uuid4()))})

    @app.get("/")
    def root():
        return {"service": "Cybersecurity Secure API", "status": "running"}

    @app.get("/health")
    def health():
        from sqlalchemy import text
        from app.database import engine
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "healthy"}

    app.include_router(auth.router)
    app.include_router(records.router)
    return app

app = create_app()
