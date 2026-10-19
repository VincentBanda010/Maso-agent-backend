import asyncio
import hmac
import io
import os
import time
from contextlib import asynccontextmanager
from email import policy
from email.parser import BytesParser

import cv2
import numpy as np
from PIL import Image, UnidentifiedImageError
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, Security
from fastapi.security import APIKeyHeader
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .observability import RequestLog, configure_logging, log_event
from .engine import analyze
from .providers import Providers
from .schemas import AnalysisRequest, AnalysisResponse

MAX_BODY = 3 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)


class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        # Buffer only a bounded body, including chunked requests, before multipart parsing.
        messages, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                log_event("request.disconnected")
                return
            size += len(message.get("body", b""))
            if size > MAX_BODY:
                log_event("request.body_rejected", received_bytes=size, limit_bytes=MAX_BODY)
                response = JSONResponse(status_code=413, content={"detail": "Request is too large."})
                return await response(scope, receive, send)
            messages.append(message)
            if not message.get("more_body", False):
                break
        async def replay():
            return messages.pop(0) if messages else await receive()
        await self.app(scope, replay, send)


def create_app(providers=None):
    service = providers if providers is not None else Providers()
    @asynccontextmanager
    async def lifespan(app):
        configure_logging()
        log_event("server.starting")
        if os.getenv("MASO_ENV") == "production" and not os.getenv("MASO_API_KEY"):
            raise RuntimeError("MASO_API_KEY is required in production")
        try:
            if providers is None:
                await asyncio.to_thread(service.load)
                await service.prepare_threat_service()
        except Exception as exc:
            log_event("server.startup_failed", error_type=type(exc).__name__)
            raise
        log_event("server.ready", text_model=service.model_status,
            url_model=service.url_model_status)
        try:
            yield
        finally:
            log_event("server.stopped")

    app = FastAPI(title="Maso Safety API", version="1.0.0", lifespan=lifespan,
                  description="Local model phishing classification. Inputs are not persisted. Model inference, observed evidence and optional threat intelligence are reported separately.")
    app.add_middleware(BodyLimit)
    slots = asyncio.Semaphore(32)

    async def authorize(request: Request, supplied_key: str | None = Security(api_key_header)):
        key = os.getenv("MASO_API_KEY")
        if key and not hmac.compare_digest((supplied_key or "").encode(), key.encode()):
            log_event("auth.rejected")
            raise HTTPException(401, "A valid API key is required.")
        if slots.locked():
            log_event("capacity.rejected")
            raise HTTPException(503, "Service is busy. Please retry shortly.", headers={"Retry-After": "2"})
        log_event("auth.accepted", key_required=bool(key))
        async with slots:
            yield

    @app.middleware("http")
    async def headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        log_event("validation.rejected", error_count=len(exc.errors()))
        # Default validation details echo the submitted input; omit that sensitive data.
        return JSONResponse(status_code=422, content={"detail": [
            {"loc": error["loc"], "type": error["type"], "msg": error["msg"]} for error in exc.errors()]})

    @app.get("/health/live", tags=["Operations"])
    async def live():
        return {"status": "ok"}

    @app.get("/health/ready", tags=["Operations"])
    async def ready():
        return {"status": "ready", "ai": service.model_status, "url_ai": service.url_model_status,
                "threat_intelligence": service.threat_metadata()}

    @app.post("/api/v1/analyze", response_model=AnalysisResponse, tags=["Analysis"], dependencies=[Depends(authorize)])
    async def analyze_content(body: AnalysisRequest):
        return await analyze(body, service)

    @app.post("/api/v1/analyze/email", response_model=AnalysisResponse, tags=["Analysis"], dependencies=[Depends(authorize)])
    async def analyze_email(file: UploadFile = File(...), expand_links: bool = False,
                            external_checks: bool = False):
        raw = await file.read(MAX_FILE + 1)
        log_event("upload.received", kind="email", bytes=len(raw))
        if len(raw) > MAX_FILE:
            raise HTTPException(413, "Email must be under 2 MiB.")
        message = BytesParser(policy=policy.default).parsebytes(raw)
        parts = []
        for part in message.walk():
            if part.get_content_disposition() == "attachment" or part.get_content_type() not in ("text/plain", "text/html"):
                continue
            try:
                parts.append(str(part.get_content()))
            except (LookupError, UnicodeError):
                raise HTTPException(422, "Email text could not be decoded.")
        content = str(message.get("Subject", "")) + "\n" + "\n".join(parts)
        if len(content) > 20000:
            raise HTTPException(422, "Email text exceeds 20,000 characters; submit a shorter excerpt.")
        if not content.strip():
            raise HTTPException(422, "No readable email text was found.")
        body = AnalysisRequest(content=content, sender=str(message.get("From", ""))[:320],
            reply_to=str(message.get("Reply-To", ""))[:320], expand_links=expand_links, external_checks=external_checks)
        log_event("email.parsed", characters=len(content), text_parts=len(parts))
        result = await analyze(body, service)
        result.limitations.append("Sender authentication (SPF, DKIM, DMARC) was not verified. Email attachments were not scanned.")
        return result

    @app.post("/api/v1/analyze/qr", response_model=AnalysisResponse, tags=["Analysis"], dependencies=[Depends(authorize)])
    async def analyze_qr(file: UploadFile = File(...), expand_links: bool = False,
                         external_checks: bool = False):
        start = time.monotonic()
        raw = await file.read(MAX_FILE + 1)
        log_event("upload.received", kind="qr", bytes=len(raw))
        if len(raw) > MAX_FILE:
            raise HTTPException(413, "QR image must be under 2 MiB.")
        def decode():
            try:
                with Image.open(io.BytesIO(raw)) as image:
                    if image.format not in ("PNG", "JPEG", "WEBP"):
                        raise ValueError("Use a PNG, JPEG or WebP image.")
                    if image.width * image.height > 4_000_000:
                        raise ValueError("Image must be at most 4 million pixels.")
                    pixels = np.array(image.convert("RGB"))
                detector = cv2.QRCodeDetector()
                ok, decoded, _, _ = detector.detectAndDecodeMulti(pixels)
                if ok:
                    return "\n".join(value for value in decoded if value)
                value, _, _ = detector.detectAndDecode(pixels)
                return value
            except (UnidentifiedImageError, OSError, Image.DecompressionBombError, ValueError) as exc:
                raise ValueError("Image is invalid, unsupported or too large.") from exc
        try:
            text = await asyncio.to_thread(decode)
        except (ValueError, cv2.error):
            raise HTTPException(422, "Image is invalid, unsupported or too large.")
        if not text or len(text) > 20000:
            raise HTTPException(422, "No readable QR code found, or decoded content is too long.")
        log_event("qr.decoded", characters=len(text))
        result = await analyze(AnalysisRequest(content=text, expand_links=expand_links,
                                               external_checks=external_checks), service)
        result.elapsed_ms = round((time.monotonic() - start) * 1000)
        return result

    app.add_middleware(RequestLog)
    return app


app = create_app()
