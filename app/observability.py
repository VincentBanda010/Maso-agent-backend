"""Structured operational logs. Never log payloads, headers, URLs or exception text."""
import json
import logging
import os
import sys
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

request_id = ContextVar("maso_request_id", default="-")
logger = logging.getLogger("maso")
logger.setLevel(logging.INFO)


def configure_logging():
    if any(getattr(handler, "maso_handler", False) for handler in logger.handlers):
        return
    handlers = [logging.StreamHandler(sys.stdout)]
    destination = os.getenv("MASO_LOG_FILE", str(Path(__file__).resolve().parent.parent / "logs" / "maso.log"))
    if destination:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(RotatingFileHandler(path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"))
    for handler in handlers:
        handler.maso_handler = True
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)


def log_event(event, *, level=logging.INFO, **fields):
    logger.log(level, json.dumps({"time": datetime.now(timezone.utc).isoformat(),
        "level": logging.getLevelName(level), "event": event,
        "request_id": request_id.get(), **fields}, ensure_ascii=True))


class RequestLog:
    """Outer user middleware: includes body-limit rejects, unknown routes and crashes."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        identifier = str(uuid.uuid4())
        token = request_id.set(identifier)
        start = time.monotonic()
        status, received, sent, disconnected = 500, 0, 0, False
        known_paths = {getattr(route, "path", None) for route in scope["app"].routes}
        path = scope["path"] if scope["path"] in known_paths else "<unmatched>"
        method = scope["method"] if scope["method"] in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"} else "OTHER"

        async def read():
            nonlocal received, disconnected
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
            received += len(message.get("body", b""))
            return message

        async def write(message):
            nonlocal status, sent
            if message["type"] == "http.response.start":
                status = message["status"]
                message = {**message, "headers": [*message.get("headers", []),
                    (b"x-request-id", identifier.encode("ascii"))]}
            if message["type"] == "http.response.body":
                sent += len(message.get("body", b""))
            await send(message)

        log_event("request.started", method=method, path=path)
        try:
            await self.app(scope, read, write)
        except Exception as exc:
            log_event("request.failed", level=logging.ERROR, error_type=type(exc).__name__)
            raise
        finally:
            log_event("request.completed", method=method, path=path, status=status,
                elapsed_ms=round((time.monotonic() - start) * 1000, 2),
                request_bytes=received, response_bytes=sent, disconnected=disconnected)
            request_id.reset(token)
