"""AegisRAG Main FastAPI Application.

Assembles API routes, security headers middleware, CORS policy,
request-size limits, and safe global exception handlers.
"""

import logging

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.routes_chat import router as chat_router
from backend.app.api.routes_documents import router as documents_router
from backend.app.api.routes_health import router as health_router
from backend.app.api.routes_security import router as security_router
from backend.app.config import settings

# Configure root logger
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("contextforge")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Secure Retrieval-Augmented Generation (RAG) Application with AI Security Guardrails",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# -------------------------------------------------------------
# Middleware: CORS Configuration
# -------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"] if settings.DEBUG else ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# -------------------------------------------------------------
# Middleware: Security Headers & Request Sizing
# -------------------------------------------------------------
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    # Reject oversized payload upfront if Content-Length header is present
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.MAX_UPLOAD_SIZE_BYTES * 1.5:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": "Request entity exceeds maximum allowable size"},
        )

    response = await call_next(request)

    # Attach hardened security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; object-src 'none'; frame-ancestors 'none';"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# -------------------------------------------------------------
# Exception Handlers: Never leak stack traces or internal secrets
# -------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled server exception on %s: %s", request.url.path, str(exc), exc_info=settings.DEBUG)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "An unexpected security or processing error occurred. Incident has been recorded.",
        },
    )


# -------------------------------------------------------------
# Include API Routers
# -------------------------------------------------------------
app.include_router(health_router)
app.include_router(documents_router)
app.include_router(chat_router)
app.include_router(security_router)
