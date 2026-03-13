import os
from dotenv import load_dotenv
import json

# Load environment variables FIRST (before other imports that need them)
load_dotenv()

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import structlog
from app.routes.scan import router as scan_router


def _parse_csv_env(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _normalize_origin(origin: str) -> str:
    """Normalize an origin entry from environment variables."""
    candidate = origin.strip().strip('"').strip("'").rstrip("/")
    return candidate


def _build_cors_origins() -> list[str]:
    raw_cors_origins = os.getenv("CORS_ORIGINS", "").strip()
    origins: list[str] = []

    if raw_cors_origins:
        try:
            parsed = json.loads(raw_cors_origins)
            if isinstance(parsed, list):
                origins.extend(str(origin).strip() for origin in parsed)
            elif isinstance(parsed, str):
                origins.extend(_parse_csv_env(parsed))
        except json.JSONDecodeError:
            origins.extend(_parse_csv_env(raw_cors_origins))

    if not origins:
        origins.append("http://localhost:5173")

    extension_ids: list[str] = []
    extension_ids.extend(_parse_csv_env(os.getenv("PROMPTSHIELD_EXTENSION_ID")))
    extension_ids.extend(_parse_csv_env(os.getenv("CHROME_EXTENSION_ID")))
    extension_ids.extend(_parse_csv_env(os.getenv("CHROME_EXTENSION_IDS")))

    for extension_id in extension_ids:
        origins.append(f"chrome-extension://{extension_id}")

    normalized_origins: list[str] = []
    for origin in origins:
        candidate = _normalize_origin(origin)
        if not candidate or "*" in candidate:
            continue
        if candidate not in normalized_origins:
            normalized_origins.append(candidate)

    # Final safety fallback: never return an empty allowlist.
    # This can happen when env values are present but invalid, such as
    # chrome-extension://* which is intentionally filtered out above.
    if not normalized_origins:
        normalized_origins.append("http://localhost:5173")

    return normalized_origins

# Configure structured logging - DEBUG level for full visibility
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.make_filtering_bound_logger(10),  # DEBUG level (10) - show all logs
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Initialize FastAPI app
app = FastAPI(
    title="PromptShield API",
    description="AI Prompt Injection Scanner - Production-grade security analysis",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS configuration
cors_origins = _build_cors_origins()

# SECURITY FIX: Removed wildcard chrome-extension regex
# Use specific extension IDs only in CORS_ORIGINS environment variable
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,  # Specific origins only - no wildcards
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining"],
    max_age=3600  # Cache preflight requests for 1 hour
)

# Include routers
app.include_router(scan_router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "PromptShield API",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs"
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.error("unhandled_exception", 
                path=request.url.path,
                error=str(exc),
                exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred. Please try again."
        }
    )


@app.on_event("startup")
async def startup_event():
    """Startup event - validate configuration."""
    logger.info("promptshield_starting", version="1.0.0")
    
    # Check required environment variables
    if not os.getenv("GROQ_API_KEY"):
        logger.error("groq_api_key_missing")
        raise ValueError("GROQ_API_KEY environment variable is required")

    if not any(origin.startswith("chrome-extension://") for origin in cors_origins):
        logger.warning(
            "chrome_extension_origin_missing",
            message="No Chrome extension origin configured in CORS_ORIGINS or *_EXTENSION_ID environment variables",
        )
    
    logger.info("promptshield_ready", cors_origins=cors_origins)


@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event."""
    logger.info("promptshield_shutting_down")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="error")
