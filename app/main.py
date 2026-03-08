import os
from dotenv import load_dotenv

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
cors_origins = os.getenv("CORS_ORIGINS", '["http://localhost:5173"]')
if isinstance(cors_origins, str):
    import json
    cors_origins = json.loads(cors_origins)

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
    
    logger.info("promptshield_ready", cors_origins=cors_origins)


@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event."""
    logger.info("promptshield_shutting_down")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="error")
