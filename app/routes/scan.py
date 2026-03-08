from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
import structlog
from app.core.models import ScanRequest, ScanResponse
from app.core.security import SecurityScanner
from app.services.cache_service import scan_cache
from slowapi import Limiter
from slowapi.util import get_remote_address
import os

logger = structlog.get_logger()

router = APIRouter(prefix="/api", tags=["scan"])
limiter = Limiter(key_func=get_remote_address)

# Lazy initialization - scanner created on first use
_scanner = None

def get_scanner() -> SecurityScanner:
    """Get or create the SecurityScanner singleton instance."""
    global _scanner
    if _scanner is None:
        _scanner = SecurityScanner()
    return _scanner


@router.post("/scan", response_model=ScanResponse)
@limiter.limit("10/minute")
async def scan_code(request: Request, scan_request: ScanRequest):
    """
    Scan code for prompt injection vulnerabilities.
    
    Rate limit: 10 requests per minute per IP.
    Max code size: 500KB.
    Caching enabled: Identical code scans are cached for 5 minutes.
    """
    try:
        logger.info(
            "scan_request_received",
            filename=scan_request.filename,
            language=scan_request.language,
            code_length=len(scan_request.code)
        )
        
        # Check cache first (if enabled)
        cache_enabled = os.getenv("CACHE_ENABLED", "true").lower() == "true"
        if cache_enabled:
            cached_result = scan_cache.get(
                scan_request.code,
                scan_request.filename,
                scan_request.language
            )
            if cached_result:
                logger.info("cache_hit", filename=scan_request.filename)
                return cached_result
        
        # Perform scan
        scanner = get_scanner()
        result = scanner.scan_code(
            code=scan_request.code,
            filename=scan_request.filename,
            language=scan_request.language
        )
        
        # Store in cache (if enabled)
        if cache_enabled:
            scan_cache.set(
                scan_request.code,
                scan_request.filename,
                scan_request.language,
                result
            )
        
        logger.info(
            "scan_complete",
            filename=scan_request.filename,
            vulnerabilities=len(result.vulnerabilities),
            score=result.overall_score
        )
        
        return result
        
    except ValueError as e:
        logger.error("validation_error", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        logger.error("scan_error", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Internal server error during scan. Please try again."
        )


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        scanner = get_scanner()
        groq_available = scanner.groq_client.health_check()
        return {
            "status": "healthy",
            "groq_available": groq_available,
            "version": "1.0.0"
        }
    except Exception as e:
        logger.error("health_check_error", error=str(e))
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e)}
        )
