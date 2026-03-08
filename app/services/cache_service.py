import hashlib
import time
from typing import Optional, Dict
from app.core.models import ScanResponse
import os
import structlog

logger = structlog.get_logger()

class ScanCache:
    """
    Serverless-compatible cache for scan results.
    
    NOTE: In-memory caching doesn't work well in serverless (each request = new instance).
    For production Vercel deployment, consider:
    1. Vercel KV (Redis) - https://vercel.com/docs/storage/vercel-kv
    2. Upstash Redis - serverless Redis
    3. Client-side caching only
    
    Current implementation: In-memory (works locally, limited in serverless)
    """
    
    def __init__(self, ttl_seconds: int = 300):  # 5 minutes default TTL
        self.cache: Dict[str, tuple[ScanResponse, float]] = {}
        self.ttl_seconds = ttl_seconds
        self.max_entries = 100  # Limit cache size
        self.enabled = os.getenv("CACHE_ENABLED", "true").lower() == "true"
        
        if not self.enabled:
            logger.info("cache_disabled", reason="CACHE_ENABLED=false in environment")
    
    def _generate_key(self, code: str, filename: str, language: str) -> str:
        """Generate cache key from code content."""
        # Hash code content to create unique key
        code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()[:16]
        return f"{language}:{filename}:{code_hash}"
    
    def get(self, code: str, filename: str, language: str) -> Optional[ScanResponse]:
        """Retrieve cached scan result if available and not expired."""
        if not self.enabled:
            return None
            
        key = self._generate_key(code, filename, language)
        
        if key in self.cache:
            result, timestamp = self.cache[key]
            age = time.time() - timestamp
            
            # Check if cache entry is still valid
            if age < self.ttl_seconds:
                logger.info("cache_hit", filename=filename, age_seconds=round(age, 2))
                return result
            else:
                # Remove expired entry
                logger.info("cache_expired", filename=filename, age_seconds=round(age, 2))
                del self.cache[key]
        
        logger.info("cache_miss", filename=filename)
        return None
    
    def set(self, code: str, filename: str, language: str, result: ScanResponse) -> None:
        """Store scan result in cache."""
        if not self.enabled:
            return
            
        key = self._generate_key(code, filename, language)
        
        # Evict oldest entries if cache is full
        if len(self.cache) >= self.max_entries:
            # Remove oldest entry
            oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k][1])
            del self.cache[oldest_key]
            logger.info("cache_eviction", reason="max_entries_reached")
        
        self.cache[key] = (result, time.time())
        logger.info("cache_set", filename=filename, total_entries=len(self.cache))
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self.cache.clear()
        logger.info("cache_cleared")
    
    def cleanup_expired(self) -> None:
        """Remove all expired cache entries."""
        current_time = time.time()
        expired_keys = [
            key for key, (_, timestamp) in self.cache.items()
            if current_time - timestamp >= self.ttl_seconds
        ]
        
        for key in expired_keys:
            del self.cache[key]
        
        if expired_keys:
            logger.info("cache_cleanup", removed_entries=len(expired_keys))

# Global cache instance
# WARNING: In serverless, this creates a NEW instance per function invocation
# Consider using Vercel KV or Upstash Redis for true persistent caching
scan_cache = ScanCache(ttl_seconds=int(os.getenv("CACHE_TTL_SECONDS", "300")))
