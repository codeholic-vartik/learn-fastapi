# app/utils/rate_limiter.py
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from cachetools import TTLCache

# Create a cache to store rate limit data
rate_limit_cache = TTLCache(maxsize=1000, ttl=60)  # Max 1000 entries, TTL of 60 seconds

def check_rate_limit(request: Request, limit: int = 10):
    """
    Check if the client has exceeded the rate limit.
    :param request: FastAPI Request object
    :param limit: Maximum allowed requests per time window
    :return: None if within limit, raises HTTPException if limit is exceeded
    """
    client_ip = request.client.host  # Get the client's IP address

    # Check if the IP is in the cache
    if client_ip in rate_limit_cache:
        request_count = rate_limit_cache[client_ip]
        if request_count >= limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded. Please try again later.")
        rate_limit_cache[client_ip] += 1
    else:
        rate_limit_cache[client_ip] = 1

    return None

# Expose the rate_limiter function
rate_limiter = check_rate_limit