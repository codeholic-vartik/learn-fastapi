# app/routers/rate_limiter.py
from fastapi import APIRouter, Depends, Request
from app.utils.rate_limiter import rate_limiter

router = APIRouter()

@router.get("/test-rate-limit")
async def test_rate_limit(request: Request):
    # Apply rate limiting
    rate_limiter(request)
    return {"message": "Rate limit check passed!"}