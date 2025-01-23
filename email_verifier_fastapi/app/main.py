from fastapi import FastAPI
from app.routers import email_verifier, rate_limiter

app = FastAPI()

# Include routers
app.include_router(email_verifier.router)
app.include_router(rate_limiter.router)

@app.get("/")
def home():
    return {"message": "Email Verification API"}