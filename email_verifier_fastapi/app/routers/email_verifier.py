from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse
from app.services.email_verifier import EmailVerifier
from app.services.quick_verifier import QuickEmailVerifier
from app.utils.rate_limiter import check_rate_limit
import logging
from io import StringIO
import csv

router = APIRouter()

# Initialize verifiers
quick_verifier = QuickEmailVerifier()
detailed_verifier = EmailVerifier()

@router.post("/validate")
async def validate_email(email: str, validation_type: str = "quick", rate_limit: bool = Depends(check_rate_limit)):
    try:
        if validation_type == "quick":
            result = quick_verifier.verify_email(email)
        else:
            result = detailed_verifier.verify_email(email)
        return JSONResponse(content=result.__dict__)
    except Exception as e:
        logging.error(f"Error validating email: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/validate-csv")
async def validate_csv(file: UploadFile = File(...), rate_limit: bool = Depends(check_rate_limit)):
    try:
        content = await file.read()
        csv_content = StringIO(content.decode("utf-8"))
        csv_reader = csv.DictReader(csv_content)
        results = []
        for row in csv_reader:
            email = row.get("email", "").strip()
            if email:
                result = quick_verifier.verify_email(email)
                results.append(result.__dict__)
        return JSONResponse(content=results)
    except Exception as e:
        logging.error(f"Error processing CSV: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))